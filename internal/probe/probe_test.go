package probe

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// These tests run the program through BPF_PROG_TEST_RUN. They need
// CAP_BPF + CAP_NET_ADMIN but never attach to a real interface.

func TestToLPMKey(t *testing.T) {
	k := toLPMKey(netip.MustParsePrefix("10.38.5.77/24"))
	if k.Prefixlen != 120 {
		t.Errorf("v4 prefixlen = %d, want 120", k.Prefixlen)
	}
	if got := netip.AddrFrom16(k.Addr); got != netip.MustParseAddr("::ffff:10.38.5.0") {
		t.Errorf("v4 addr = %s", got)
	}
	k = toLPMKey(netip.MustParsePrefix("2001:db8:1::5/64"))
	if k.Prefixlen != 64 || netip.AddrFrom16(k.Addr) != netip.MustParseAddr("2001:db8:1::") {
		t.Errorf("v6 key = %d %s", k.Prefixlen, netip.AddrFrom16(k.Addr))
	}
}

func loadTestProbe(t *testing.T) *Probe {
	t.Helper()
	p, err := Load(Options{
		Interface: "lo",
		LocalNets: []netip.Prefix{
			netip.MustParsePrefix("10.38.5.0/24"),
			netip.MustParsePrefix("2001:db8:1::/64"),
		},
	})
	if errors.Is(err, os.ErrPermission) {
		t.Skip("needs CAP_BPF/CAP_NET_ADMIN:", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

type pkt struct {
	vlans    []uint16 // outer first TPIDs
	etype    uint16
	src, dst netip.Addr
	proto    byte
	payload  int
}

func (p pkt) bytes() []byte {
	b := make([]byte, 12) // dst+src MAC
	b[0], b[6] = 0x02, 0x02
	for _, tpid := range p.vlans {
		b = binary.BigEndian.AppendUint16(b, tpid)
		b = binary.BigEndian.AppendUint16(b, 10) // TCI
	}
	etype := p.etype
	if etype == 0 {
		if p.src.Is4() {
			etype = 0x0800
		} else {
			etype = 0x86dd
		}
	}
	b = binary.BigEndian.AppendUint16(b, etype)
	if etype != 0x0800 && etype != 0x86dd {
		return append(b, make([]byte, 46)...)
	}

	l4 := make([]byte, 8)
	if p.proto == 6 {
		l4 = make([]byte, 20)
		l4[12] = 5 << 4
	}
	l4 = append(l4, make([]byte, p.payload)...)

	if p.src.Is4() {
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
		ip[8] = 64
		ip[9] = p.proto
		s, d := p.src.As4(), p.dst.As4()
		copy(ip[12:], s[:])
		copy(ip[16:], d[:])
		b = append(b, ip...)
	} else {
		ip := make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
		ip[6] = p.proto
		ip[7] = 64
		s, d := p.src.As16(), p.dst.As16()
		copy(ip[8:], s[:])
		copy(ip[24:], d[:])
		b = append(b, ip...)
	}
	return append(b, l4...)
}

// skbCtx is struct __sk_buff laid out as raw bytes (192 bytes in 6.12).
// Only gso_segs/gso_size are set; the kernel rejects other non-zero fields.
func skbCtx(gsoSegs, gsoSize uint32) []byte {
	ctx := make([]byte, 192)
	binary.NativeEndian.PutUint32(ctx[164:], gsoSegs)
	binary.NativeEndian.PutUint32(ctx[176:], gsoSize)
	return ctx
}

func run(t *testing.T, prog *ebpf.Program, data []byte, gsoSegs uint32) {
	t.Helper()
	opts := &ebpf.RunOptions{Data: data}
	if gsoSegs > 0 {
		opts.Context = skbCtx(gsoSegs, 500)
	}
	ret, err := prog.Run(opts)
	if err != nil {
		t.Fatal("run:", err)
	}
	if int32(ret) != -1 {
		t.Fatalf("program returned %d, want TCX_NEXT (-1)", int32(ret))
	}
}

func TestProgram(t *testing.T) {
	var (
		host4   = netip.MustParseAddr("10.38.5.20")
		host4b  = netip.MustParseAddr("10.38.5.30")
		remote4 = netip.MustParseAddr("1.1.1.1")
		host6   = netip.MustParseAddr("2001:db8:1::5")
		remote6 = netip.MustParseAddr("2001:4860::8888")
	)

	tests := []struct {
		name string
		pkt  pkt
		segs uint32
		want map[netip.Addr]Counters
	}{
		{
			name: "v4 upload",
			pkt:  pkt{src: host4, dst: remote4, proto: 17, payload: 58},
			want: map[netip.Addr]Counters{host4: {TxBytes: 100, TxPackets: 1}},
		},
		{
			name: "v4 download",
			pkt:  pkt{src: remote4, dst: host4, proto: 17, payload: 58},
			want: map[netip.Addr]Counters{host4: {RxBytes: 100, RxPackets: 1}},
		},
		{
			name: "v4 local to local",
			pkt:  pkt{src: host4, dst: host4b, proto: 17, payload: 58},
			want: map[netip.Addr]Counters{
				host4:  {TxBytes: 100, TxPackets: 1},
				host4b: {RxBytes: 100, RxPackets: 1},
			},
		},
		{
			name: "v6 upload",
			pkt:  pkt{src: host6, dst: remote6, proto: 17, payload: 38},
			want: map[netip.Addr]Counters{host6: {TxBytes: 100, TxPackets: 1}},
		},
		{
			name: "v6 download",
			pkt:  pkt{src: remote6, dst: host6, proto: 17, payload: 38},
			want: map[netip.Addr]Counters{host6: {RxBytes: 100, RxPackets: 1}},
		},
		{
			name: "802.1Q",
			pkt:  pkt{vlans: []uint16{0x8100}, src: host4, dst: remote4, proto: 17, payload: 54},
			want: map[netip.Addr]Counters{host4: {TxBytes: 100, TxPackets: 1}},
		},
		{
			name: "QinQ",
			pkt:  pkt{vlans: []uint16{0x88a8, 0x8100}, src: remote4, dst: host4, proto: 17, payload: 50},
			want: map[netip.Addr]Counters{host4: {RxBytes: 100, RxPackets: 1}},
		},
		{
			name: "ARP ignored",
			pkt:  pkt{etype: 0x0806},
			want: map[netip.Addr]Counters{},
		},
		{
			name: "non-local ignored",
			pkt:  pkt{src: remote4, dst: netip.MustParseAddr("8.8.8.8"), proto: 17, payload: 58},
			want: map[netip.Addr]Counters{},
		},
		{
			// GRO super-packet: 4 segments of 500 bytes, 54 bytes of
			// headers each on the wire. (Test-run data must fit in a page.)
			name: "TCP GSO",
			pkt:  pkt{src: remote4, dst: host4, proto: 6, payload: 2000},
			segs: 4,
			want: map[netip.Addr]Counters{host4: {RxBytes: 4*54 + 2000, RxPackets: 4}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := loadTestProbe(t)
			data := tt.pkt.bytes()
			// Same code on both hooks: each packet is counted once per run.
			run(t, p.objs.Ingress, data, tt.segs)
			run(t, p.objs.Egress, data, tt.segs)

			got, err := p.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Errorf("tracked %d addresses %v, want %d", len(got), got, len(tt.want))
			}
			for addr, w := range tt.want {
				w = Counters{2 * w.RxBytes, 2 * w.RxPackets, 2 * w.TxBytes, 2 * w.TxPackets}
				if got[addr] != w {
					t.Errorf("%s: got %+v, want %+v", addr, got[addr], w)
				}
			}
		})
	}
}

func TestDelete(t *testing.T) {
	p := loadTestProbe(t)
	host := netip.MustParseAddr("10.38.5.20")
	run(t, p.objs.Ingress, pkt{src: host, dst: netip.MustParseAddr("1.1.1.1"), proto: 17, payload: 58}.bytes(), 0)

	if err := p.Delete(host); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(host); err != nil {
		t.Fatal("deleting a missing address:", err)
	}
	got, err := p.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("after delete: %v", got)
	}
}
