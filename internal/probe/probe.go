// Package probe loads the per-IP traffic accounting BPF program, attaches it
// to an interface via TCX and reads its counters.
package probe

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel traffic ../../bpf/traffic.c -- -I../../bpf/headers

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Counters are the accumulated counters of one IP address. Rx is traffic
// destined to the address (download), Tx is traffic sourced from it (upload).
// The layout must match struct counters in bpf/traffic.c.
type Counters struct {
	RxBytes   uint64
	RxPackets uint64
	TxBytes   uint64
	TxPackets uint64
}

func (c *Counters) add(o Counters) {
	c.RxBytes += o.RxBytes
	c.RxPackets += o.RxPackets
	c.TxBytes += o.TxBytes
	c.TxPackets += o.TxPackets
}

// Options configure a Probe.
type Options struct {
	// Interface to attach to. It is also used to pick the link-layer header
	// length, so it must exist even if the probe is never attached.
	Interface string
	// LocalNets are the networks whose addresses are accounted.
	LocalNets []netip.Prefix
	// MaxEntries caps the number of tracked addresses (LRU evicted).
	// Zero keeps the default compiled into the program.
	MaxEntries uint32
}

// Probe is the loaded BPF program for one interface.
type Probe struct {
	iface   string
	ifindex int
	objs    trafficObjects
	links   []link.Link
}

// Load loads the BPF objects and populates the local network table. The
// program is not attached until Attach is called.
func Load(opts Options) (*Probe, error) {
	if len(opts.LocalNets) == 0 {
		return nil, errors.New("no local networks configured")
	}

	ifc, err := net.InterfaceByName(opts.Interface)
	if err != nil {
		return nil, err
	}
	l2Len, err := linkHeaderLen(opts.Interface)
	if err != nil {
		return nil, err
	}

	spec, err := loadTraffic()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	if err := spec.Variables["l2_len"].Set(l2Len); err != nil {
		return nil, fmt.Errorf("set l2_len: %w", err)
	}
	if opts.MaxEntries > 0 {
		spec.Maps["stats"].MaxEntries = opts.MaxEntries
	}
	if n := uint32(len(opts.LocalNets)); n > spec.Maps["local_nets"].MaxEntries {
		spec.Maps["local_nets"].MaxEntries = n
	}

	p := &Probe{iface: opts.Interface, ifindex: ifc.Index}
	if err := spec.LoadAndAssign(&p.objs, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return nil, fmt.Errorf("load objects: %+v", verr)
		}
		return nil, fmt.Errorf("load objects: %w", err)
	}

	for _, pfx := range opts.LocalNets {
		if err := p.objs.LocalNets.Put(toLPMKey(pfx), uint8(1)); err != nil {
			p.Close()
			return nil, fmt.Errorf("add local network %s: %w", pfx, err)
		}
	}
	return p, nil
}

// Attach attaches the program to the interface's TCX ingress and egress
// hooks. The links are not pinned: they are released when the probe is
// closed or the process exits, so a crash never leaves the hook behind.
//
// The program goes to the head of the chain: any program returning a
// verdict other than TCX_NEXT ends the chain, so appending would miss every
// packet when another program is already attached. Ours always returns
// TCX_NEXT, so programs after it are unaffected.
func (p *Probe) Attach() error {
	for _, a := range []struct {
		prog *ebpf.Program
		typ  ebpf.AttachType
	}{
		{p.objs.Ingress, ebpf.AttachTCXIngress},
		{p.objs.Egress, ebpf.AttachTCXEgress},
	} {
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: p.ifindex,
			Program:   a.prog,
			Attach:    a.typ,
			Anchor:    link.Head(),
		})
		if err != nil {
			return fmt.Errorf("attach %s to %s: %w", a.typ, p.iface, err)
		}
		p.links = append(p.links, l)
	}
	return nil
}

// Close detaches and unloads everything.
func (p *Probe) Close() error {
	var errs []error
	for _, l := range p.links {
		errs = append(errs, l.Close())
	}
	p.links = nil
	errs = append(errs, p.objs.Close())
	return errors.Join(errs...)
}

// Name returns the interface name.
func (p *Probe) Name() string { return p.iface }

// Snapshot returns the current counters of every tracked address, summed
// over all CPUs.
func (p *Probe) Snapshot() (map[netip.Addr]Counters, error) {
	out := make(map[netip.Addr]Counters)
	var (
		key    [16]byte
		perCPU []Counters
	)
	it := p.objs.Stats.Iterate()
	for it.Next(&key, &perCPU) {
		var sum Counters
		for _, c := range perCPU {
			sum.add(c)
		}
		out[netip.AddrFrom16(key).Unmap()] = sum
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate stats: %w", err)
	}
	return out, nil
}

// Delete forgets an address. Its counters restart from zero if it is seen
// again.
func (p *Probe) Delete(addr netip.Addr) error {
	err := p.objs.Stats.Delete(addr.As16())
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func toLPMKey(pfx netip.Prefix) trafficLpmKey {
	pfx = pfx.Masked()
	bits := pfx.Bits()
	if pfx.Addr().Is4() {
		bits += 96 // stored IPv4-mapped
	}
	return trafficLpmKey{Prefixlen: uint32(bits), Addr: pfx.Addr().As16()}
}

// linkHeaderLen returns the link-layer header length the program sees on
// the interface, based on its ARPHRD type.
func linkHeaderLen(iface string) (uint32, error) {
	b, err := os.ReadFile("/sys/class/net/" + iface + "/type")
	if err != nil {
		return 0, err
	}
	typ, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("parse link type of %s: %w", iface, err)
	}
	switch typ {
	case 1, 772: // ARPHRD_ETHER, ARPHRD_LOOPBACK
		return 14, nil
	case 65534, 512, 768, 769, 776, 778: // NONE (tun/wg), PPP, IPIP, TUNNEL6, SIT, IPGRE
		return 0, nil
	default:
		return 0, fmt.Errorf("unsupported link type %d on %s", typ, iface)
	}
}
