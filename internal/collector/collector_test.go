package collector

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/KexiChanProjectProxy/ebpf-prometheus-exporter/internal/probe"
)

type fakeSource struct {
	name string
	data map[netip.Addr]probe.Counters
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) Snapshot() (map[netip.Addr]probe.Counters, error) {
	out := make(map[netip.Addr]probe.Counters, len(f.data))
	for k, v := range f.data {
		out[k] = v
	}
	return out, nil
}

func (f *fakeSource) Delete(a netip.Addr) error {
	delete(f.data, a)
	return nil
}

func TestCollect(t *testing.T) {
	src := &fakeSource{name: "eno1", data: map[netip.Addr]probe.Counters{
		netip.MustParseAddr("10.38.5.20"):    {RxBytes: 1000, RxPackets: 10, TxBytes: 200, TxPackets: 2},
		netip.MustParseAddr("2001:db8:1::5"): {TxBytes: 50, TxPackets: 1},
	}}
	c := New(src)

	want := `
# HELP ip_traffic_bytes_total Layer 2 bytes per local IP. direction=rx is traffic to the IP (download), tx is traffic from it (upload).
# TYPE ip_traffic_bytes_total counter
ip_traffic_bytes_total{direction="rx",iface="eno1",ip="10.38.5.20"} 1000
ip_traffic_bytes_total{direction="rx",iface="eno1",ip="2001:db8:1::5"} 0
ip_traffic_bytes_total{direction="tx",iface="eno1",ip="10.38.5.20"} 200
ip_traffic_bytes_total{direction="tx",iface="eno1",ip="2001:db8:1::5"} 50
# HELP ip_traffic_packets_total Packets per local IP. direction=rx is traffic to the IP (download), tx is traffic from it (upload).
# TYPE ip_traffic_packets_total counter
ip_traffic_packets_total{direction="rx",iface="eno1",ip="10.38.5.20"} 10
ip_traffic_packets_total{direction="rx",iface="eno1",ip="2001:db8:1::5"} 0
ip_traffic_packets_total{direction="tx",iface="eno1",ip="10.38.5.20"} 2
ip_traffic_packets_total{direction="tx",iface="eno1",ip="2001:db8:1::5"} 1
# HELP ip_traffic_tracked_ips Number of local IPs currently tracked.
# TYPE ip_traffic_tracked_ips gauge
ip_traffic_tracked_ips{iface="eno1"} 2
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"ip_traffic_bytes_total", "ip_traffic_packets_total", "ip_traffic_tracked_ips"); err != nil {
		t.Error(err)
	}
}

func TestExpire(t *testing.T) {
	busy := netip.MustParseAddr("10.38.5.20")
	idle := netip.MustParseAddr("10.38.5.30")
	src := &fakeSource{name: "eno1", data: map[netip.Addr]probe.Counters{
		busy: {RxBytes: 1},
		idle: {RxBytes: 1},
	}}
	c := New(src)
	t0 := time.Unix(0, 0)
	const timeout = time.Hour

	c.Expire(t0, timeout)
	src.data[busy] = probe.Counters{RxBytes: 2}
	c.Expire(t0.Add(30*time.Minute), timeout)
	if len(src.data) != 2 {
		t.Fatalf("expired too early: %v", src.data)
	}

	c.Expire(t0.Add(61*time.Minute), timeout)
	if _, ok := src.data[idle]; ok {
		t.Error("idle address not expired")
	}
	if _, ok := src.data[busy]; !ok {
		t.Error("busy address expired")
	}

	// A re-appearing address starts a fresh idle period.
	src.data[idle] = probe.Counters{TxBytes: 1}
	c.Expire(t0.Add(62*time.Minute), timeout)
	c.Expire(t0.Add(90*time.Minute), timeout)
	if _, ok := src.data[idle]; !ok {
		t.Error("re-appeared address expired too early")
	}
}
