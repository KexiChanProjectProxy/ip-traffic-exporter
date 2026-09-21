// Package collector exposes per-IP traffic counters as Prometheus metrics and
// expires addresses that stopped sending traffic.
package collector

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/KexiChanProjectProxy/ip-traffic-exporter/internal/probe"
)

// Source is one attached interface.
type Source interface {
	Name() string
	Snapshot() (map[netip.Addr]probe.Counters, error)
	Delete(netip.Addr) error
}

type entryKey struct {
	iface string
	addr  netip.Addr
}

type entry struct {
	last    probe.Counters
	changed time.Time
}

// Collector implements prometheus.Collector over a set of Sources.
type Collector struct {
	sources []Source

	bytes   *prometheus.Desc
	packets *prometheus.Desc
	tracked *prometheus.Desc
	errors  *prometheus.CounterVec

	mu   sync.Mutex
	seen map[entryKey]entry
}

// New returns a Collector over sources.
func New(sources ...Source) *Collector {
	labels := []string{"iface", "ip", "direction"}
	return &Collector{
		sources: sources,
		bytes: prometheus.NewDesc("ip_traffic_bytes_total",
			"Layer 2 bytes per local IP. direction=rx is traffic to the IP (download), tx is traffic from it (upload).",
			labels, nil),
		packets: prometheus.NewDesc("ip_traffic_packets_total",
			"Packets per local IP. direction=rx is traffic to the IP (download), tx is traffic from it (upload).",
			labels, nil),
		tracked: prometheus.NewDesc("ip_traffic_tracked_ips",
			"Number of local IPs currently tracked.",
			[]string{"iface"}, nil),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ip_traffic_scrape_errors_total",
			Help: "Errors reading counters from the BPF map.",
		}, []string{"iface"}),
		seen: make(map[entryKey]entry),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.bytes
	ch <- c.packets
	ch <- c.tracked
	c.errors.Describe(ch)
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, src := range c.sources {
		iface := src.Name()
		snap, err := src.Snapshot()
		if err != nil {
			slog.Error("snapshot failed", "iface", iface, "err", err)
			c.errors.WithLabelValues(iface).Inc()
			continue
		}
		for addr, v := range snap {
			ip := addr.String()
			ch <- prometheus.MustNewConstMetric(c.bytes, prometheus.CounterValue, float64(v.RxBytes), iface, ip, "rx")
			ch <- prometheus.MustNewConstMetric(c.bytes, prometheus.CounterValue, float64(v.TxBytes), iface, ip, "tx")
			ch <- prometheus.MustNewConstMetric(c.packets, prometheus.CounterValue, float64(v.RxPackets), iface, ip, "rx")
			ch <- prometheus.MustNewConstMetric(c.packets, prometheus.CounterValue, float64(v.TxPackets), iface, ip, "tx")
		}
		ch <- prometheus.MustNewConstMetric(c.tracked, prometheus.GaugeValue, float64(len(snap)), iface)
	}
	c.errors.Collect(ch)
}

// Expire deletes addresses whose counters have not changed for longer than
// idle. It must be called periodically; an address's idle time is measured
// from the first call that observed its current counters.
func (c *Collector) Expire(now time.Time, idle time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, src := range c.sources {
		iface := src.Name()
		snap, err := src.Snapshot()
		if err != nil {
			slog.Error("snapshot failed", "iface", iface, "err", err)
			c.errors.WithLabelValues(iface).Inc()
			continue
		}

		// Forget addresses that disappeared on their own (LRU eviction).
		for k := range c.seen {
			if k.iface != iface {
				continue
			}
			if _, ok := snap[k.addr]; !ok {
				delete(c.seen, k)
			}
		}

		for addr, v := range snap {
			k := entryKey{iface, addr}
			e, ok := c.seen[k]
			switch {
			case !ok || e.last != v:
				c.seen[k] = entry{last: v, changed: now}
			case now.Sub(e.changed) >= idle:
				if err := src.Delete(addr); err != nil {
					slog.Error("delete failed", "iface", iface, "ip", addr, "err", err)
					continue
				}
				slog.Debug("expired idle address", "iface", iface, "ip", addr)
				delete(c.seen, k)
			}
		}
	}
}

// RunJanitor calls Expire every interval until ctx is done.
func (c *Collector) RunJanitor(ctx context.Context, interval, idle time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.Expire(now, idle)
		}
	}
}
