// Command ip-traffic-exporter attaches an eBPF program to network
// interfaces and exports per-IP traffic counters of local networks to
// Prometheus.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/KexiChanProjectProxy/ip-traffic-exporter/internal/collector"
	"github.com/KexiChanProjectProxy/ip-traffic-exporter/internal/probe"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		ifaces      = flag.String("iface", "", "comma-separated interfaces to attach to (required)")
		listen      = flag.String("listen", ":9842", "address to serve metrics on")
		metricsPath = flag.String("metrics-path", "/metrics", "path to serve metrics on")
		ipv6        = flag.Bool("ipv6", true, "account IPv6 addresses")
		idle        = flag.Duration("idle-timeout", time.Hour, "forget addresses without traffic for this long")
		maxEntries  = flag.Uint("max-entries", 16384, "max tracked addresses per interface (LRU evicted)")
		debug       = flag.Bool("debug", false, "debug logging")
		localNets   []netip.Prefix
	)
	flag.Func("local-cidr", "local network to account, repeatable (default: the networks of each interface's addresses)", func(s string) error {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return err
		}
		localNets = append(localNets, p.Masked())
		return nil
	})
	flag.Parse()

	if *debug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	if *ifaces == "" {
		flag.Usage()
		return errors.New("-iface is required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	var sources []collector.Source
	defer func() {
		for _, s := range sources {
			if err := s.(*probe.Probe).Close(); err != nil {
				slog.Error("detach", "iface", s.Name(), "err", err)
			}
		}
	}()

	for _, name := range strings.Split(*ifaces, ",") {
		name = strings.TrimSpace(name)
		nets := localNets
		if len(nets) == 0 {
			var err error
			if nets, err = interfaceNets(name); err != nil {
				return err
			}
		}
		if !*ipv6 {
			nets = slices.DeleteFunc(slices.Clone(nets), func(p netip.Prefix) bool { return p.Addr().Is6() })
		}
		if len(nets) == 0 {
			return fmt.Errorf("%s: no local networks; set -local-cidr", name)
		}

		p, err := probe.Load(probe.Options{Interface: name, LocalNets: nets, MaxEntries: uint32(*maxEntries)})
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		sources = append(sources, p)
		if err := p.Attach(); err != nil {
			return err
		}
		slog.Info("attached", "iface", name, "local_nets", nets)
	}

	coll := collector.New(sources...)
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		coll,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go coll.RunJanitor(ctx, time.Minute, *idle)

	mux := http.NewServeMux()
	mux.Handle(*metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><h1>ip-traffic-exporter</h1><a href=%q>metrics</a></body></html>\n", *metricsPath)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	slog.Info("listening", "addr", *listen)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// interfaceNets returns the networks of the interface's global addresses.
func interfaceNets(name string) ([]netip.Prefix, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, fmt.Errorf("%s: list addresses: %w", name, err)
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() && !addr.IsPrivate() {
			continue // link-local, loopback, multicast
		}
		ones, _ := ipn.Mask.Size()
		p := netip.PrefixFrom(addr, ones).Masked()
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}
