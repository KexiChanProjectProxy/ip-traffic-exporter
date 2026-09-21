# ip-traffic-exporter

Prometheus exporter for per-IP traffic of local networks, measured by an eBPF
program on an interface's TCX ingress and egress hooks.

Put it on a router's LAN interface: ingress sees LAN hosts' pre-NAT source
addresses, egress sees post-de-NAT destinations. nftables flowtable offload
does not hide anything from it, since the tc hooks sit outside the
flowtable fast path.

## Requirements

- Linux ≥ 6.6 (TCX), BTF not required
- `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` (or root)
- Build: Go only. Regenerating the BPF object (`make generate`) also needs clang.

## Usage

```
ip-traffic-exporter -iface eno1 [-listen :9842]
```

| flag | default | |
|---|---|---|
| `-iface` | | comma-separated interfaces |
| `-local-cidr` | networks of the interface's addresses | repeatable; addresses in these networks are tracked |
| `-ipv6` | `true` | track IPv6 addresses |
| `-idle-timeout` | `1h` | forget addresses whose counters stopped changing |
| `-max-entries` | `16384` | per-interface table size, LRU evicted |
| `-listen` / `-metrics-path` | `:9842` / `/metrics` | |

## Metrics

```
ip_traffic_bytes_total{iface, ip, direction="rx"|"tx"}
ip_traffic_packets_total{iface, ip, direction}
ip_traffic_tracked_ips{iface}
ip_traffic_scrape_errors_total{iface}
```

`rx` is traffic **to** the IP (its download), `tx` is traffic **from** it (its
upload). Bytes are L2 bytes without FCS, the same as the interface counters;
GRO/GSO super-packets are expanded to their wire packet and header count.

Bandwidth in bit/s:

```promql
rate(ip_traffic_bytes_total{direction="rx"}[1m]) * 8
```

The router's own LAN address shows up too (its traffic with LAN hosts).
Expired or LRU-evicted addresses restart from zero, which `rate()` treats as
a counter reset.

## Safety

- The program only reads packets and always returns `TCX_NEXT`.
- It attaches at the **head** of the TCX chain, so other TCX programs on the
  same interface (which usually end the chain) still run after it, unchanged.
- The links are not pinned: they go away when the process exits or crashes.
  Nothing touches qdiscs, nftables or routes.

## Deploy

```
make build        # or make build-arm64
install -m755 bin/ip-traffic-exporter /usr/local/bin/
cp deploy/ip-traffic-exporter.service /etc/systemd/system/   # edit -iface
systemctl enable --now ip-traffic-exporter
```

## Tests

`make test` runs everything; the BPF tests are skipped unless privileged.
To run them on a target host (uses `BPF_PROG_TEST_RUN`, attaches nothing):

```
make test-bin && scp bin/probe.test host:/tmp/ && ssh root@host /tmp/probe.test -test.v
```
