# Part 1 — Measurement Results (ONOS + Mininet)

## Setup

**Topology**

````
   h1, h2 (users)     ─┐
                       ├─ s1 ──[10 Mbps]── s2 ── srv (victim, 10.0.0.10)
   a1, a2 (attackers) ─┘
````

The s1–s2 link is capped at 10 Mbps to act as the bottleneck where the
attack's effect becomes visible.

**Detector configuration**

| Parameter | Value |
|---|---|
| Threshold | 150 packets/sec per source |
| Measurement interval | 2 seconds |
| Method | reading ONOS flow counters via REST API |
| Block action | high-priority drop rule per source IP |

All measurements are taken from h1 (legitimate user) to srv (victim).

## Results

| Scenario | Avg latency | Max latency | Throughput (recv) |
|---|---|---|---|
| A. Baseline (no attack) | 1.11 ms | 18.4 ms | 8.10 Mbps |
| B. Attack, no defense | 6.50 ms | 47.1 ms | 0.26 Mbps |
| C. Attack, with defense | 0.96 ms | 15.9 ms | 9.54 Mbps |

**Attack traffic:** UDP flood from a1 and a2 (`hping3 --udp -d 1000`) for
the throughput measurement; SYN flood for the latency measurement.

## Key figures

| Metric | Value |
|---|---|
| Reaction time (detection → block) | ~83 ms |
| Throughput drop under attack | ~31x (8.10 → 0.26 Mbps) |
| Latency increase under attack | ~6x (1.11 → 6.50 ms) |
| Attack packets dropped by one rule | 33,903 – 40,208 |

## Raw data

**A. Baseline**

````
ping:   rtt min/avg/max/mdev = 0.094/1.105/18.391/3.970 ms
iperf3: 9.79 Mbps sender / 8.10 Mbps receiver
````

**B. Attack, no defense**

````
SYN flood (latency):
  ping: rtt min/avg/max/mdev = 0.036/6.499/47.083/11.928 ms

UDP flood (throughput):
  iperf3: 518 Kbps sender / 260 Kbps receiver
````

**C. Attack, with defense**

````
ping:   rtt min/avg/max/mdev = 0.050/0.961/15.865/3.432 ms
iperf3: 10.8 Mbps sender / 9.54 Mbps receiver
````

## Interpretation

The three scenarios tell a complete story: normal → degraded → recovered.

Under attack, throughput collapsed by roughly 31x and latency rose about
6x, with peaks up to 47 ms. Once the detector identified the attacking
sources and installed drop rules, both metrics returned essentially to
baseline.

Two observations worth noting:

- **False positives:** the server itself exceeds the rate threshold because
  it replies to every SYN packet. It had to be explicitly whitelisted;
  otherwise the detector would have blocked the victim it was meant to
  protect. Real DDoS systems face exactly this problem.

- **Reaction time:** the controller-based approach reacts in tens of
  milliseconds. Each new flow must be reported to the controller, the
  detector must read counters, compute rates, and push a rule back. This
  is the main limitation compared to the data-plane approach in Part 2,
  where the switch reacts in microseconds without controller involvement.
````
````
