# Part 2 — Measurement Results (P4 + bmv2)

## Setup
- h1 = legitimate user (10.0.1.1)
- h2 = attacker (10.0.2.2)
- h3 = server / victim (10.0.3.3)
- Detection: per-source SYN counting in the data plane
- Threshold: 200 SYN packets per 1-second window

## Results (h1 latency to h3)

| Scenario | Avg latency | Packet loss |
|---|---|---|
| A. Baseline | 5.59 ms | 0% |
| B. h1 while h2 attacks | 5.02 ms | 0% |
| C. After block | 4.68 ms | 0% |

Key point: h1 latency is essentially unchanged even while h2 attacks,
because h2 is blocked in microseconds after the 200th SYN.

## Detector state (from registers)
- Attacker 10.0.2.2 detected and blocked
- Dropped packets: 30806 (single bucket)
- All other traffic unaffected

## Raw latency data
A. Baseline:  rtt min/avg/max = 2.802/5.592/34.075 ms
B. Under attack: rtt min/avg/max = 3.609/5.015/7.196 ms
C. After block:  rtt min/avg/max = 3.062/4.678/6.027 ms

## Reaction speed
- Packets allowed before block = threshold (200)
- Reaction happens in the switch pipeline, no controller involved
- Compare to Part 1 (ONOS): ~83 ms reaction via controller