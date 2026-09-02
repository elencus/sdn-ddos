# DDoS Detection and Mitigation in SDN

A seminar project comparing two approaches to the same problem — detecting
a DDoS attack — implemented with different SDN technologies:

- **Part 1:** reactive detection via an external controller (ONOS + Mininet)
- **Part 2:** detection in the data plane itself (P4 + bmv2)

The goal is to show the difference between having decisions made by a
centralized controller versus made directly inside the switch.

## Technologies

| Component | Role |
|---|---|
| Mininet | network emulation |
| Open vSwitch | software OpenFlow switch (Part 1) |
| ONOS | external SDN controller (Part 1) |
| Python + REST | detector reading stats and installing rules |
| P4 / bmv2 | programmable switch, detection in data plane (Part 2) |
| hping3, iperf3 | attack generation and measurement |

## Project structure

```
sdn-proekt/
├── README.md
├── setup.sh
├── part1-onos/
│   ├── topo.py           Mininet topology
│   ├── detector.py       detector via ONOS REST API
│   └── rezultati.md      measured results
└── part2-p4/
    └── ddos.p4           P4 program (data plane detection)
```

## Part 1 — ONOS + Mininet

### Idea

ONOS controls the network and installs forwarding rules that match on
source IP address, so every source has its own packet counter. A Python
script (`detector.py`) periodically reads these counters through the ONOS
REST API, computes a per-source packets-per-second rate, and if a source
exceeds a threshold it installs a high-priority drop rule.

This is **reactive** detection through a controller: the decision is made
outside the switch, in software.

### Topology

```
   h1, h2 (users)     ─┐
                       ├─ s1 ──[10 Mbps]── s2 ── srv (victim)
   a1, a2 (attackers) ─┘
```

The s1–s2 link is limited to 10 Mbps to act as a bottleneck where the
effect of the attack is visible.

### Running

```bash
# ONOS (Docker)
docker run -d --name onos -p 8181:8181 -p 8101:8101 \
       -p 6653:6653 -p 6640:6640 onosproject/onos:latest

# in the ONOS console (ssh -p 8101 karaf@localhost, password: karaf)
app activate org.onosproject.openflow
app activate org.onosproject.fwd
app activate org.onosproject.gui2
cfg set org.onosproject.fwd.ReactiveForwarding matchIpv4Address true

# the network
cd part1-onos
sudo mn --custom topo.py --topo ddos \
        --controller=remote,ip=127.0.0.1,port=6653 \
        --switch ovsk,protocols=OpenFlow13 --link tc --mac

# the detector (in another terminal)
python3 detector.py
```

Attack from Mininet:

```
mininet> a1 hping3 -S -p 80 -i u2000 10.0.0.10 &
```

### Results

| Scenario | Avg latency | Throughput |
|---|---|---|
| Baseline (no attack) | 1.11 ms | 8.10 Mbps |
| Attack, no defense | 6.50 ms | 0.26 Mbps |
| Attack, with defense | 0.96 ms | 9.54 Mbps |

- Reaction time (detection → block): **~83 ms**
- Throughput drop under attack: **~31x**
- A single drop rule discarded **over 33,000** attack packets

See [part1-onos/rezultati.md](part1-onos/rezultati.md) for details.

## Part 2 — P4 + bmv2

### Idea

The same detection, but implemented in the **data plane** itself. The P4
program counts SYN packets per source using registers and hashing, and
when a source exceeds the threshold the switch starts dropping its packets
on its own — with no controller involved.

The key difference from Part 1: the reaction happens inside the switch, in
microseconds, instead of going through an external controller.

### Running

```
(to be filled in when Part 2 is complete)
```

### Results

```
(to be filled in)
```

## Comparison

| | ONOS (controller) | P4 (data plane) |
|---|---|---|
| Where the logic lives | in the controller (Python) | in the switch |
| Reaction time | tens of ms | microseconds |
| Controller load | high | minimal |
| Logic flexibility | very high | limited (no loops) |
| Visibility | aggregated flow counters | per packet |

## Notes

- The server also exceeds the rate threshold because it replies to the SYN
  packets, so it had to be explicitly whitelisted. This shows that real
  DDoS systems must account for false positives.
- bmv2 is a software switch, so absolute throughput numbers are not
  representative of hardware; the point is the relative comparison between
  the two approaches.

