# DDoS Detection and Mitigation in SDN

A seminar project comparing two approaches to the same problem — detecting
and mitigating a DDoS (SYN flood) attack — implemented with different SDN
technologies:

- **Part 1:** reactive detection via an external controller (ONOS + Mininet)
- **Part 2:** detection directly in the data plane (P4 + bmv2)

The goal is to show the difference between decisions made by a centralized
controller versus decisions made inside the switch itself.

## Technologies

| Component | Role |
|---|---|
| Mininet | network emulation |
| Open vSwitch | software OpenFlow switch (Part 1) |
| ONOS | external SDN controller (Part 1) |
| Python + REST | detector reading stats and installing rules (Part 1) |
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
│   └── rezultati.md      Part 1 results
└── part2-p4/
    ├── ddos.p4           P4 program (data-plane detection)
    ├── topology.json     network topology
    ├── s1-runtime.json   initial table entries (control plane)
    ├── monitor.py        reads switch registers
    └── rezultati.md      Part 2 results
```

---

## Part 1 — ONOS + Mininet

### Idea

ONOS controls the network and installs forwarding rules that match on the
source IP address, so every source has its own packet counter. A Python
script (`detector.py`) periodically reads these counters through the ONOS
REST API, computes a per-source packets-per-second rate, and if a source
exceeds a threshold it installs a high-priority drop rule.

This is **reactive** detection through a controller: the decision is made
outside the switch, in software.

### Topology

```
   h1, h2 (users)      -----+
                            +--- s1 ---[10 Mbps]--- s2 --- srv (victim)
   a1, a2 (attackers)  -----+
```

The s1-s2 link is capped at 10 Mbps to act as a bottleneck.

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

- Reaction time (detection -> block): **~83 ms**
- Throughput drop under attack: **~31x**
- A single drop rule discarded **over 33,000** attack packets

Details: [part1-onos/rezultati.md](part1-onos/rezultati.md)

---

## Part 2 — P4 + bmv2

### Idea

The same detection, implemented in the **data plane** itself. The P4 program
counts SYN packets per source using registers and hashing (CRC32 into 4096
buckets), and when a source exceeds the threshold the switch drops its
packets on its own — with no controller involved.

The key difference from Part 1: the reaction happens inside the switch, in
microseconds, instead of going through an external controller.

### Topology

```
   h1 (user)       -----+
   h2 (attacker)   -----+--- s1 (P4 switch)
   h3 (server)     -----+
```

In Part 2 all hosts must start with "h" — a constraint of the P4 tutorials
runner script — so the attacker is h2 and the server is h3.

### Running

```bash
cd part2-p4
sudo mn -c
make run        # compiles ddos.p4, starts bmv2, loads table entries
```

Attack from Mininet:

```
mininet> h2 hping3 -S -p 80 -i u2000 10.0.3.3 &
```

Inspect detector state (second terminal):

```bash
python3 monitor.py           # show blocked sources and drop counts
python3 monitor.py --reset   # reset for a new demo
```

### Results

| Scenario | h1 avg latency | h1 packet loss |
|---|---|---|
| Baseline | 5.59 ms | 0% |
| h1 while h2 attacks | 5.02 ms | 0% |
| After block | 4.68 ms | 0% |

- Packets allowed before block = **threshold (200)**, then all dropped
- h1 latency essentially **unchanged** even during the attack
- Detector state confirmed in registers: attacker blocked, 30,000+ dropped

Details: [part2-p4/rezultati.md](part2-p4/rezultati.md)

---

## Comparison — the two approaches

| | Part 1 — ONOS (controller) | Part 2 — P4 (data plane) |
|---|---|---|
| Where the decision is made | controller (Python) | switch pipeline |
| Reaction time | ~83 ms | microseconds |
| Packets before block | thousands | exactly the threshold (200) |
| Impact on legitimate traffic | latency ~6x higher | practically none |
| Logic flexibility | very high (easy to change) | limited (no loops, fixed memory) |
| Visibility | aggregated flow counters | per-packet, in registers |
| Controller load | high (every new flow) | minimal |

**Takeaway:** the controller-based approach is flexible and easy to program,
but the switch must send traffic to the controller, wait for a decision, and
install a rule — so the legitimate user feels the attack for tens of
milliseconds. The P4 approach decides for every packet inside the switch, so
the attacker is blocked in microseconds and legitimate traffic is barely
affected — at the cost of a more constrained programming model.

---

## Notes

- In Part 1 the server also exceeds the rate threshold because it replies to
  every SYN, so it had to be explicitly whitelisted. Real DDoS systems face
  exactly this false-positive problem.
- bmv2 is a software switch, so absolute throughput numbers are not
  representative of hardware. The relative comparison between the two
  approaches is what matters.
- Both parts are separate demonstrations sharing the same theme; the network
  layouts and host names differ between them.

