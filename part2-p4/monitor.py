#!/usr/bin/env python3

# read state of P4 detector via simple_switch_CLI
# shows blocked sources and counts

import argparse
import re
import subprocess

THRIFT_PORT = 9090
PREFIX = "MyIngress"

def cli(cmd):
    # sends command to simple_switch_CLI and returns output
    p = subprocess.run(
        ["simple_switch_CLI", "--thrift-port", str(THRIFT_PORT)],
        input= cmd + "\n", capture_output=True, text=True
    )
    return p.stdout

def read_reg(name):
    # reads register and returns list of numbers
    out = cli(f"register_read {PREFIX}.{name}")
    m = re.search(r"=\s*(.*)", out, re.S)
    if not m:
        return []
    return [int(x) for x in m.group(1).replace("\n", " ").split(",")
            if x.strip().isdigit()]

def int_to_ip(v):
    return ".".join(str((v >>s) & 0xFF) for s in (24, 16, 8, 0))

def show():
    blocked = read_reg("blocked")
    if not blocked:
        print("I can't read. Does the switch run?")
        return

    srcs = read_reg("blocked_src")
    dropped = read_reg("dropped_pkts")
    syns = read_reg("syn_count")

    active = [i for i, v in enumerate(blocked) if v == 1]

    print("=" * 55)
    print(" State of P4 detector")
    print("=" * 55)

    if not active:
        print("No blocked sources")
    else:
        print(f" {'bucket':<10}{'src':<18}{'dropped pkts':>15}")
        print(" " + "-" * 43)
        for i in active:
            ip = int_to_ip(srcs[i]) if i<len(srcs) else "?"
            dp = dropped[i] if i<len(dropped) else 0
            print(f" {i:<10}{ip:<18}{dp:>15}")

    total = sum(dropped)
    print(f"\nTotal dropped packets: {total}")

def reset():
    for r in ("blocked", "syn_count", "blocked_src", "dropped_pkts", "window_start"):
        cli(f"register_reset {PREFIX}.{r}")
    print("Registers reset")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()
    reset() if args.reset else show()

