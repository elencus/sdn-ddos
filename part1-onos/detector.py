#!/usr/bin/env python3

# ddos detector on ONOS REST API
# every n seconds -> read counter -> calc pps -> block if beyond threshold

import argparse
import sys
import time
from collections import defaultdict
import requests
from requests.auth import HTTPBasicAuth

# conf

ONOS_URL = "http://localhost:8181/onos/v1"
AUTH = HTTPBasicAuth("onos", "rocks")

APP_ID = "org.onosproject.rest" 
INTERVAL = 2.0  
THRESHOLD_PPS = 150  
BLOCK_PRIORITY = 60000 # drop priority

WHITELIST = {"10.0.0.10"} # server IP


# functions

def get_flows():
    # get all flows from ONOS
    r = requests.get(f"{ONOS_URL}/flows", auth=AUTH, timeout=5)
    r.raise_for_status()
    return r.json().get("flows", [])

def src_ip_of(flow):
    # extract source IP from selector
    for c in flow.get("selector", {}).get("criteria", []):
        if c.get("type") == "IPV4_SRC":
            return c["ip"].split("/")[0]
    return None


def collect_counters():
    # dict: {(deviceId, srcIp): packets}

    counters = defaultdict(int)
    for f in get_flows():
        if f.get("priority", 0) >= BLOCK_PRIORITY:
            continue  # skip blocked flows
        if f.get("state") != "ADDED":
            continue  # skip non-active flows
        src = src_ip_of(f)
        if src is None:
            continue  # skip flows without source IP
        counters[(f["deviceId"], src)] += f.get("packets", 0)
    return counters


def install_drop(device_id, src_ip):
    # installs a drop flow for IPv4 packets from src_ip
    rule = {
        "priority": BLOCK_PRIORITY,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": device_id,
        "tableId": 0,
        "treatment": {"instructions": []},  # empty = drop
        "selector": {
            "criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IPV4_SRC", "ip": f"{src_ip}/32"},
            ]
        },
    }
    r = requests.post(
        f"{ONOS_URL}/flows/{device_id}",
        params={"appId": APP_ID},
        json=rule,
        auth=AUTH,
        timeout=5,
    )
    if r.status_code in (200, 201):
        return True
    print(f"  [x] Failed: {r.status_code} {r.text[:200]}")
    return False


def list_blocks():
    # list all blocked flows
    out = []
    for f in get_flows():
        if f.get("priority", 0) >= BLOCK_PRIORITY:
            src = src_ip_of(f)
            if src:
                out.append((f["deviceId"], src, f["id"], f.get("packets", 0)))
    return out


def clear_blocks():
    # remove all blocked flows
    n = 0
    for dev, src, fid, pkts in list_blocks():
        r = requests.delete(f"{ONOS_URL}/flows/{dev}/{fid}", auth=AUTH, timeout=5)
        if r.status_code in (200, 204):
            print(f" Removed: {src} on {dev} (removed {pkts} packets)")
            n += 1
    print(f"Cleared {n} blocked flows.")


def monitor_loop():
    print("=" * 62)
    print(" DDos Detector - ONOS REST API")
    print(f" threshold: {THRESHOLD_PPS} packets/sec, interval: {INTERVAL}s")
    print("=" * 62)

    prev = collect_counters()  
    prev_t = time.time()
    blocked = set() 

    while True:
        time.sleep(INTERVAL)

        try: 
            cur = collect_counters()
        except requests.RequestException as e:
            print(f"[!] ONOS error: {e}")
            continue

        now = time.time()
        dt = now - prev_t 

        rows = []
        for key, pkts in cur.items():
            dev, src = key
            delta = pkts - prev.get(key, 0)
            if delta < 0:
                delta = pkts # counter reset
            rate = delta / dt
            if rate > 1:
                rows.append((rate, dev, src))


        # list active flows
        rows.sort(reverse=True)
        if rows:
            print(f"\n--- {time.strftime('%H:%M:%S')} ---")
            for rate, dev, src in rows[:8]:
                flag = ""
                if src in blocked:
                    flag = " [BLOCKED]"
                elif rate > THRESHOLD_PPS:
                    flag = " <== ABOVE THRESHOLD"
                print(f" {src:<15} {rate:8.1f} pps   {dev}{flag}")



        # block flows above threshold
        for rate, dev, src in rows:
            if src in WHITELIST or src in blocked:
                continue
            if rate > THRESHOLD_PPS:
                t0 = time.time()
                if install_drop(dev, src):
                    blocked.add(src)
                    print(f"\n *** BLOCKED {src} on {dev} "
                          f"({rate:.0f} pps) in {(time.time()-t0)*1000:.0f} ms ***\n")

        prev, prev_t = cur, now


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="list blocked flows")
    ap.add_argument("--clear", action="store_true", help="remove all blocked flows")
    args = ap.parse_args()

    if args.clear:
        clear_blocks()
        return
    if args.list:
        for dev, src, fid, pkts in list_blocks():
            print(f" {src:<15} {dev} removed {pkts} packets")
        return

    try:
        monitor_loop()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)

if __name__ == "__main__":
    main()