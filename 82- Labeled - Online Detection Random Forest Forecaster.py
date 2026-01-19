# Labeled - Online Detection Random Forest Forecaster

'''
import sys, subprocess
subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
subprocess.check_call([sys.executable, "-m", "pip", "install",
                      "requests", "psutil", "scapy", "matplotlib"])
'''
import time
import os
import json
import socket
import threading

import csv

import requests
import psutil
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from scapy.all import sniff, IP, Ether, conf
#from scapy.utils import wrpcap
from scapy.utils import rdpcap, wrpcap
from collections import defaultdict
conf.use_pcap = True

import joblib
import numpy as np
from collections import deque

# ---- load RF forecaster ----
try:
    _RF_BUNDLE = joblib.load("rf_forecaster.joblib")
    _RF_MODEL = _RF_BUNDLE["model"]
    _RF_SCALER = _RF_BUNDLE["scaler"]
    _RF_FEATURES = _RF_BUNDLE["features"]
    _RF_SEQ_LEN = int(_RF_BUNDLE["seq_len"])
    _RF_THRESHOLD = float(_RF_BUNDLE["threshold"])
    print("✅ Loaded RF forecaster.")
except Exception as e:
    _RF_BUNDLE = None
    _RF_MODEL = _RF_SCALER = _RF_FEATURES = None
    _RF_SEQ_LEN = 0
    _RF_THRESHOLD = float("inf")
    print("⚠ RF model not loaded (rf_forecaster.joblib). Forecast anomaly disabled.", e)

# -----------------------------
# Splunk HEC configuration
# -----------------------------
SPLUNK_HEC_URL    = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088/services/collector")
SPLUNK_HEC_TOKEN  = os.getenv("SPLUNK_HEC_TOKEN", "cdab321d-23f9-4818-a413-380f80936bfa")
SPLUNK_INDEX      = os.getenv("SPLUNK_INDEX", "main")
SPLUNK_SOURCE     = "Scapy-sniffer"
SPLUNK_SOURCETYPE = "net:rx"
HOSTNAME          = socket.gethostname()


def packet_counter(
    src_ip=None, dst_ip=None,
    src_mac=None, dst_mac=None,
    track_ip=None, track_mac=None,
    iface=None, timeout=30,
    replay_pcap=None,   # path to pcap file to replay instead of live sniff
    replay_csv=None     # path to CSV file (packet_log.csv) to replay counts-only
):
    # ---- accumulators / state ----
    stats = {'tx': 0, 'rx': 0, 'other': 0}
    byte_stats = {'tx': 0, 'rx': 0, 'other': 0}
    captured_packets = []
    last_timestamp = None
    peak_memory = 0
    time_points, tx_points, rx_points = [], [], []
    first_pkt_time = None
    last_pkt_time = None

    # ---- Wire IAT accumulators (true on-the-wire gaps)
    last_wire_ts = None
    wire_iat_sum_ms = 0.0
    wire_iat_count = 0

    # per-second Wire IAT
    wire_iat_sum_ms_persec = defaultdict(float)
    wire_iat_count_persec = defaultdict(int)

    ip_directional_stats = {}
    mac_directional_stats = {}

    tx_per_second = defaultdict(int)
    tx_bytes_per_second = defaultdict(int)
    rx_per_second = defaultdict(int)
    rx_bytes_per_second = defaultdict(int)
    tracked_rx_per_second = defaultdict(int)
    tracked_rx_bytes_per_second = defaultdict(int)

    # (CSV logging removed)
    log_file = open("packet_log.csv", "w", newline='', encoding='utf-8')
    writer = csv.writer(log_file)
    writer.writerow(["Timestamp", "Direction", "Wire IAT (ms)", "Summary"])
    
    start_time = time.time()
    stop_time = start_time + timeout
    process = psutil.Process(os.getpid())

    def zero_counters():
        return {'tx': 0, 'rx': 0}

    ip_directional_stats  = defaultdict(zero_counters)
    mac_directional_stats = defaultdict(zero_counters)

    # new
    fwd_per_second  = defaultdict(int);  fwd_bytes_per_second  = defaultdict(int)  # src -> dst
    rev_per_second  = defaultdict(int);  rev_bytes_per_second  = defaultdict(int)  # dst -> src

    # ---- packet handler ----
    def match(pkt):
        nonlocal stats, last_timestamp, peak_memory, first_pkt_time, last_pkt_time
        nonlocal ip_directional_stats, mac_directional_stats
        nonlocal last_wire_ts, wire_iat_sum_ms, wire_iat_count
        nonlocal wire_iat_sum_ms_persec, wire_iat_count_persec

        #pkt_time = pkt.time
        # Ensure pkt_time is a float (rdpcap may give Decimal-like timestamps)
        pkt_time = float(pkt.time)
        if first_pkt_time is None:
            first_pkt_time = pkt_time
        last_pkt_time = pkt_time

        _now = time.time()
        memory = process.memory_info().rss / 1024
        peak_memory = max(peak_memory, memory)

        #CSV
        #timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pkt_time))
        #pkt_len = len(pkt)
        pkt_len = len(pkt) if hasattr(pkt, '__len__') else 0
        rx_sec = int(pkt_time - (first_pkt_time or start_time))

        # Inter-packet time (wire)
        wire_iat_ms = None
        if last_wire_ts is not None:
            wire_iat_ms = (pkt_time - last_wire_ts) * 1000.0
            wire_iat_sum_ms += wire_iat_ms
            wire_iat_count  += 1
            wire_iat_sum_ms_persec[rx_sec] += wire_iat_ms
            wire_iat_count_persec[rx_sec]  += 1
        last_wire_ts = pkt_time

        direction = None

        # ---------- L3: IP ----------
        if IP in pkt and (src_ip or dst_ip):
            s_ip = pkt[IP].src
            d_ip = pkt[IP].dst

            if src_ip and dst_ip:
                if s_ip == src_ip and d_ip == dst_ip:
                    stats['tx'] += 1; byte_stats['tx'] += pkt_len; direction = "TX"
                    tx_per_second[rx_sec] += 1
                    tx_bytes_per_second[rx_sec] += pkt_len
                elif s_ip == dst_ip and d_ip == src_ip:
                    stats['rx'] += 1; byte_stats['rx'] += pkt_len; direction = "RX"
                    rx_per_second[rx_sec] += 1; rx_bytes_per_second[rx_sec] += pkt_len
                else:
                    stats['other'] += 1; byte_stats['other'] += pkt_len; direction = "OTHER"
            else:
                if dst_ip and d_ip == dst_ip:
                    stats['rx'] += 1; byte_stats['rx'] += pkt_len; direction = "RX"
                    rx_per_second[rx_sec] += 1; rx_bytes_per_second[rx_sec] += pkt_len
                elif src_ip and s_ip == src_ip:
                    stats['tx'] += 1; byte_stats['tx'] += pkt_len; direction = "TX"
                    tx_per_second[rx_sec] += 1
                    tx_bytes_per_second[rx_sec] += pkt_len
                else:
                    stats['other'] += 1; byte_stats['other'] += pkt_len; direction = "OTHER"

        # ---------- L2: MAC ----------
        elif Ether in pkt and (src_mac or dst_mac):
            s = pkt[Ether].src.lower()
            d = pkt[Ether].dst.lower()
            sm = src_mac.lower() if src_mac else None
            dm = dst_mac.lower() if dst_mac else None

            if sm and dm:
                if s == sm and d == dm:
                    stats['tx'] += 1; byte_stats['tx'] += pkt_len; direction = "TX"
                    fwd_per_second[rx_sec]  += 1
                    fwd_bytes_per_second[rx_sec] += pkt_len
                    tx_per_second[rx_sec]       += 1
                    tx_bytes_per_second[rx_sec] += pkt_len
                elif s == dm and d == sm:
                    stats['rx'] += 1; byte_stats['rx'] += pkt_len; direction = "RX"
                    rev_per_second[rx_sec]  += 1
                    rev_bytes_per_second[rx_sec] += pkt_len
                    rx_per_second[rx_sec] += 1
                    rx_bytes_per_second[rx_sec] += pkt_len
                else:
                    stats['other'] += 1; byte_stats['other'] += pkt_len; direction = "OTHER"
            else:
                if dm and d == dm:
                    stats['rx'] += 1; byte_stats['rx'] += pkt_len; direction = "RX"
                    rx_per_second[rx_sec] += 1; rx_bytes_per_second[rx_sec] += pkt_len
                elif sm and s == sm:
                    stats['tx'] += 1; byte_stats['tx'] += pkt_len; direction = "TX"
                    tx_per_second[rx_sec] += 1
                    tx_bytes_per_second[rx_sec] += pkt_len
                else:
                    stats['other'] += 1; byte_stats['other'] += pkt_len; direction = "OTHER"

        # ---- ALWAYS update "tracked" counters ----
        if track_ip and IP in pkt and pkt[IP].dst == track_ip:
            tracked_rx_per_second[rx_sec] += 1
            tracked_rx_bytes_per_second[rx_sec] += pkt_len
        if track_mac and Ether in pkt and pkt[Ether].dst.lower() == track_mac.lower():
            tracked_rx_per_second[rx_sec] += 1
            tracked_rx_bytes_per_second[rx_sec] += pkt_len

        # ---- directional tallies (IPs/MACs) ----
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            ip_directional_stats[src]['tx'] += 1
            ip_directional_stats[dst]['rx'] += 1

        if Ether in pkt:
            s = pkt[Ether].src.lower()
            d = pkt[Ether].dst.lower()
            mac_directional_stats[s]['tx'] += 1
            mac_directional_stats[d]['rx'] += 1

        # (Per-packet printing and CSV writes removed)
        if direction:
            summary = pkt.summary()
            #print(f"[{timestamp_str}] {direction} ➜ {summary} | Wire-IAT: {None if wire_iat_ms is None else round(wire_iat_ms,3)} ms")
            writer.writerow([timestamp_str, direction,
                             None if wire_iat_ms is None else round(wire_iat_ms, 3),
                             summary])

    # ---- kernel-level BPF (captures ALL traffic to keep behavior identical) ----
    # This is a tautology for libpcap: evaluates true for every frame.
    # ---- handle replay modes ----
    if replay_pcap:
        # read pcap and feed packets through match() — keeps behavior identical to live sniff
        try:
            pcap_pkts = rdpcap(replay_pcap)
            if not pcap_pkts:
                print(f"⚠ replay_pcap: file {replay_pcap} contained no packets.")
            # set first_pkt_time based on first packet
            pcap_pkts = sorted(pcap_pkts, key=lambda p: getattr(p, 'time', 0))
            # set timeline anchors so rx_sec calculations match pcap times
            if pcap_pkts and hasattr(pcap_pkts[0], 'time'):
                #first_pkt_time = pcap_pkts[0].time
                first_pkt_time = float(pcap_pkts[0].time)
            # iterate and call match for each packet
            for pkt in pcap_pkts:
                # ensure pkt.time exists
                if not hasattr(pkt, 'time'):
                    pkt.time = first_pkt_time or time.time()
                match(pkt)
                captured_packets.append(pkt)
            # skip live sniffing and plotting wait — but still produce final charts below
            print(f"✅ Replayed {len(pcap_pkts)} packets from {replay_pcap}")
        except FileNotFoundError:
            print(f"❌ replay_pcap file not found: {replay_pcap}")
        except Exception as e:
            print(f"❌ Failed to replay pcap {replay_pcap}: {e}")

    elif replay_csv:
        # CSV replay: reconstruct per-second counters and wire IAT buckets from our logged CSV
        # NOTE: the CSV contains only Timestamp, Direction, Wire IAT (ms), Summary
        # so we can restore per-second counts and IAT aggregates but NOT full scapy pkt fields (IP/MAC).
        try:
            import datetime
            rows = []
            with open(replay_csv, newline='', encoding='utf-8') as rcsv:
                reader = csv.DictReader(rcsv)
                for row in reader:
                    # parse Timestamp as localtime string "YYYY-MM-DD HH:MM:SS"
                    ts = None
                    if row.get("Timestamp"):
                        try:
                            dt = datetime.datetime.strptime(row["Timestamp"], "%Y-%m-%d %H:%M:%S")
                            ts = dt.timestamp()
                        except Exception:
                            # if parse fails, use increasing timestamps
                            ts = start_time + len(rows)
                    direction = row.get("Direction", "").upper()
                    iat = None
                    try:
                        iat = float(row.get("Wire IAT (ms)", "") or 0.0)
                    except Exception:
                        iat = 0.0
                    rows.append((ts, direction, iat, row.get("Summary","")))
            if not rows:
                print(f"⚠ replay_csv: file {replay_csv} contained no rows.")
            rows = sorted(rows, key=lambda x: x[0])
            if rows:
                first_pkt_time = rows[0][0]
            # iterate rows and populate counters
            last_row_ts = None
            for ts, direction, iat_ms, summary in rows:
                # create a fake minimal object so match-like CSV writes still work partially
                class _FakePkt:
                    pass
                p = _FakePkt()
                p.time = ts
                # minimal attributes for len(p) and summary — length unknown, set to 0
                def _summary():
                    return summary
                p.__len__ = lambda self: 0
                p.summary = _summary
                # update wire iat aggregates
                if last_row_ts is not None and ts is not None:
                    wire_iat_ms_local = (ts - last_row_ts) * 1000.0
                    wire_iat_sum_ms += wire_iat_ms_local
                    wire_iat_count += 1
                    rx_sec = int(ts - (first_pkt_time or start_time))
                    wire_iat_sum_ms_persec[rx_sec] += wire_iat_ms_local
                    wire_iat_count_persec[rx_sec] += 1
                last_row_ts = ts
                # update direction counts and per-second buckets
                rx_sec = int(ts - (first_pkt_time or start_time))
                if direction == "TX":
                    stats['tx'] += 1
                    tx_per_second[rx_sec] += 1
                elif direction == "RX":
                    stats['rx'] += 1
                    rx_per_second[rx_sec] += 1
                else:
                    stats['other'] += 1
                # write log line similar to match()
                writer.writerow([
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                    direction,
                    round(iat_ms, 3) if iat_ms is not None else None,
                    summary
                ])
            print(f"✅ Replayed {len(rows)} CSV rows from {replay_csv}. Note: IP/MAC-level stats not reconstructable from CSV.")
        except FileNotFoundError:
            print(f"❌ replay_csv file not found: {replay_csv}")
        except Exception as e:
            print(f"❌ Failed to replay csv {replay_csv}: {e}")

    else:
        # ---- kernel-level BPF (captures ALL traffic to keep behavior identical) ----
        # This is a tautology for libpcap: evaluates true for every frame. 
        bpf = "len >= 0"

        # ---- sniff thread ----
        def sniff_packets():
            nonlocal captured_packets
            captured_packets = sniff(
                iface=iface,
                timeout=timeout,
                store=1,
                prn=match,
                filter=bpf  # kernel-level filter present, but non-restrictive
            )

        print("\n⏱ Starting packet sniffing...")
        print(f"Using kernel BPF filter: {bpf}")
        sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
        sniff_thread.start()

        # ---- quick live plot ----
        fig, ax = plt.subplots()
        tx_line, = ax.plot([], [], label='Transmit', color='blue')
        rx_line, = ax.plot([], [], label='Receive', color='red')
        ax.set_xlabel("Seconds"); ax.set_ylabel("Packets")
        ax.set_title("Live Packet Count (TX vs RX)")
        ax.grid(); ax.legend()

        def update(_frame):
            now = time.time()
            if now > stop_time:
                plt.close(fig); return
            elapsed = int(now - start_time)
            time_points.append(elapsed)
            tx_points.append(stats['tx'])
            rx_points.append(stats['rx'])
            tx_line.set_data(time_points, tx_points)
            rx_line.set_data(time_points, rx_points)
            ax.relim(); ax.autoscale_view()

        ani = FuncAnimation(fig, update, interval=1000)
        plt.show()

        sniff_thread.join()
    # If we replayed pcap, we didn't run live plotting above; but we still want to continue to finalization.
    # ---- finalize timings ----
    if first_pkt_time is not None and last_pkt_time is not None:
        total_duration = max(1e-5, last_pkt_time - first_pkt_time)
    else:
        total_duration = 1e-5

    # ---- summary calculations ----
    processed_count = stats['tx'] + stats['rx']
    total_packets = processed_count + stats['other']

    tx_bytes = byte_stats['tx']; rx_bytes = byte_stats['rx']; other_bytes = byte_stats['other']
    total_tx_rx_bytes = tx_bytes + rx_bytes
    total_bytes = total_tx_rx_bytes + other_bytes
    average_packet_size = (total_bytes / total_packets) if total_packets else 0

    tx_rate = stats['tx'] / total_duration
    rx_rate = stats['rx'] / total_duration
    total_tx_rx_rate = tx_rate + rx_rate
    other_rate = stats['other'] / total_duration
    total_rate = total_packets / total_duration

    tx_bps = tx_bytes * 8 / total_duration
    rx_bps = rx_bytes * 8 / total_duration
    total_tx_rx_bps = total_tx_rx_bytes * 8 / total_duration
    Other_bps = other_bytes * 8 / total_duration
    total_bps = total_bytes * 8 / total_duration

    tx_Bps = tx_bytes / total_duration
    rx_Bps = rx_bytes / total_duration
    total_tx_rx_Bps = total_tx_rx_bytes / total_duration
    Other_Bps = other_bytes / total_duration
    total_Bps = total_bytes / total_duration

    # ---- Wire IAT averages (overall) ----
    avg_wire_iat_ms = (wire_iat_sum_ms / wire_iat_count) if wire_iat_count > 0 else 0.0

    # ---- persist artifacts ----
    #fig.savefig("packet_chart.png")
    if 'fig' in locals():
        try:
            fig.savefig("packet_chart.png")
        except Exception as e:
            print("⚠ could not save figure:", e)
    else:
        print("⚠ No live figure to save (replay mode) — packet_chart.png not created from live plot.")
        # If we did live sniff or replay_csv, write a pcap of captured_packets. If replay_pcap was used, avoid overwriting unless you still want to.
    try:
        if not replay_pcap:
            wrpcap("capture1.pcap", captured_packets)
            print(" Packets exported to capture1.pcap")
        else:
            print("⚠ replay_pcap mode: original pcap was used; not overwriting capture1.pcap")
    except Exception as e:
        print("⚠ could not write pcap:", e)
    
    print("\n Sniffing completed.")
    print(f" Peak memory usage: {peak_memory:.2f} KB")
    print("\n Packet Counter Results:")
    print(f"  - TX: {stats['tx']}")
    print(f"  - RX: {stats['rx']}")
    print(f"  - OTHER: {stats['other']}")
    print(f"  - Filtered (TX+RX): {processed_count}")
    Not_Filtered_PKT = len(captured_packets) - processed_count
    print(f"  - Not Filtered Based on specified address: {Not_Filtered_PKT}")
    print(f"\n  - Raw captured total: {len(captured_packets)}")
    print(f"  - Total Bytes Captured: {total_bytes}")
    print(f"  - Total Execution Time: {total_duration:.3f} seconds")
    print(f"  - Average Packet Size: {average_packet_size:.0f} Bytes")
    print(f"  - Avg Inter-Packet Time: {avg_wire_iat_ms:.4f} ms")
    print("\n Packet Rates:")
    print(f"  - TX Rate   : {tx_rate:.2f} packets/sec")
    print(f"  - RX Rate   : {rx_rate:.2f} packets/sec")
    print(f"  - total (tx+rx) Rate   : {total_tx_rx_rate:.2f} packets/sec")
    print(f"  - Other Rate   : {other_rate:.2f} packets/sec")
    print(f"  - Total Rate: {total_rate:.2f} packets/sec")

    print("\n Data Rates:")
    print(f"  - TX: {tx_bps:.2f} bps ({tx_Bps:.2f} Bps)")
    print(f"  - RX: {rx_bps:.2f} bps ({rx_Bps:.2f} Bps)")
    print(f"  - Total (tx+rx): {total_tx_rx_bps:.2f} bps ({total_tx_rx_Bps:.2f} Bps)")
    print(f"  - Other: {Other_bps:.2f} bps ({Other_Bps:.2f} Bps)")
    print(f"  - Total: {total_bps:.2f} bps ({total_Bps:.2f} Bps)")
    print(f"\n- Packet Snap Length (snaplen): 65535 bytes (default)")

    print("\n Per-IP Packet Statistics:")
    for ip, data in sorted(ip_directional_stats.items()):
        print(f"  {ip} ➜ Sent: {data['tx']} packets, Received: {data['rx']} packets")
    print("\n Per-MAC Packet Statistics:")
    for mac, data in sorted(mac_directional_stats.items()):
        print(f"  {mac} ➜ Sent: {data['tx']} packets, Received: {data['rx']} packets")
    print(" Chart saved to packet_chart.png")
    #print(" Packets exported to capture1.pcap")
    print("\n Log saved to packet_log.csv")

    # ---- optional charts (kept as in your code) ----
    import numpy as np

    # === Bar chart for IP Sent ===
    ips = list(ip_directional_stats.keys())
    tx_ip_values = [ip_directional_stats[ip]['tx'] for ip in ips]
    rx_ip_values = [ip_directional_stats[ip]['rx'] for ip in ips]

    # === Bar chart for MAC Sent ===
    macs = list(mac_directional_stats.keys())
    tx_mac_values = [mac_directional_stats[mac]['tx'] for mac in macs]
    rx_mac_values = [mac_directional_stats[mac]['rx'] for mac in macs]

    plt.figure(figsize=(12, 6))
    #plt.bar(macs, tx_mac_values, color='purple')
    plt.bar(macs, tx_mac_values)  # removed explicit colors to match our earlier imports style
    plt.xticks(rotation=45, ha='right')
    plt.title("Sent Packets per MAC Address")
    plt.xlabel("MAC Address")
    plt.ylabel("Sent Packets")
    plt.tight_layout()
    plt.savefig("mac_sent_packets.png")
    plt.show()

    plt.figure(figsize=(12, 6))
    #plt.bar(macs, rx_mac_values, color='orange')
    plt.bar(macs, rx_mac_values)
    plt.xticks(rotation=45, ha='right')
    plt.title("Received Packets per MAC Address")
    plt.xlabel("MAC Address")
    plt.ylabel("Received Packets")
    plt.tight_layout()
    plt.savefig("mac_received_packets.png")
    plt.show()

    seconds_sorted = sorted(tx_per_second.keys())
    rx_counts = [tx_per_second[sec] for sec in seconds_sorted]
    plt.figure(figsize=(10, 5))
    #plt.plot(seconds_sorted, rx_counts, marker='o', color='green')
    plt.plot(seconds_sorted, rx_counts, marker='o')
    plt.title("Packets To Destination Per Second (PLC-src → MD-dst)")
    plt.xlabel("Elapsed Time (seconds)")
    plt.ylabel("Received Packets")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("src_dst_packets_per_second.png")
    plt.show()

    # RX tracked per-second (if any)
    if tracked_rx_per_second:
        sec_sorted = sorted(tracked_rx_per_second.keys())
        tracked_counts = [tracked_rx_per_second[s] for s in sec_sorted]
        label = track_ip if track_ip else track_mac
        plt.figure(figsize=(10, 5))
        #plt.plot(sec_sorted, tracked_counts, marker='o', color='orange')
        plt.plot(sec_sorted, tracked_counts, marker='o')
        plt.title(f"Tracked RX Packets Per Second - {label}")
        plt.xlabel("Elapsed Time (seconds)")
        plt.ylabel("Packets to Tracked Address")
        plt.grid(True)
        plt.tight_layout()
        plt.savefig("tracked_rx_packets_per_second.png")
        plt.show()
    else:
        print(f"⚠ No packets received for tracked address: {track_ip or track_mac}")

    # -----------------------------
    # Send to Splunk (batched)
    # -----------------------------
    def send_to_splunk(events):
        headers = {
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json"
        }
        payload = "\n".join(json.dumps(e) for e in events)
        try:
            r = requests.post(
                SPLUNK_HEC_URL,
                data=payload,
                headers=headers,
                timeout=10,
                verify=False
            )
            if r.status_code != 200:
                print("HEC error:", r.status_code, r.text)
            r.raise_for_status()
        except requests.RequestException as e:
            print("❌ HEC post failed:", e)

    import math
    def _union_keys(*dicts):
        ks = set()
        for d in dicts:
            ks |= set(d.keys())
        return sorted(ks)

    all_secs = _union_keys(
        rx_per_second, rx_bytes_per_second,
        tracked_rx_per_second, tracked_rx_bytes_per_second,
        fwd_per_second, fwd_bytes_per_second,
        rev_per_second, rev_bytes_per_second
    )
    # buffer of last SEQ_LEN scaled feature vectors
    seq_buffer = deque(maxlen=_RF_SEQ_LEN if _RF_MODEL is not None else 1)
    pred_next_scaled = None   # holds prediction for the next observation
    if not all_secs:
        print("⚠ No per-second buckets to send (no traffic matched your filters).")
    else:
        window_seconds = int(math.ceil(stop_time - start_time))
        base_time = int(start_time)
        
        # CSV dataset
        csv_file = "features_dataset.csv"
        write_header = not os.path.exists(csv_file)
        with open(csv_file, "a", newline='', encoding="utf-8") as fcsv:
            fieldnames = [
                "time",
                "rx_packets_per_sec",
                "rx_bytes_per_sec",
                "avg_pkt_size_bytes_to_dst",
                "avg_wire_iat_ms",
                "label"
            ]
            writer_feat = csv.DictWriter(fcsv, fieldnames=fieldnames)
            if write_header:
                writer_feat.writeheader()
        
            events = []
            for sec in range(0, window_seconds):
                to_dst_pkts    = int(fwd_per_second.get(sec, 0))
                to_dst_bytes   = int(fwd_bytes_per_second.get(sec, 0))
                from_dst_pkts  = int(rev_per_second.get(sec, 0))
                from_dst_bytes = int(rev_bytes_per_second.get(sec, 0))

                if wire_iat_count_persec.get(sec, 0) > 0:
                    avg_iat_ms_sec = wire_iat_sum_ms_persec[sec] / wire_iat_count_persec[sec]
                else:
                    avg_iat_ms_sec = 0.0

                legacy_rx_pkts  = int(fwd_per_second.get(sec, rx_per_second.get(sec, 0)))
                legacy_rx_bytes = int(fwd_bytes_per_second.get(sec, rx_bytes_per_second.get(sec, 0)))
                
                
                # Dataset Feature 
                avg_pkt_size_to = (to_dst_bytes / max(to_dst_pkts, 1))
                label = "attack" if (
                    legacy_rx_pkts > 506 or
                    legacy_rx_pkts < 491 or
                    legacy_rx_bytes > 67500 or
                    avg_iat_ms_sec < 1.92 or
                    avg_iat_ms_sec > 2.01 or
                    avg_pkt_size_to != 133
                    ) else "normal"
                writer_feat.writerow({
                    "time": base_time + sec,
                    "rx_packets_per_sec": legacy_rx_pkts,
                    "rx_bytes_per_sec": legacy_rx_bytes,
                    "avg_pkt_size_bytes_to_dst": avg_pkt_size_to,
                    "avg_wire_iat_ms": avg_iat_ms_sec,
                    "label": label,
                    #"ml_pred": pred,              # 1 / 0
                    #"ml_score": prob
                })
                # ----- RF forecast-based anomaly scoring (same logic as LSTM) -----
                rf_anomaly = 0
                rf_score = None
                rf_threshold = _RF_THRESHOLD
                rf_forecast_rx_pps = None

                if _RF_MODEL is not None:
                    feat_vec = np.array([[  # current observation (unscaled)
                        legacy_rx_pkts,
                        legacy_rx_bytes,
                        avg_pkt_size_to,
                        avg_iat_ms_sec
                    ]], dtype=np.float32)

                    feat_scaled = _RF_SCALER.transform(feat_vec)[0]

                    # 1) Score CURRENT point using prediction made at previous step
                    if pred_next_scaled is not None:
                        mse = float(np.mean((pred_next_scaled - feat_scaled) ** 2))
                        rf_score = mse
                        if mse > _RF_THRESHOLD:
                            rf_anomaly = 1

                    # 2) Update buffer with current observation
                    seq_buffer.append(feat_scaled)

                    # 3) Predict NEXT point (t+1) from last SEQ_LEN observations
                    if len(seq_buffer) == _RF_SEQ_LEN:
                        X_flat = np.array(seq_buffer, dtype=np.float32).reshape(1, -1)  # flatten
                        pred_next_scaled = _RF_MODEL.predict(X_flat)[0]  # (n_features,)

                        pred_next_unscaled = _RF_SCALER.inverse_transform(pred_next_scaled.reshape(1, -1))[0]
                        rf_forecast_rx_pps = float(pred_next_unscaled[0])
                    else:
                        pred_next_scaled = None

                # ---- realtime ML scoring (optional) ----
                '''
                row = {
                    "rx_packets_per_sec": legacy_rx_pkts,
                    "rx_bytes_per_sec":   legacy_rx_bytes,
                    "avg_pkt_size_bytes_to_dst": avg_pkt_size_to,
                    "avg_wire_iat_ms":    avg_iat_ms_sec
                }
                '''

                
                events.append({
                    "time": base_time + sec,
                    "host": HOSTNAME,
                    "source": SPLUNK_SOURCE,
                    "sourcetype": SPLUNK_SOURCETYPE,
                    "index": SPLUNK_INDEX,
                    "event": {
                        "iface": iface,
                        "dst_mac": (dst_mac or track_mac or "").lower(),
                        "to_dst_packets_per_sec":   to_dst_pkts,
                        "to_dst_bytes_per_sec":     to_dst_bytes,
                        "from_dst_packets_per_sec": from_dst_pkts,
                        "from_dst_bytes_per_sec":   from_dst_bytes,
                        "rx_packets_per_sec":       legacy_rx_pkts,
                        "rx_bytes_per_sec":         legacy_rx_bytes,
                        "avg_wire_iat_ms":          avg_iat_ms_sec,
                        "wire_iat_samples_in_sec":  int(wire_iat_count_persec.get(sec, 0)),
                        "tracked_rx_packets_per_sec": int(tracked_rx_per_second.get(sec, 0)),
                        "tracked_rx_bytes_per_sec":   int(tracked_rx_bytes_per_second.get(sec, 0)),
                        "avg_pkt_size_bytes_to_dst":   (to_dst_bytes   / max(to_dst_pkts, 1)),
                        "avg_pkt_size_bytes_from_dst": (from_dst_bytes / max(from_dst_pkts, 1)),
                        "hostname": HOSTNAME,
                        "sniffer_version": "1.2.0",
                        
                        "lstm_anomaly": int(rf_anomaly),
                        #"rf_score": rf_score,
                        "rf_score": (None if rf_score is None else float(rf_score)),
                        "rf_threshold": rf_threshold,
                        "rf_forecast_rx_pps": rf_forecast_rx_pps,
                        "label": label,

                    }
                })
                '''
                if rf_anomaly == 1:
                    events.append({
                        "time": base_time + sec,
                        "host": HOSTNAME,
                        "source": "rf_forecaster",
                        "sourcetype": "alert:rf_forecast_anomaly",
                        "index": SPLUNK_INDEX,
                        "event": {
                            "alert": "rf_anomaly_detected",
                            "score": rf_score,
                            "threshold": rf_threshold,
                            "forecast_rx_pps_next": rf_forecast_rx_pps,
                            "label": label,
                            "rx_packets_per_sec": legacy_rx_pkts,
                            "rx_bytes_per_sec": legacy_rx_bytes,
                            "avg_pkt_size_bytes_to_dst": avg_pkt_size_to,
                            "avg_wire_iat_ms": avg_iat_ms_sec,
                        }
                    })
                    '''


    if 'events' in locals() and events:
        try:
            CHUNK = 500
            for i in range(0, len(events), CHUNK):
                send_to_splunk(events[i:i + CHUNK])
            print(f"✅ Sent {len(events)} per-second events to Splunk.")
        except Exception as e:
            print(f"❌ Failed to send to Splunk: {e}")


# -------------- Run (L2 example) --------------
if __name__ == "__main__":
    # === Run using your Layer 2 test ===
    packet_counter(
    src_mac='30:b8:51:03:21:a2',
    dst_mac='00:0d:1e:1c:64:32',
    iface='Ethernet',
    timeout=350,
    replay_pcap='D:\\PhD L\'Aquila\\Selmec\\4-12 replay file attack 250 sec 2 - 350\\capture1.pcap'
    #replay_pcap='D:\\PhD L\'Aquila\\Selmec\\4 attack high packets 1000- move 60 sec\\capture1.pcap'
    )

    
    '''
    packet_counter(
        #src_mac='00:0d:1e:1c:64:32', # My PC
        #src_mac='cc:82:7f:86:96:a7',
        src_mac='30:b8:51:03:21:a2',  # PLC
        #src_mac='dc:a6:32:77:84:47', # PI 1 send
        #dst_mac='A4:91:B1:80:D5:6F',
        dst_mac='00:0d:1e:1c:64:32',  # MD
        #track_ip='192.168.1.254',
        #track_mac='dc:a6:32:77:82:af',
        #iface='Wi-Fi',
        iface='Ethernet 2',
        timeout=50
    )
'''
'''
# Layer 3 (IP level)
packet_counter(
     src_ip='10.0.9.41',
     dst_ip='10.0.9.253',
     iface='Ethernet 2',
     timeout=30
 )
'''

