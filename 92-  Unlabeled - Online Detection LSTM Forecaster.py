# Unlabeled - Online Detection LSTM Forecaster

'''
import sys, subprocess
subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
subprocess.check_call([sys.executable, "-m", "pip", "install",
                       "requests", "psutil", "scapy", "matplotlib", "tensorflow", "joblib"])
'''
import time
import os
import json
import socket
import threading
import csv
from collections import defaultdict, deque

import requests
import psutil
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from scapy.all import sniff, IP, Ether, conf
from scapy.utils import rdpcap, wrpcap

import numpy as np
from tensorflow.keras.models import load_model
import joblib

conf.use_pcap = True

# ---- load LSTM forecaster and meta ----
try:
    _LSTM_MODEL = load_model("lstm_forecaster.h5", compile=False)
    _LSTM_META = joblib.load("lstm_meta.joblib")
    _LSTM_SCALER = _LSTM_META["scaler"]
    _LSTM_FEATURES = _LSTM_META["features"]
    _LSTM_SEQ_LEN = _LSTM_META["seq_len"]
    _LSTM_THRESHOLD = float(_LSTM_META["threshold"])
    print("✅ Loaded LSTM forecaster.")
except Exception as e:
    _LSTM_MODEL = None
    _LSTM_SCALER = None
    _LSTM_FEATURES = None
    _LSTM_SEQ_LEN = 0
    _LSTM_THRESHOLD = float("inf")
    print("⚠ LSTM model not loaded, anomaly detection disabled:", e)

# -----------------------------
# Splunk HEC configuration
# -----------------------------
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088/services/collector")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "cdab321d-23f9-4818-a413-380f80936bfa")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "main")
SPLUNK_SOURCE = "Scapy-sniffer"
SPLUNK_SOURCETYPE = "net:rx"
HOSTNAME = socket.gethostname()


def packet_counter(
    src_ip=None, dst_ip=None,
    src_mac=None, dst_mac=None,
    track_ip=None, track_mac=None,
    iface=None, timeout=30,
    replay_pcap=None,
    replay_csv=None
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

    # packet log (for debugging)
    log_file = open("packet_log.csv", "w", newline='', encoding='utf-8')
    writer = csv.writer(log_file)
    writer.writerow(["Timestamp", "Direction", "Wire IAT (ms)", "Summary"])

    start_time = time.time()
    stop_time = start_time + timeout
    process = psutil.Process(os.getpid())

    def zero_counters():
        return {'tx': 0, 'rx': 0}

    ip_directional_stats = defaultdict(zero_counters)
    mac_directional_stats = defaultdict(zero_counters)

    # directional between src_mac -> dst_mac
    fwd_per_second = defaultdict(int)
    fwd_bytes_per_second = defaultdict(int)
    rev_per_second = defaultdict(int)
    rev_bytes_per_second = defaultdict(int)

    # ---- packet handler ----
    def match(pkt):
        nonlocal stats, last_timestamp, peak_memory, first_pkt_time, last_pkt_time
        nonlocal ip_directional_stats, mac_directional_stats
        nonlocal last_wire_ts, wire_iat_sum_ms, wire_iat_count
        nonlocal wire_iat_sum_ms_persec, wire_iat_count_persec

        pkt_time = float(pkt.time)
        if first_pkt_time is None:
            first_pkt_time = pkt_time
        last_pkt_time = pkt_time

        _now = time.time()
        memory = process.memory_info().rss / 1024
        peak_memory = max(peak_memory, memory)

        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pkt_time))
        pkt_len = len(pkt) if hasattr(pkt, '__len__') else 0
        rx_sec = int(pkt_time - (first_pkt_time or start_time))

        # Inter-packet time (wire)
        wire_iat_ms = None
        if last_wire_ts is not None:
            wire_iat_ms = (pkt_time - last_wire_ts) * 1000.0
            wire_iat_sum_ms += wire_iat_ms
            wire_iat_count += 1
            wire_iat_sum_ms_persec[rx_sec] += wire_iat_ms
            wire_iat_count_persec[rx_sec] += 1
        last_wire_ts = pkt_time

        direction = None

        # ---------- L3: IP ----------
        if IP in pkt and (src_ip or dst_ip):
            s_ip = pkt[IP].src
            d_ip = pkt[IP].dst

            if src_ip and dst_ip:
                if s_ip == src_ip and d_ip == dst_ip:
                    stats['tx'] += 1
                    byte_stats['tx'] += pkt_len
                    direction = "TX"
                    tx_per_second[rx_sec] += 1
                    tx_bytes_per_second[rx_sec] += pkt_len
                elif s_ip == dst_ip and d_ip == src_ip:
                    stats['rx'] += 1
                    byte_stats['rx'] += pkt_len
                    direction = "RX"
                    rx_per_second[rx_sec] += 1
                    rx_bytes_per_second[rx_sec] += pkt_len
                else:
                    stats['other'] += 1
                    byte_stats['other'] += pkt_len
                    direction = "OTHER"
            else:
                if dst_ip and d_ip == dst_ip:
                    stats['rx'] += 1
                    byte_stats['rx'] += pkt_len
                    direction = "RX"
                    rx_per_second[rx_sec] += 1
                    rx_bytes_per_second[rx_sec] += pkt_len
                elif src_ip and s_ip == src_ip:
                    stats['tx'] += 1
                    byte_stats['tx'] += pkt_len
                    direction = "TX"
                    tx_per_second[rx_sec] += 1
                    tx_bytes_per_second[rx_sec] += pkt_len
                else:
                    stats['other'] += 1
                    byte_stats['other'] += pkt_len
                    direction = "OTHER"

        # ---------- L2: MAC ----------
        elif Ether in pkt and (src_mac or dst_mac):
            s = pkt[Ether].src.lower()
            d = pkt[Ether].dst.lower()
            sm = src_mac.lower() if src_mac else None
            dm = dst_mac.lower() if dst_mac else None

            if sm and dm:
                if s == sm and d == dm:
                    stats['tx'] += 1
                    byte_stats['tx'] += pkt_len
                    direction = "TX"
                    fwd_per_second[rx_sec] += 1
                    fwd_bytes_per_second[rx_sec] += pkt_len
                    tx_per_second[rx_sec] += 1
                    tx_bytes_per_second[rx_sec] += pkt_len
                elif s == dm and d == sm:
                    stats['rx'] += 1
                    byte_stats['rx'] += pkt_len
                    direction = "RX"
                    rev_per_second[rx_sec] += 1
                    rev_bytes_per_second[rx_sec] += pkt_len
                    rx_per_second[rx_sec] += 1
                    rx_bytes_per_second[rx_sec] += pkt_len
                else:
                    stats['other'] += 1
                    byte_stats['other'] += pkt_len
                    direction = "OTHER"
            else:
                if dm and d == dm:
                    stats['rx'] += 1
                    byte_stats['rx'] += pkt_len
                    direction = "RX"
                    rx_per_second[rx_sec] += 1
                    rx_bytes_per_second[rx_sec] += pkt_len
                elif sm and s == sm:
                    stats['tx'] += 1
                    byte_stats['tx'] += pkt_len
                    direction = "TX"
                    tx_per_second[rx_sec] += 1
                    tx_bytes_per_second[rx_sec] += pkt_len
                else:
                    stats['other'] += 1
                    byte_stats['other'] += pkt_len
                    direction = "OTHER"

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

        # log to CSV for debugging
        if direction:
            summary = pkt.summary()
            writer.writerow([
                timestamp_str,
                direction,
                None if wire_iat_ms is None else round(wire_iat_ms, 3),
                summary
            ])

    # ---------- capture / replay ----------
    if replay_pcap:
        try:
            pcap_pkts = rdpcap(replay_pcap)
            if not pcap_pkts:
                print(f"⚠ replay_pcap: file {replay_pcap} contained no packets.")
            pcap_pkts = sorted(pcap_pkts, key=lambda p: getattr(p, 'time', 0))
            if pcap_pkts and hasattr(pcap_pkts[0], 'time'):
                first_pkt_time = float(pcap_pkts[0].time)
            for pkt in pcap_pkts:
                if not hasattr(pkt, 'time'):
                    pkt.time = first_pkt_time or time.time()
                match(pkt)
                captured_packets.append(pkt)
            print(f"✅ Replayed {len(pcap_pkts)} packets from {replay_pcap}")
        except FileNotFoundError:
            print(f"❌ replay_pcap file not found: {replay_pcap}")
        except Exception as e:
            print(f"❌ Failed to replay pcap {replay_pcap}: {e}")

    elif replay_csv:
        try:
            import datetime
            rows = []
            with open(replay_csv, newline='', encoding='utf-8') as rcsv:
                reader = csv.DictReader(rcsv)
                for row in reader:
                    ts = None
                    if row.get("Timestamp"):
                        try:
                            dt = datetime.datetime.strptime(row["Timestamp"], "%Y-%m-%d %H:%M:%S")
                            ts = dt.timestamp()
                        except Exception:
                            ts = start_time + len(rows)
                    direction = row.get("Direction", "").upper()
                    try:
                        iat = float(row.get("Wire IAT (ms)", "") or 0.0)
                    except Exception:
                        iat = 0.0
                    rows.append((ts, direction, iat, row.get("Summary", "")))
            if not rows:
                print(f"⚠ replay_csv: file {replay_csv} contained no rows.")
            rows = sorted(rows, key=lambda x: x[0])
            if rows:
                first_pkt_time = rows[0][0]
            last_row_ts = None
            for ts, direction, iat_ms, summary in rows:
                class _FakePkt:
                    pass
                p = _FakePkt()
                p.time = ts

                def _summary():
                    return summary
                p.__len__ = lambda self: 0
                p.summary = _summary

                if last_row_ts is not None and ts is not None:
                    wire_iat_ms_local = (ts - last_row_ts) * 1000.0
                    wire_iat_sum_ms += wire_iat_ms_local
                    wire_iat_count += 1
                    rx_sec = int(ts - (first_pkt_time or start_time))
                    wire_iat_sum_ms_persec[rx_sec] += wire_iat_ms_local
                    wire_iat_count_persec[rx_sec] += 1
                last_row_ts = ts

                rx_sec = int(ts - (first_pkt_time or start_time))
                if direction == "TX":
                    stats['tx'] += 1
                    tx_per_second[rx_sec] += 1
                elif direction == "RX":
                    stats['rx'] += 1
                    rx_per_second[rx_sec] += 1
                else:
                    stats['other'] += 1

                writer.writerow([
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                    direction,
                    round(iat_ms, 3) if iat_ms is not None else None,
                    summary
                ])
            print(f"✅ Replayed {len(rows)} CSV rows from {replay_csv}.")
        except FileNotFoundError:
            print(f"❌ replay_csv file not found: {replay_csv}")
        except Exception as e:
            print(f"❌ Failed to replay csv {replay_csv}: {e}")

    else:
        bpf = "len >= 0"

        def sniff_packets():
            nonlocal captured_packets
            captured_packets = sniff(
                iface=iface,
                timeout=timeout,
                store=1,
                prn=match,
                filter=bpf
            )

        print("\n⏱ Starting packet sniffing...")
        print(f"Using kernel BPF filter: {bpf}")
        sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
        sniff_thread.start()

        fig, ax = plt.subplots()
        tx_line, = ax.plot([], [], label='Transmit', color='blue')
        rx_line, = ax.plot([], [], label='Receive', color='red')
        ax.set_xlabel("Seconds")
        ax.set_ylabel("Packets")
        ax.set_title("Live Packet Count (TX vs RX)")
        ax.grid()
        ax.legend()

        def update(_frame):
            now = time.time()
            if now > stop_time:
                plt.close(fig)
                return
            elapsed = int(now - start_time)
            time_points.append(elapsed)
            tx_points.append(stats['tx'])
            rx_points.append(stats['rx'])
            tx_line.set_data(time_points, tx_points)
            rx_line.set_data(time_points, rx_points)
            ax.relim()
            ax.autoscale_view()

        ani = FuncAnimation(fig, update, interval=1000)
        plt.show()

        sniff_thread.join()

    # ---- finalize timings ----
    if first_pkt_time is not None and last_pkt_time is not None:
        total_duration = max(1e-5, last_pkt_time - first_pkt_time)
    else:
        total_duration = 1e-5

    processed_count = stats['tx'] + stats['rx']
    total_packets = processed_count + stats['other']

    tx_bytes = byte_stats['tx']
    rx_bytes = byte_stats['rx']
    other_bytes = byte_stats['other']
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
    other_bps = other_bytes * 8 / total_duration
    total_bps = total_bytes * 8 / total_duration

    tx_Bps = tx_bytes / total_duration
    rx_Bps = rx_bytes / total_duration
    total_tx_rx_Bps = total_tx_rx_bytes / total_duration
    other_Bps = other_bytes / total_duration
    total_Bps = total_bytes / total_duration

    avg_wire_iat_ms = (wire_iat_sum_ms / wire_iat_count) if wire_iat_count > 0 else 0.0

    if 'fig' in locals():
        try:
            fig.savefig("packet_chart.png")
        except Exception as e:
            print("⚠ could not save figure:", e)
    else:
        print("⚠ No live figure to save (replay mode).")

    try:
        if not replay_pcap:
            wrpcap("capture1.pcap", captured_packets)
            print("Packets exported to capture1.pcap")
        else:
            print("⚠ replay_pcap mode: original pcap was used; not overwriting capture1.pcap")
    except Exception as e:
        print("⚠ could not write pcap:", e)

    print("\nSniffing completed.")
    print(f" Peak memory usage: {peak_memory:.2f} KB")
    print("\n Packet Counter Results:")
    print(f"  - TX: {stats['tx']}")
    print(f"  - RX: {stats['rx']}")
    print(f"  - OTHER: {stats['other']}")
    print(f"  - Filtered (TX+RX): {processed_count}")
    not_filtered_pkt = len(captured_packets) - processed_count
    print(f"  - Not Filtered Based on specified address: {not_filtered_pkt}")
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
    print(f"  - Other: {other_bps:.2f} bps ({other_Bps:.2f} Bps)")
    print(f"  - Total: {total_bps:.2f} bps ({total_Bps:.2f} Bps)")
    print(f"\n- Packet Snap Length (snaplen): 65535 bytes (default)")

    print("\n Per-IP Packet Statistics:")
    for ip, data in sorted(ip_directional_stats.items()):
        print(f"  {ip} ➜ Sent: {data['tx']} packets, Received: {data['rx']} packets")
    print("\n Per-MAC Packet Statistics:")
    for mac, data in sorted(mac_directional_stats.items()):
        print(f"  {mac} ➜ Sent: {data['tx']} packets, Received: {data['rx']} packets")
    print(" Chart saved to packet_chart.png")
    print("\n Log saved to packet_log.csv")

    # ---- optional charts ----
    macs = list(mac_directional_stats.keys())
    tx_mac_values = [mac_directional_stats[mac]['tx'] for mac in macs]
    rx_mac_values = [mac_directional_stats[mac]['rx'] for mac in macs]

    plt.figure(figsize=(12, 6))
    plt.bar(macs, tx_mac_values)
    plt.xticks(rotation=45, ha='right')
    plt.title("Sent Packets per MAC Address")
    plt.xlabel("MAC Address")
    plt.ylabel("Sent Packets")
    plt.tight_layout()
    plt.savefig("mac_sent_packets.png")
    plt.show()

    plt.figure(figsize=(12, 6))
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
    plt.plot(seconds_sorted, rx_counts, marker='o')
    plt.title("Packets To Destination Per Second (PLC-src → MD-dst)")
    plt.xlabel("Elapsed Time (seconds)")
    plt.ylabel("Received Packets")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("src_dst_packets_per_second.png")
    plt.show()

    if tracked_rx_per_second:
        sec_sorted = sorted(tracked_rx_per_second.keys())
        tracked_counts = [tracked_rx_per_second[s] for s in sec_sorted]
        label = track_ip if track_ip else track_mac
        plt.figure(figsize=(10, 5))
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
    seq_buffer = deque(maxlen=_LSTM_SEQ_LEN if _LSTM_MODEL is not None else 1)
    #pred_next_scaled = None
    #seq_buffer = deque(maxlen=_LSTM_SEQ_LEN)
    pred_next_scaled = None   # holds prediction for the next observation
    
    if not all_secs:
        print("⚠ No per-second buckets to send (no traffic matched your filters).")
    else:
        window_seconds = int(math.ceil(stop_time - start_time))
        base_time = int(start_time)

        # CSV dataset (optional; currently writes unlabeled rows)
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
                to_dst_pkts = int(fwd_per_second.get(sec, 0))
                to_dst_bytes = int(fwd_bytes_per_second.get(sec, 0))
                from_dst_pkts = int(rev_per_second.get(sec, 0))
                from_dst_bytes = int(rev_bytes_per_second.get(sec, 0))

                if wire_iat_count_persec.get(sec, 0) > 0:
                    avg_iat_ms_sec = wire_iat_sum_ms_persec[sec] / wire_iat_count_persec[sec]
                else:
                    avg_iat_ms_sec = 0.0

                legacy_rx_pkts = int(fwd_per_second.get(sec, rx_per_second.get(sec, 0)))
                legacy_rx_bytes = int(fwd_bytes_per_second.get(sec, rx_bytes_per_second.get(sec, 0)))
                avg_pkt_size_to = (to_dst_bytes / max(to_dst_pkts, 1))

                # optional dataset logging (label left empty)
                writer_feat.writerow({
                    "time": base_time + sec,
                    "rx_packets_per_sec": legacy_rx_pkts,
                    "rx_bytes_per_sec": legacy_rx_bytes,
                    "avg_pkt_size_bytes_to_dst": avg_pkt_size_to,
                    "avg_wire_iat_ms": avg_iat_ms_sec,
                    "label": ""
                })

                # ----- LSTM anomaly scoring -----
                lstm_anomaly = 0
                lstm_score = None
                lstm_threshold = _LSTM_THRESHOLD
                lstm_forecast_rx_pps = None

                if _LSTM_MODEL is not None:
                    feat_vec = np.array([[
                        legacy_rx_pkts,
                        legacy_rx_bytes,
                        avg_pkt_size_to,
                        avg_iat_ms_sec
                    ]], dtype="float32")

                    feat_scaled = _LSTM_SCALER.transform(feat_vec)[0]
                   
                    # 1) If we already predicted this step last time, score it NOW
                    if pred_next_scaled is not None:
                        mse = float(np.mean((pred_next_scaled - feat_scaled) ** 2))
                        lstm_score = mse
                        if mse > _LSTM_THRESHOLD:
                            lstm_anomaly = 1

                    # 2) Update buffer with current observation
                    seq_buffer.append(feat_scaled)

                    # 3) Predict next step from the last SEQ_LEN observations
                    if len(seq_buffer) == _LSTM_SEQ_LEN:
                        seq_arr = np.array(seq_buffer, dtype="float32").reshape(1, _LSTM_SEQ_LEN, len(_LSTM_FEATURES))
                        pred_next_scaled = _LSTM_MODEL.predict(seq_arr, verbose=0)[0]

                        # forecast (UNSCALED) for next step
                        pred_next_unscaled = _LSTM_SCALER.inverse_transform(pred_next_scaled.reshape(1, -1))[0]
                        lstm_forecast_rx_pps = float(pred_next_unscaled[0])
                    else:
                        pred_next_scaled = None
                    '''
                    seq_buffer.append(feat_scaled)

                    if len(seq_buffer) == _LSTM_SEQ_LEN:
                        seq_arr = np.array(seq_buffer, dtype="float32").reshape(
                            1, _LSTM_SEQ_LEN, len(_LSTM_FEATURES)
                        )
                        yhat_scaled = _LSTM_MODEL.predict(seq_arr, verbose=0)[0]

                        mse = float(np.mean((yhat_scaled - feat_scaled) ** 2))
                        lstm_score = mse
                        if mse > _LSTM_THRESHOLD:
                            lstm_anomaly = 1

                        yhat_unscaled = _LSTM_SCALER.inverse_transform(
                            yhat_scaled.reshape(1, -1)
                        )[0]
                        lstm_forecast_rx_pps = float(yhat_unscaled[0])
'''
                # ---- main per-second event to Splunk ----
                events.append({
                    "time": base_time + sec,
                    "host": HOSTNAME,
                    "source": SPLUNK_SOURCE,
                    "sourcetype": SPLUNK_SOURCETYPE,
                    "index": SPLUNK_INDEX,
                    "event": {
                        "iface": iface,
                        #"dst_mac": (dst_mac or track_mac or "").lower(),
                        #"to_dst_packets_per_sec": to_dst_pkts,
                        #"to_dst_bytes_per_sec": to_dst_bytes,
                        #"from_dst_packets_per_sec": from_dst_pkts,
                        #"from_dst_bytes_per_sec": from_dst_bytes,
                        "rx_packets_per_sec": legacy_rx_pkts,
                        "rx_bytes_per_sec": legacy_rx_bytes,
                        "avg_wire_iat_ms": avg_iat_ms_sec,
                        #"wire_iat_samples_in_sec": int(wire_iat_count_persec.get(sec, 0)),
                        #"tracked_rx_packets_per_sec": int(tracked_rx_per_second.get(sec, 0)),
                        #"tracked_rx_bytes_per_sec": int(tracked_rx_bytes_per_second.get(sec, 0)),
                        #"avg_pkt_size_bytes_from_dst": (from_dst_bytes / max(from_dst_pkts, 1)),
                        "avg_pkt_size_bytes_to_dst": avg_pkt_size_to,
                        "hostname": HOSTNAME,
                        "sniffer_version": "1.2.0",
                        "lstm_anomaly": int(lstm_anomaly),
                        "lstm_score": lstm_score,
                        "lstm_threshold": lstm_threshold,
                        "lstm_forecast_rx_pps": lstm_forecast_rx_pps,
                    }
                })
                '''
                # ---- separate alert event if anomaly ----
                if lstm_anomaly == 1:
                    events.append({
                        "time": base_time + sec,
                        "host": HOSTNAME,
                        "source": "packet_lstm",
                        "sourcetype": "alert:packet_anomaly_lstm",
                        "index": SPLUNK_INDEX,
                        "event": {
                            "alert": "lstm_anomaly_detected",
                            "score": lstm_score,
                            "threshold": lstm_threshold,
                            "forecast_rx_packets_per_sec": lstm_forecast_rx_pps,
                            "rx_packets_per_sec": legacy_rx_pkts,
                            "rx_bytes_per_sec": legacy_rx_bytes,
                            "avg_pkt_size_bytes_to_dst": avg_pkt_size_to,
                            "avg_wire_iat_ms": avg_iat_ms_sec,
                            "hostname": HOSTNAME,
                            "iface": iface,
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
    packet_counter(
        src_mac='30:b8:51:03:21:a2',
        dst_mac='00:0d:1e:1c:64:32',
        iface='Ethernet',
        timeout=300,
        replay_pcap=r"D:\PhD L'Aquila\Selmec\30 attack - move 300\capture1.pcap"
        # replay_pcap=r"D:\PhD L'Aquila\Selmec\20 attack 50 sec\attack 50 wireshark.pcap"
    )
