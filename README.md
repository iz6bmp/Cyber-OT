# Cyber-OT
# SELMEC - CyberOT: OT Cybersecurity Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange.svg)](https://www.tensorflow.org/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.x-green.svg)](https://scikit-learn.org/)

This repository contains the implementation of attack simulation scenarios and AI-based anomaly detection systems developed within the **CyberOT** research project, focusing on cybersecurity for **Operational Technology (OT)** environments and industrial automation systems using **PROFINET** protocols.

## Acknowledgments

This work has been funded by **Abruzzo Region** through **POR FESR Abruzzo 2021/2027 Programme** – Measure 1.1.1.1  
**CUP: C79J24000060007**

## Overview

The project addresses cybersecurity challenges in industrial networks by providing:

1. **Attack Simulation Toolkit**: Seven distinct attack scenarios targeting PLC-to-Motor Driver PROFINET communications
2. **AI-Based Detection Systems**: Two complementary approaches for real-time anomaly detection
   - **Supervised Detection**: Random Forest forecaster using labeled datasets
   - **Unsupervised Detection**: LSTM-based forecaster for environments without labeled attack data
3. **SIEM Integration**: Full integration with Splunk for real-time monitoring and alerting

## Architecture

![Attack Scenario Taxonomy](0-%20Attack-scenario%20taxonomy.png)

The testbed consists of:
- **PLC (Programmable Logic Controller)**: Industrial controller managing the automation process
- **Motor Driver**: Actuator receiving commands from the PLC via PROFINET
- **Proposal Agent**: Network monitoring agent capturing traffic and performing detection
- **Raspberry Pi Attacker**: Adversarial node injecting malicious traffic
- **Splunk SIEM**: Centralized security event management platform

## Attack Scenarios

| # | Scenario | Description |
|---|----------|-------------|
| 1 | Low-burst random packet spoofing | Injection of spoofed packets at low rate to avoid detection |
| 2 | High-volume random flooding | DoS attack flooding the network with >1,000 packets/burst |
| 3 | Replay of captured PLC–Motor Driver packets | Replaying legitimate traffic to disrupt synchronization |
| 4 | Replay with ProviderState = 0 ("Stop") | Manipulated replay forcing motor driver into stop condition |
| 5 | Replay with increasing CycleCounter | Counter manipulation causing sequence number anomalies |
| 6 | Replay with decreasing CycleCounter | Reverse counter manipulation for protocol confusion |
| 7 | Injection of captured normal traffic segment | Extended injection (250 sec) of previously captured traffic |

## Detection Modules

### Supervised Detection (Random Forest)

![Random Forest Detection Architecture](80-%20Abnormal%20Detection%20Using%20Labeled%20Data%20(Random%20Forest)%20offline%20training%20and%20online%20detection.png)

**Offline Training** (`81- Labeled - Offline Training Random Forest Forecaster.py`):
- Trains on labeled dataset with normal/attack annotations
- Builds time-series windows (SEQ_LEN = 20 seconds)
- Sets anomaly threshold at 99th percentile of validation MSE

**Online Detection** (`82- Labeled - Online Detection Random Forest Forecaster.py`):
- Real-time packet capture using Scapy
- Per-second feature aggregation (pps, bps, psb, ipt)
- Forecast-error scoring with threshold-based alerting
- Direct integration with Splunk via HTTP Event Collector (HEC)

### Unsupervised Detection (LSTM)

![LSTM Detection Architecture](90-%20Abnormal%20Detection%20Using%20Unlabeled%20Data%20(LSTM)%20offline%20training%20and%20online%20detection.png)

**Offline Training** (`91- Unlabeled - Offline Training LSTM Forecaster.py`):
- Trains exclusively on normal traffic (no labels required)
- LSTM architecture for sequential pattern learning
- Automatic threshold calibration from validation errors

**Online Detection** (`92- Unlabeled - Online Detection LSTM Forecaster.py`):
- Same real-time capture and feature extraction pipeline
- LSTM-based next-step forecasting
- Anomaly flagging when prediction error exceeds threshold

## Features Extracted

| Feature | Description |
|---------|-------------|
| `rx_packets_per_sec` (pps) | Received packets per second |
| `rx_bytes_per_sec` (bps) | Received bytes per second |
| `avg_pkt_size_bytes_to_dst` (psb) | Average packet size in bytes |
| `avg_wire_iat_ms` (ipt) | Average inter-arrival time in milliseconds |

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/SELMEC.git
cd SELMEC

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install numpy pandas scikit-learn tensorflow scapy joblib requests
```

## Usage

### Running Attack Simulations

```bash
# Requires root privileges for raw packet injection
sudo python "1- Low-burst random packet spoofing.py"
```

**Note**: Modify `IFACE`, `SRC_MAC`, and `DST_MAC_TEST` variables to match your network configuration.

### Training Detection Models

```bash
# Supervised (requires labeled CSV with 'label' column)
python "81- Labeled - Offline Training Random Forest Forecaster.py"

# Unsupervised (requires CSV with normal traffic only)
python "91- Unlabeled - Offline Training LSTM Forecaster.py"
```

### Running Online Detection

```bash
# Configure Splunk HEC settings in the script, then:
sudo python "82- Labeled - Online Detection Random Forest Forecaster.py"
# or
sudo python "92-  Unlabeled - Online Detection LSTM Forecaster.py"
```

## Requirements

- Python 3.8+
- NumPy
- Pandas
- scikit-learn
- TensorFlow/Keras
- Scapy
- joblib
- Splunk Enterprise (for SIEM integration)

## Related Publication

This work is associated with the following peer-reviewed publication:

> **Enhancing IIoT Security: BERT-Driven Intrusion Detection with MLP in Industrial Networks**  
> Z. Ali, A. Marotta, W. Tiberti, O. Odoardi, D. Cassioli, P. Di Marco  
> *IEEE Global Communications Conference (GLOBECOM) 2024*  
> 
> 📄 [IEEE Xplore](https://ieeexplore.ieee.org/document/11270748) | [Google Scholar](https://scholar.google.com/citations?view_op=view_citation&hl=it&user=9jTKjTMAAAAJ&sortby=pubdate&citation_for_view=9jTKjTMAAAAJ:l7t_Zn2s7bgC)

## Partners

- **SELMEC S.r.l.** - Industrial automation partner
- **University of L'Aquila (DISIM)** - Scientific supervision and AI/ML research

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.

## Contact

For questions or collaboration inquiries, please open an issue or contact the project maintainers.

---

*Part of the CyberOT - OT Cybersecurity Framework research initiative*

