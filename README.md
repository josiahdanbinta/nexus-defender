# 🛡️ Nexus Defender — Security Analyzer

Nexus Defender is a Python-based cybersecurity lab framework that integrates **attack simulation** and a **real-time intrusion detection system (IDS)** for analyzing network behavior in a controlled environment.

It demonstrates how malicious network traffic patterns can be generated and detected using behavioral anomaly detection techniques.

---

## 🔥 Key Features

### 🟥 Attack Simulation Module
- SYN Flood simulation
- ICMP Flood generation
- UDP traffic flood
- ARP spoofing simulation
- Port scanning behavior
- DNS flood simulation
- Mixed attack scenarios

### 🟦 Security Analyzer (IDS Engine)
- Real-time packet sniffing
- DoS detection (packets-per-second analysis)
- Port scan detection (unique port tracking)
- ICMP flood detection
- Sensitive port monitoring (SSH, Telnet, SMB)
- Severity classification (Critical / Warning / Normal)

---

## 🧠 Detection Approach

- Sliding time-window analysis using deque
- Per-IP behavioral tracking
- Stateful packet inspection using Scapy
- Rule-based anomaly detection system

---

## ⚙️ Tech Stack

- Python 🐍
- Scapy 📡
- Tkinter 🖥️
- Networking (TCP/IP, UDP, ICMP, ARP)

---

## 📊 System Overview

- Attack Simulator generates controlled malicious traffic patterns
- IDS Dashboard detects anomalies in real time
- PCAP export enables forensic analysis using Wireshark

---

## ⚠️ Disclaimer

This project is strictly for **educational and cybersecurity research purposes only**.  
It must be used in controlled lab environments only.

---

## 🚀 How to Run

### Install dependencies
```bash
pip install scapy
