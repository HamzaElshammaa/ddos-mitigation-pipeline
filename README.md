<div align="center">

# Real-Time DDoS Detection & Graduated Mitigation Pipeline 🛡️🌐

### **4-Stage Statistical Traffic Profiling, Composite Z-Score Anomaly Detection & Firewall Mitigation**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Live_Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![CICIDS Dataset](https://img.shields.io/badge/Dataset-CICIDS_DDoS-00599C?style=for-the-badge)](#)

*An end-to-end network security pipeline that ingests PCAP/CSV network flows, models statistical baselines from benign traffic, detects volumetric and protocol DDoS anomalies via composite Z-scores, enforces graduated Token-Bucket / `iptables` mitigation, and visualizes telemetry on a live Streamlit dashboard.*

</div>

---

## 🏗️ 4-Stage Pipeline Architecture

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 1: Statistical Baseline Profiling (`src/baseline.py`)             │
│  • Ingests benign traffic windows from CICIDS flow records or PCAPs     │
│  • Computes per-metric μ, σ, percentiles (P95/P99), and protocol ratios │
└────────────────────────────────────┬────────────────────────────────────┘
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 2: Composite Z-Score Anomaly Detection (`src/detection.py`)       │
│  • Evaluates sliding time windows against baseline distributions        │
│  • Scores Packet Rate, Byte Volume, SYN Ratio, Source IP Entropy        │
│  • Classifies severity into LOW / MEDIUM / HIGH / CRITICAL alerts       │
└────────────────────────────────────┬────────────────────────────────────┘
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 3: Graduated Firewall Mitigation (`src/mitigation.py`)            │
│  • TokenBucket per-IP rate limiting (LOW: 500/s, MED: 100/s, HIGH: 10/s)│
│  • Automatic blocklist expiration, dry-run simulation & iptables rules  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 4: Interactive Telemetry & Alerting (`src/dashboard.py`, `alerts`)│
│  • Real-time Streamlit dashboard: Z-score timelines, top talkers & logs │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Repository Structure

```text
├── src/
│   ├── baseline.py         # Benign traffic statistical profiler (CSV & PCAP modes)
│   ├── detection.py        # Sliding-window composite Z-score anomaly detector
│   ├── mitigation.py       # Token-bucket rate limiter, allowlist/blocklist & iptables engine
│   ├── dashboard.py        # Interactive Streamlit visualization dashboard
│   └── alerts.py           # Structured alert dispatcher & audit logger
├── tests/                  # Unit tests for baseline, detection, and mitigation stages
├── Dockerfile              # Container image definition with network tools
├── docker-compose.yml      # Multi-service orchestration
└── requirements.txt        # Python dependencies
```

---

## 🚀 Getting Started

### 1. Local Setup
```bash
python -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run the 4-Stage Pipeline
Place the CICIDS dataset (`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`) in `./data/`:
```bash
# Step 1: Build statistical baseline from benign traffic
python src/baseline.py csv --csv data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --output baseline_outputs

# Step 2: Run anomaly detection across traffic windows
python src/detection.py --csv data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --baseline baseline_outputs/baseline_stats.json

# Step 3: Launch the interactive Streamlit monitoring dashboard
streamlit run src/dashboard.py
```

### 3. Run via Docker Compose
```bash
docker compose up --build
```
