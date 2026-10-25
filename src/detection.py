"""
hybrid_detection.py
===================

Hybrid DDoS Detection & Attack Classification

Project requirement coverage:
  ✓ Compare monitoring windows against BENIGN baseline
  ✓ Flag deviations from baseline mean/std/p99
  ✓ Sudden traffic spikes
  ✓ Protocol distribution shifts
  ✓ Source IP concentration  (actual top IP carried through)
  ✓ Port concentration       (actual top port carried through)
  ✓ Composite anomaly score  (continuous, per window)
  ✓ Rolling-window / window-based monitoring
  ✓ Incremental aggregation  (chunked CSV + streaming PCAP)
  ✓ DDoS attack classification
  ✓ Mitigation recommendations with real IP/port substitution
  ✓ De-duplicated alerts     (consecutive same-type windows collapsed)
  ✓ Continuous-attack grouping (one vs. multiple separate attacks)
  ✓ Detection justification  (signal, observed value, threshold, timestamp)
  ✓ Dashboard-ready CSV + JSON outputs

Usage
-----
1) Pre-aggregated windows CSV:
   python hybrid_detection.py windows \\
       --windows baseline_outputs/all_monitoring_windows.csv \\
       --baseline baseline_outputs/baseline_metrics.json \\
       --output detection_outputs

2) Rolling windows CSV:
   python hybrid_detection.py windows \\
       --windows baseline_outputs/rolling_windows_all.csv \\
       --baseline baseline_outputs/baseline_metrics.json \\
       --output detection_outputs_rolling

3) Raw CICIDS-format CSV:
   python hybrid_detection.py csv \\
       --csv data/combined_attacks.csv \\
       --baseline baseline_outputs/baseline_metrics.json \\
       --output detection_outputs \\
       --chunksize 50000

4) Raw PCAP file:
   python hybrid_detection.py pcap \\
       --pcap data/capture.pcap \\
       --baseline baseline_outputs/baseline_metrics.json \\
       --output detection_outputs \\
       --window-size 1s
"""

import argparse
import json
import math
import os
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURABLE THRESHOLDS
# ══════════════════════════════════════════════════════════════════════════════

COMPOSITE_THRESHOLD = 2.5       # Main fixed decision threshold
Z_THRESHOLD = 3.0               # Individual signal trigger threshold
P99_SPIKE_MULTIPLIER = 1.0      # Multiplier on baseline p99 for spike detection

ADAPTIVE_ATTACK_PERCENTILE = 85
ADAPTIVE_SUSPICIOUS_PERCENTILE = 50

IP_DOMINANCE_THRESHOLD   = 0.30
PORT_SPIKE_THRESHOLD     = 0.50
UDP_DOMINANCE_THRESHOLD  = 0.90
TCP_DOMINANCE_THRESHOLD  = 0.95
ASYMMETRY_THRESHOLD      = 0.85

# Gap in seconds between windows that separates two distinct attacks
ATTACK_GAP_SECONDS = 5


# ══════════════════════════════════════════════════════════════════════════════
# SIGNAL WEIGHTS FOR COMPOSITE SCORE
# ══════════════════════════════════════════════════════════════════════════════

SIGNAL_WEIGHTS = {
    "avg_flow_bytes_per_sec":       0.18,
    "total_flow_bytes_per_sec":     0.12,
    "avg_flow_packets_per_sec":     0.14,
    "total_flow_packets_per_sec":   0.05,
    "udp_flow_count":               0.06,
    "tcp_flow_count":               0.04,
    "udp_ratio":                    0.06,
    "tcp_ratio":                    0.04,
    "proto_entropy_inverse":        0.04,
    "total_syn_flags":              0.04,
    "total_ack_flags":              0.04,
    "top_source_ip_ratio":          0.08,
    "top_destination_ip_ratio":     0.04,
    "top_destination_port_ratio":   0.05,
    "ip_entropy_inverse":           0.04,
    "port_entropy_inverse":         0.04,
}


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK CLASSIFICATION RULES
# ══════════════════════════════════════════════════════════════════════════════

ATTACK_RULES = {
    "Protocol_SYN": {
        "avg_flow_packets_per_sec": ("gt", 200_000),
        "tcp_flow_count":           ("gt", 0),
        "avg_flow_bytes_per_sec":   ("lt", 500_000),
    },
    "Application_UDP_Lag": {
        "avg_flow_bytes_per_sec":   ("gt", 50_000_000),
        "udp_flow_count":           ("gt", 0),
        "avg_flow_packets_per_sec": ("gt", 500_000),
        "total_bwd_packets":        ("lt", 10),
    },
    "Volumetric_UDP": {
        "avg_flow_bytes_per_sec":   ("gt", 50_000_000),
        "udp_flow_count":           ("gt", 0),
    },
}

RULE_PRIORITY = ["Protocol_SYN", "Application_UDP_Lag", "Volumetric_UDP"]


# ══════════════════════════════════════════════════════════════════════════════
# MITIGATION RECOMMENDATIONS
# ══════════════════════════════════════════════════════════════════════════════

MITIGATION_RECOMMENDATIONS = {
    "Volumetric_UDP": {
        "rate_limit": "Rate-limit UDP to 10 Mbps per source IP.",
        "firewall": (
            "iptables -A INPUT -p udp -s {top_source_ip} -m hashlimit "
            "--hashlimit-above 10mb/s --hashlimit-mode srcip "
            "--hashlimit-name udp_flood -j DROP"
        ),
        "safeguard": "Start with lenient UDP rate limiting, whitelist critical IPs, then gradually tighten.",
        "description": "Volumetric UDP flood: bandwidth saturation caused by extreme UDP traffic volume.",
    },
    "Protocol_SYN": {
        "rate_limit": "Enable SYN cookies and limit new TCP connections to 100/s per source IP.",
        "firewall": (
            "iptables -A INPUT -p tcp --syn -s {top_source_ip} -m hashlimit "
            "--hashlimit-above 100/s --hashlimit-mode srcip "
            "--hashlimit-name syn_flood -j DROP"
        ),
        "safeguard": "Apply SYN-specific limits first instead of blocking all TCP traffic.",
        "description": "SYN/protocol flood: abnormal TCP packet pattern attempting to exhaust connection state.",
    },
    "Application_UDP_Lag": {
        "rate_limit": "Rate-limit UDP on the targeted service port to 5 Mbps per source IP.",
        "firewall": (
            "iptables -A INPUT -p udp --dport {top_destination_port} -s {top_source_ip} "
            "-m hashlimit --hashlimit-above 5mb/s --hashlimit-mode srcip "
            "--hashlimit-name udp_lag -j DROP"
        ),
        "safeguard": "Apply service-port limiting, whitelist legitimate service clients, then escalate.",
        "description": "Application-layer UDP-lag flood: high request rate aimed at a specific UDP service.",
    },
    "Unknown_DDoS": {
        "rate_limit": "Apply conservative generic ingress rate limiting.",
        "firewall": (
            "iptables -A INPUT -s {top_source_ip} -m hashlimit "
            "--hashlimit-above 50mb/s --hashlimit-name ddos_generic -j DROP"
        ),
        "safeguard": "Use temporary lenient limits and monitor false positives before blocking.",
        "description": "Anomalous traffic that does not match a known attack signature.",
    },
    "BENIGN": {
        "rate_limit": "No mitigation required.",
        "firewall": "",
        "safeguard": "Continue monitoring.",
        "description": "Traffic matches baseline behavior.",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# CARRY COLUMNS — preserved through the whole pipeline
# ══════════════════════════════════════════════════════════════════════════════

CARRY_COLS = [
    "time_window",
    "flow_count",

    "tcp_flow_count",
    "udp_flow_count",
    "icmp_flow_count",

    "avg_flow_bytes_per_sec",
    "total_flow_bytes_per_sec",
    "max_flow_bytes_per_sec",

    "avg_flow_packets_per_sec",
    "total_flow_packets_per_sec",
    "max_flow_packets_per_sec",

    "total_syn_flags",
    "total_ack_flags",
    "total_fin_flags",
    "total_rst_flags",
    "total_psh_flags",
    "total_urg_flags",

    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",

    "unique_source_ips",
    "unique_destination_ips",
    "unique_destination_ports",

    # ratio features
    "top_source_ip_ratio",
    "top_destination_ip_ratio",
    "top_destination_port_ratio",

    # ── NEW: actual top IP/port strings ──
    "top_source_ip",
    "top_destination_ip",
    "top_destination_port",

    "avg_packet_length",
    "avg_flow_duration",

    "udp_ratio",
    "tcp_ratio",
    "icmp_ratio",
    "proto_entropy",
    "proto_entropy_inverse",

    "source_ip_entropy",
    "ip_entropy_inverse",
    "destination_port_entropy",
    "port_entropy_inverse",

    "fwd_bwd_asymmetry",

    "ip_dominance_flag",
    "port_spike_flag",
    "protocol_shift",
    "traffic_asymmetry",
]


# ══════════════════════════════════════════════════════════════════════════════
# GENERIC HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def load_baseline(path: str) -> dict:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Baseline not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        baseline = json.load(f)
    if "metrics" not in baseline:
        raise ValueError(
            "Baseline JSON must contain a 'metrics' key. "
            "Expected baseline_outputs/baseline_metrics.json format."
        )
    return baseline


def load_windows(path: str) -> pd.DataFrame:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Windows CSV not found: {path}")
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    if "time_window" in df.columns:
        df["time_window"] = pd.to_datetime(df["time_window"], errors="coerce")
    return df


def safe_numeric(df: pd.DataFrame, col: str, default: float = 0.0) -> pd.Series:
    if col not in df.columns:
        return pd.Series(default, index=df.index)
    return pd.to_numeric(df[col], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(default)


def safe_col_value(row: pd.Series, col: str, default: float = 0.0) -> float:
    try:
        value = row.get(col, default)
        if pd.isna(value):
            return default
        return float(value)
    except Exception:
        return default


def shannon_entropy_from_counts(counts: pd.Series) -> float:
    if counts is None or len(counts) == 0:
        return 0.0
    arr = np.array(counts, dtype=float)
    total = arr.sum()
    if total <= 0:
        return 0.0
    probs = arr / total
    probs = probs[probs > 0]
    return float(-(probs * np.log2(probs)).sum())


def concentration_ratio(series: pd.Series, top_n: int = 1) -> float:
    if series is None or len(series) == 0:
        return 0.0
    vc = series.dropna().value_counts()
    if vc.empty:
        return 0.0
    return float(vc.iloc[:top_n].sum() / len(series.dropna()))


def _z_score(value: float, stat: dict) -> float:
    """One-sided positive z-score. Lower-than-baseline is not treated as DDoS."""
    if not stat:
        return 0.0
    mean    = float(stat.get("mean", 0.0))
    std     = float(stat.get("std",  0.0))
    max_val = float(stat.get("max",  mean))
    if std == 0:
        return 3.0 if value > max_val else 0.0
    return max((value - mean) / std, 0.0)


def _two_sided_z_score(value: float, stat: dict) -> float:
    """Two-sided z-score for distribution metrics like entropy/ratios."""
    if not stat:
        return 0.0
    mean = float(stat.get("mean", 0.0))
    std  = float(stat.get("std",  0.0))
    if std == 0:
        return 3.0 if value != mean else 0.0
    return abs((value - mean) / std)


def _check_rule(row: pd.Series, rule: dict) -> bool:
    ops = {
        "gt":  lambda a, b: a > b,
        "lt":  lambda a, b: a < b,
        "gte": lambda a, b: a >= b,
        "lte": lambda a, b: a <= b,
        "eq":  lambda a, b: a == b,
    }
    for feature, (op, threshold) in rule.items():
        if feature not in row.index:
            return False
        if not ops[op](safe_col_value(row, feature, 0.0), threshold):
            return False
    return True


def normalize_label(value: str) -> str:
    if not isinstance(value, str):
        return str(value)
    mapping = {
        "drdos_udp": "DrDoS_UDP", "drdos-udp": "DrDoS_UDP", "drdos udp": "DrDoS_UDP",
        "syn": "Syn", "udp-lag": "UDPLag", "udp lag": "UDPLag",
        "udplag": "UDPLag", "benign": "BENIGN",
    }
    return mapping.get(value.strip().lower(), value)


# ══════════════════════════════════════════════════════════════════════════════
# ADAPTIVE THRESHOLD REPORTING
# ══════════════════════════════════════════════════════════════════════════════

def adaptive_threshold_report(scores: pd.Series) -> dict:
    clean = pd.to_numeric(scores, errors="coerce").dropna()
    if clean.empty:
        return {"adaptive_suspicious_threshold": None, "adaptive_attack_threshold": None, "scores_seen": 0}
    return {
        "adaptive_suspicious_threshold": round(float(np.percentile(clean, ADAPTIVE_SUSPICIOUS_PERCENTILE)), 4),
        "adaptive_attack_threshold":     round(float(np.percentile(clean, ADAPTIVE_ATTACK_PERCENTILE)),     4),
        "scores_seen": int(len(clean)),
        "note": (
            "Adaptive thresholds are reported for dashboard tuning only. "
            "The detector uses the fixed composite threshold by default."
        ),
    }


# ══════════════════════════════════════════════════════════════════════════════
# DERIVED FEATURES FROM WINDOW CSV
# ══════════════════════════════════════════════════════════════════════════════

def _add_derived_features(windows: pd.DataFrame) -> pd.DataFrame:
    windows = windows.copy()

    for col in [
        "flow_count", "tcp_flow_count", "udp_flow_count", "icmp_flow_count",
        "total_fwd_packets", "total_bwd_packets",
        "top_source_ip_ratio", "top_destination_port_ratio",
    ]:
        if col not in windows.columns:
            windows[col] = 0

    # Ensure IP/port string columns exist (may not be present in pre-aggregated CSVs)
    for col in ["top_source_ip", "top_destination_ip"]:
        if col not in windows.columns:
            windows[col] = ""
    if "top_destination_port" not in windows.columns:
        windows["top_destination_port"] = 0

    total_flows = safe_numeric(windows, "flow_count").replace(0, np.nan)

    windows["udp_ratio"]  = (safe_numeric(windows, "udp_flow_count")  / total_flows).fillna(0)
    windows["tcp_ratio"]  = (safe_numeric(windows, "tcp_flow_count")  / total_flows).fillna(0)
    windows["icmp_ratio"] = (safe_numeric(windows, "icmp_flow_count") / total_flows).fillna(0)

    proto_entropy = []
    for _, r in windows.iterrows():
        counts = pd.Series([
            safe_col_value(r, "tcp_flow_count"),
            safe_col_value(r, "udp_flow_count"),
            safe_col_value(r, "icmp_flow_count"),
        ])
        proto_entropy.append(shannon_entropy_from_counts(counts))

    windows["proto_entropy"] = proto_entropy

    max_proto_entropy = math.log2(3)
    windows["proto_entropy_inverse"] = (max_proto_entropy - windows["proto_entropy"]).clip(lower=0)

    if "source_ip_entropy" not in windows.columns:
        windows["source_ip_entropy"] = np.nan
    if "destination_port_entropy" not in windows.columns:
        windows["destination_port_entropy"] = np.nan

    windows["ip_entropy_inverse"]   = safe_numeric(windows, "top_source_ip_ratio").fillna(0)
    windows["port_entropy_inverse"] = safe_numeric(windows, "top_destination_port_ratio").fillna(0)

    total_packets = (
        safe_numeric(windows, "total_fwd_packets") +
        safe_numeric(windows, "total_bwd_packets")
    ).replace(0, np.nan)

    windows["fwd_bwd_asymmetry"] = (
        (safe_numeric(windows, "total_fwd_packets") - safe_numeric(windows, "total_bwd_packets")).abs()
        / total_packets
    ).fillna(0)

    windows["protocol_shift"] = (
        (windows["udp_ratio"] > UDP_DOMINANCE_THRESHOLD)
        | (
            (windows["tcp_ratio"] > TCP_DOMINANCE_THRESHOLD)
            & (safe_numeric(windows, "avg_flow_bytes_per_sec") < 100_000)
        )
    )

    windows["traffic_asymmetry"] = windows["fwd_bwd_asymmetry"] > ASYMMETRY_THRESHOLD
    windows["ip_dominance_flag"] = safe_numeric(windows, "top_source_ip_ratio")         >= IP_DOMINANCE_THRESHOLD
    windows["port_spike_flag"]   = safe_numeric(windows, "top_destination_port_ratio")  >= PORT_SPIKE_THRESHOLD

    return windows


# ══════════════════════════════════════════════════════════════════════════════
# CORE DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def compute_signal_scores(windows: pd.DataFrame, baseline: dict) -> pd.DataFrame:
    """
    Per window:
      1. z-score each signal vs benign baseline
      2. add entropy/concentration/protocol bonuses
      3. compute weighted composite score
      4. flag if composite >= threshold
      5. build triggered_signals list with observed value + threshold for B.3
    """
    metrics = baseline.get("metrics", {})
    results = []

    for _, row in windows.iterrows():
        record = {col: row[col] for col in CARRY_COLS if col in row.index}

        composite = 0.0
        triggered_signals: List[str] = []
        signal_details: List[str] = []    # human-readable justifications (B.3)

        # ── weighted z-score signals ─────────────────────────────────────────
        for signal, weight in SIGNAL_WEIGHTS.items():
            val  = safe_col_value(row, signal, 0.0)
            stat = metrics.get(signal)

            if stat is None:
                continue

            if signal in {
                "udp_ratio", "tcp_ratio", "proto_entropy_inverse",
                "ip_entropy_inverse", "port_entropy_inverse",
            }:
                z = _two_sided_z_score(val, stat)
            else:
                z = _z_score(val, stat)

            record[f"z_{signal}"] = round(z, 4)
            composite += z * weight

            if z >= Z_THRESHOLD:
                triggered_signals.append(signal)
                signal_details.append(
                    f"{signal}=observed:{val:.4g},z:{z:.2f},threshold:{Z_THRESHOLD}"
                )

        # ── baseline p99 spike checks ─────────────────────────────────────────
        for metric_name in [
            "avg_flow_bytes_per_sec",
            "avg_flow_packets_per_sec",
            "total_flow_bytes_per_sec",
            "total_flow_packets_per_sec",
        ]:
            stat = metrics.get(metric_name)
            if not stat:
                continue
            p99 = float(stat.get("p99", stat.get("max", float("inf"))))
            val = safe_col_value(row, metric_name, 0.0)
            if val > p99 * P99_SPIKE_MULTIPLIER:
                label = f"{metric_name}_above_p99"
                triggered_signals.append(label)
                signal_details.append(
                    f"{label}=observed:{val:.4g},p99_baseline:{p99:.4g}"
                )
                composite += 0.15

        # ── hybrid binary signal bonuses ──────────────────────────────────────
        if bool(row.get("protocol_shift", False)):
            composite += 0.30
            triggered_signals.append("protocol_distribution_shift")
            signal_details.append(
                f"protocol_distribution_shift=udp_ratio:{safe_col_value(row,'udp_ratio'):.3f},"
                f"tcp_ratio:{safe_col_value(row,'tcp_ratio'):.3f}"
            )

        if bool(row.get("traffic_asymmetry", False)):
            composite += 0.20
            triggered_signals.append("traffic_asymmetry")
            signal_details.append(
                f"traffic_asymmetry=fwd_bwd_asymmetry:{safe_col_value(row,'fwd_bwd_asymmetry'):.3f},"
                f"threshold:{ASYMMETRY_THRESHOLD}"
            )

        if bool(row.get("ip_dominance_flag", False)):
            composite += 0.25
            triggered_signals.append("source_ip_concentration")
            signal_details.append(
                f"source_ip_concentration=top_src_ip_ratio:{safe_col_value(row,'top_source_ip_ratio'):.3f},"
                f"threshold:{IP_DOMINANCE_THRESHOLD},"
                f"top_ip:{row.get('top_source_ip','?')}"
            )

        if bool(row.get("port_spike_flag", False)):
            composite += 0.25
            triggered_signals.append("destination_port_concentration")
            signal_details.append(
                f"destination_port_concentration=top_dst_port_ratio:{safe_col_value(row,'top_destination_port_ratio'):.3f},"
                f"threshold:{PORT_SPIKE_THRESHOLD},"
                f"top_port:{row.get('top_destination_port','?')}"
            )

        record["composite_score"]    = round(float(composite), 4)
        record["triggered_signals"]  = "|".join(sorted(set(triggered_signals))) if triggered_signals else ""
        record["signal_details"]     = " || ".join(signal_details) if signal_details else ""
        record["n_triggered"]        = len(set(triggered_signals))
        record["is_anomaly"]         = composite >= COMPOSITE_THRESHOLD

        if record["is_anomaly"] and composite >= COMPOSITE_THRESHOLD * 2:
            record["severity"] = "HIGH"
        elif record["is_anomaly"]:
            record["severity"] = "MEDIUM"
        elif record["n_triggered"] > 0:
            record["severity"] = "LOW"
        else:
            record["severity"] = "NORMAL"

        results.append(record)

    return pd.DataFrame(results)


def classify_attack(scored: pd.DataFrame) -> pd.DataFrame:
    """
    Rule-based attack type classification with dynamic IP/port substitution
    into firewall rules.
    """
    attack_types = []
    confidences  = []

    for _, row in scored.iterrows():
        if not bool(row.get("is_anomaly", False)):
            attack_types.append("BENIGN")
            confidences.append("high")
            continue

        matched = None
        for attack_name in RULE_PRIORITY:
            if _check_rule(row, ATTACK_RULES[attack_name]):
                matched = attack_name
                break

        if matched is None:
            udp_ratio  = safe_col_value(row, "udp_ratio",               0.0)
            tcp_ratio  = safe_col_value(row, "tcp_ratio",               0.0)
            bytes_rate = safe_col_value(row, "avg_flow_bytes_per_sec",  0.0)
            pps        = safe_col_value(row, "avg_flow_packets_per_sec",0.0)
            port_spike = bool(row.get("port_spike_flag", False))

            if tcp_ratio > 0.90 and pps > 100_000 and bytes_rate < 1_000_000:
                matched = "Protocol_SYN"
            elif udp_ratio > 0.90 and port_spike and pps > 200_000:
                matched = "Application_UDP_Lag"
            elif udp_ratio > 0.90 and bytes_rate > 10_000_000:
                matched = "Volumetric_UDP"

        attack_types.append(matched if matched else "Unknown_DDoS")
        confidences.append("high" if matched else "low")

    out = scored.copy()
    out["attack_type"] = attack_types
    out["confidence"]  = confidences

    # ── fill firewall template with actual IP/port ────────────────────────────
    def _fill_firewall(row: pd.Series) -> str:
        template = MITIGATION_RECOMMENDATIONS.get(
            row["attack_type"],
            MITIGATION_RECOMMENDATIONS["Unknown_DDoS"]
        )["firewall"]
        top_ip   = str(row.get("top_source_ip", ""))   or "UNKNOWN_IP"
        top_port = str(row.get("top_destination_port", "")) or "UNKNOWN_PORT"
        return template.format(top_source_ip=top_ip, top_destination_port=top_port)

    out["mitigation_rate_limit"] = out["attack_type"].map(
        lambda a: MITIGATION_RECOMMENDATIONS.get(a, MITIGATION_RECOMMENDATIONS["Unknown_DDoS"])["rate_limit"]
    )
    out["firewall_rule"]         = out.apply(_fill_firewall, axis=1)
    out["mitigation_safeguard"]  = out["attack_type"].map(
        lambda a: MITIGATION_RECOMMENDATIONS.get(a, MITIGATION_RECOMMENDATIONS["Unknown_DDoS"])["safeguard"]
    )
    out["attack_description"]    = out["attack_type"].map(
        lambda a: MITIGATION_RECOMMENDATIONS.get(a, MITIGATION_RECOMMENDATIONS["Unknown_DDoS"])["description"]
    )

    return out


# ══════════════════════════════════════════════════════════════════════════════
# CONTINUOUS ATTACK GROUPING  (B.4 — distinguishes separate attacks)
# ══════════════════════════════════════════════════════════════════════════════

def group_attack_events(results: pd.DataFrame, gap_seconds: int = ATTACK_GAP_SECONDS) -> pd.DataFrame:
    """
    Assign an attack_event_id to every anomalous window.
    A new event starts when:
      - the attack type changes, OR
      - the gap between consecutive anomalous windows exceeds gap_seconds.

    BENIGN windows get event_id = 0.
    """
    results = results.copy().reset_index(drop=True)
    results["attack_event_id"] = 0

    anomalous = results[results["is_anomaly"]].copy()
    if anomalous.empty:
        return results

    anomalous = anomalous.sort_values("time_window").reset_index()  # keep original index

    event_id     = 1
    prev_time    = None
    prev_type    = None

    for _, row in anomalous.iterrows():
        orig_idx = row["index"]
        curr_time = pd.Timestamp(row["time_window"])
        curr_type = row["attack_type"]

        if prev_time is not None:
            try:
                gap = (curr_time - prev_time).total_seconds()
            except Exception:
                gap = 0.0
            if curr_type != prev_type or gap > gap_seconds:
                event_id += 1

        results.at[orig_idx, "attack_event_id"] = event_id
        prev_time = curr_time
        prev_type = curr_type

    return results


# ══════════════════════════════════════════════════════════════════════════════
# DE-DUPLICATION  (B.5 — collapses same-event windows into one alert)
# ══════════════════════════════════════════════════════════════════════════════

def build_deduped_alerts(results: pd.DataFrame) -> List[dict]:
    """
    Produce one alert per attack event (attack_event_id), not one per window.
    Each alert reports:
      - event id and time span
      - number of windows it spanned
      - peak composite score
      - attack type and severity
      - triggered signals across all windows
      - actual top source IP and destination port
      - ready-to-paste firewall rule
      - full detection justification
    """
    anomalous = results[results["is_anomaly"]].copy()
    if anomalous.empty:
        return []

    alerts = []

    for event_id, group in anomalous.groupby("attack_event_id"):
        group = group.sort_values("time_window")

        peak_row    = group.loc[group["composite_score"].idxmax()]
        start_time  = group["time_window"].min()
        end_time    = group["time_window"].max()
        n_windows   = len(group)

        # Collect all unique triggered signals across the event
        all_signals: set = set()
        for sigs in group["triggered_signals"].dropna():
            if sigs:
                all_signals.update(sigs.split("|"))

        # Pick the most severe severity level seen in the event
        sev_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NORMAL": 0}
        peak_severity = max(
            group["severity"].dropna(),
            key=lambda s: sev_order.get(s, 0),
            default="UNKNOWN"
        )

        # Best top_source_ip (prefer the one from the peak window)
        top_ip   = str(peak_row.get("top_source_ip", "")) or ""
        top_port = str(peak_row.get("top_destination_port", "")) or ""

        alerts.append({
            "event_id":           int(event_id),
            "attack_type":        str(peak_row.get("attack_type", "Unknown_DDoS")),
            "severity":           peak_severity,
            "start_time":         str(start_time),
            "end_time":           str(end_time),
            "duration_windows":   n_windows,
            "peak_score":         round(float(peak_row.get("composite_score", 0.0)), 4),
            "confidence":         str(peak_row.get("confidence", "low")),
            "top_source_ip":      top_ip,
            "top_destination_port": top_port,
            "triggered_signals":  "|".join(sorted(all_signals)),
            "detection_justification": str(peak_row.get("signal_details", "")),
            "mitigation":         str(peak_row.get("mitigation_rate_limit", "")),
            "firewall_rule":      str(peak_row.get("firewall_rule", "")),
            "safeguard":          str(peak_row.get("mitigation_safeguard", "")),
            "message": (
                f"[Event {event_id}] {peak_severity} {peak_row.get('attack_type','Unknown_DDoS')} "
                f"from {start_time} to {end_time} "
                f"({n_windows} window(s), peak score {round(float(peak_row.get('composite_score',0.0)),4)}) "
                f"— top source IP: {top_ip or 'N/A'}, top dest port: {top_port or 'N/A'}"
            ),
        })

    return alerts


# ══════════════════════════════════════════════════════════════════════════════
# RAW CSV INCREMENTAL AGGREGATION
# ══════════════════════════════════════════════════════════════════════════════

def aggregate_raw_csv(csv_path: str, chunksize: int = 50_000, window_size: str = "1min") -> pd.DataFrame:
    """
    Incrementally aggregate raw CICIDS-style CSV data into time windows.
    top_source_ip, top_destination_ip, and top_destination_port are carried
    through as string/int columns for alert enrichment.
    """
    if not os.path.isfile(csv_path):
        raise FileNotFoundError(f"Raw CSV not found: {csv_path}")

    print(f"[detection] Incrementally aggregating raw CSV: {csv_path}")

    num_cols = [
        "Flow Bytes/s", "Flow Packets/s", "Flow Duration",
        "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Packet Length Mean", "SYN Flag Count", "ACK Flag Count",
        "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "URG Flag Count",
        "Source Port", "Destination Port", "Protocol",
    ]

    partial_windows: List[pd.DataFrame] = []
    total_rows = 0

    for chunk in pd.read_csv(csv_path, chunksize=chunksize, low_memory=False):
        total_rows += len(chunk)
        chunk.columns = chunk.columns.str.strip()

        if "Timestamp" not in chunk.columns:
            raise ValueError("Raw CSV must contain a 'Timestamp' column.")

        chunk["Timestamp"] = pd.to_datetime(chunk["Timestamp"], errors="coerce")
        chunk = chunk.dropna(subset=["Timestamp"])

        for col in num_cols:
            if col in chunk.columns:
                chunk[col] = (
                    pd.to_numeric(chunk[col], errors="coerce")
                    .replace([np.inf, -np.inf], np.nan).clip(lower=0).fillna(0)
                )

        for col in [
            "Protocol", "Flow Bytes/s", "Flow Packets/s", "Flow Duration",
            "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets",
            "Packet Length Mean", "SYN Flag Count", "ACK Flag Count",
            "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "URG Flag Count",
        ]:
            if col not in chunk.columns:
                chunk[col] = 0

        if "Source IP"        not in chunk.columns: chunk["Source IP"]        = "unknown"
        if "Destination IP"   not in chunk.columns: chunk["Destination IP"]   = "unknown"
        if "Destination Port" not in chunk.columns: chunk["Destination Port"] = 0

        chunk["time_window"] = chunk["Timestamp"].dt.floor(window_size)
        chunk["is_tcp"]  = (chunk["Protocol"] == 6).astype(int)
        chunk["is_udp"]  = (chunk["Protocol"] == 17).astype(int)
        chunk["is_icmp"] = (chunk["Protocol"] == 1).astype(int)

        grouped_rows = []

        for tw, g in chunk.groupby("time_window"):
            flow_count = len(g)

            protocol_counts = g["Protocol"].value_counts()
            src_counts      = g["Source IP"].value_counts()
            dst_port_counts = g["Destination Port"].value_counts()
            dst_ip_counts   = g["Destination IP"].value_counts()

            top_source_ip        = src_counts.index[0]      if not src_counts.empty      else ""
            top_destination_ip   = dst_ip_counts.index[0]   if not dst_ip_counts.empty   else ""
            top_destination_port = int(dst_port_counts.index[0]) if not dst_port_counts.empty else 0

            top_source_ip_ratio        = float(src_counts.iloc[0]      / flow_count) if flow_count else 0.0
            top_destination_ip_ratio   = float(dst_ip_counts.iloc[0]   / flow_count) if flow_count else 0.0
            top_destination_port_ratio = float(dst_port_counts.iloc[0] / flow_count) if flow_count else 0.0

            source_ip_entropy        = shannon_entropy_from_counts(src_counts)
            destination_port_entropy = shannon_entropy_from_counts(dst_port_counts)
            proto_entropy            = shannon_entropy_from_counts(protocol_counts)

            max_proto_entropy = math.log2(3)
            max_src_entropy   = math.log2(max(int(g["Source IP"].nunique()),        2))
            max_port_entropy  = math.log2(max(int(g["Destination Port"].nunique()), 2))

            grouped_rows.append({
                "time_window":  tw,
                "flow_count":   flow_count,

                "tcp_flow_count":  int(g["is_tcp"].sum()),
                "udp_flow_count":  int(g["is_udp"].sum()),
                "icmp_flow_count": int(g["is_icmp"].sum()),

                "avg_flow_bytes_per_sec":   float(g["Flow Bytes/s"].mean()),
                "total_flow_bytes_per_sec": float(g["Flow Bytes/s"].sum()),
                "max_flow_bytes_per_sec":   float(g["Flow Bytes/s"].max()),

                "avg_flow_packets_per_sec":   float(g["Flow Packets/s"].mean()),
                "total_flow_packets_per_sec": float(g["Flow Packets/s"].sum()),
                "max_flow_packets_per_sec":   float(g["Flow Packets/s"].max()),

                "avg_flow_duration": float(g["Flow Duration"].mean()),
                "avg_packet_length": float(g["Packet Length Mean"].mean()),

                "total_fwd_packets": float(g["Total Fwd Packets"].sum()),
                "total_bwd_packets": float(g["Total Backward Packets"].sum()),
                "total_fwd_bytes":   float(g["Total Length of Fwd Packets"].sum()),
                "total_bwd_bytes":   float(g["Total Length of Bwd Packets"].sum()),

                "total_syn_flags": float(g["SYN Flag Count"].sum()),
                "total_ack_flags": float(g["ACK Flag Count"].sum()),
                "total_fin_flags": float(g["FIN Flag Count"].sum()),
                "total_rst_flags": float(g["RST Flag Count"].sum()),
                "total_psh_flags": float(g["PSH Flag Count"].sum()),
                "total_urg_flags": float(g["URG Flag Count"].sum()),

                "unique_source_ips":        int(g["Source IP"].nunique()),
                "unique_destination_ips":   int(g["Destination IP"].nunique()),
                "unique_destination_ports": int(g["Destination Port"].nunique()),

                "top_source_ip_ratio":        top_source_ip_ratio,
                "top_destination_ip_ratio":   top_destination_ip_ratio,
                "top_destination_port_ratio": top_destination_port_ratio,

                # ── NEW: actual top IP/port ──
                "top_source_ip":        top_source_ip,
                "top_destination_ip":   top_destination_ip,
                "top_destination_port": top_destination_port,

                "proto_entropy":            proto_entropy,
                "source_ip_entropy":        source_ip_entropy,
                "destination_port_entropy": destination_port_entropy,

                "proto_entropy_inverse": max(0.0, max_proto_entropy - proto_entropy),
                "ip_entropy_inverse":    max(0.0, max_src_entropy   - source_ip_entropy),
                "port_entropy_inverse":  max(0.0, max_port_entropy  - destination_port_entropy),
            })

        if grouped_rows:
            partial_windows.append(pd.DataFrame(grouped_rows))

    if not partial_windows:
        return pd.DataFrame()

    all_partial = pd.concat(partial_windows, ignore_index=True)

    # Combine windows that span multiple chunks — use the most-dominant IP/port
    def _top_str(s: pd.Series) -> str:
        vc = s[s != ""].value_counts()
        return vc.index[0] if not vc.empty else ""

    final = all_partial.groupby("time_window").agg(
        flow_count=("flow_count", "sum"),

        tcp_flow_count=("tcp_flow_count",   "sum"),
        udp_flow_count=("udp_flow_count",   "sum"),
        icmp_flow_count=("icmp_flow_count", "sum"),

        avg_flow_bytes_per_sec=("avg_flow_bytes_per_sec",     "mean"),
        total_flow_bytes_per_sec=("total_flow_bytes_per_sec", "sum"),
        max_flow_bytes_per_sec=("max_flow_bytes_per_sec",     "max"),

        avg_flow_packets_per_sec=("avg_flow_packets_per_sec",     "mean"),
        total_flow_packets_per_sec=("total_flow_packets_per_sec", "sum"),
        max_flow_packets_per_sec=("max_flow_packets_per_sec",     "max"),

        avg_flow_duration=("avg_flow_duration", "mean"),
        avg_packet_length=("avg_packet_length", "mean"),

        total_fwd_packets=("total_fwd_packets", "sum"),
        total_bwd_packets=("total_bwd_packets", "sum"),
        total_fwd_bytes=("total_fwd_bytes",     "sum"),
        total_bwd_bytes=("total_bwd_bytes",     "sum"),

        total_syn_flags=("total_syn_flags", "sum"),
        total_ack_flags=("total_ack_flags", "sum"),
        total_fin_flags=("total_fin_flags", "sum"),
        total_rst_flags=("total_rst_flags", "sum"),
        total_psh_flags=("total_psh_flags", "sum"),
        total_urg_flags=("total_urg_flags", "sum"),

        unique_source_ips=("unique_source_ips",               "max"),
        unique_destination_ips=("unique_destination_ips",     "max"),
        unique_destination_ports=("unique_destination_ports", "max"),

        top_source_ip_ratio=("top_source_ip_ratio",               "max"),
        top_destination_ip_ratio=("top_destination_ip_ratio",     "max"),
        top_destination_port_ratio=("top_destination_port_ratio", "max"),

        top_destination_port=("top_destination_port", "max"),

        proto_entropy=("proto_entropy",                 "mean"),
        source_ip_entropy=("source_ip_entropy",         "mean"),
        destination_port_entropy=("destination_port_entropy", "mean"),

        proto_entropy_inverse=("proto_entropy_inverse", "mean"),
        ip_entropy_inverse=("ip_entropy_inverse",       "mean"),
        port_entropy_inverse=("port_entropy_inverse",   "mean"),
    ).reset_index()

    # top_source_ip / top_destination_ip can't be agg'd above — compute separately
    ip_agg = (
        all_partial.groupby("time_window")["top_source_ip"]
        .agg(_top_str)
        .rename("top_source_ip")
    )
    dst_ip_agg = (
        all_partial.groupby("time_window")["top_destination_ip"]
        .agg(_top_str)
        .rename("top_destination_ip")
    )
    final = final.merge(ip_agg, on="time_window", how="left")
    final = final.merge(dst_ip_agg, on="time_window", how="left")

    print(f"[detection] Rows processed : {total_rows:,}")
    print(f"[detection] Windows created: {len(final):,}")
    return final


# ══════════════════════════════════════════════════════════════════════════════
# PCAP INCREMENTAL AGGREGATION
# ══════════════════════════════════════════════════════════════════════════════

def aggregate_pcap(pcap_path: str, window_size: str = "1s") -> pd.DataFrame:
    """
    Read a .pcap/.pcapng file with Scapy, reconstruct flow-level records,
    then aggregate into the same time-window schema as aggregate_raw_csv().
    top_source_ip, top_destination_ip, and top_destination_port are preserved.

    Requires: pip install scapy
    """
    try:
        from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP
    except ImportError:
        raise ImportError(
            "Scapy is required for pcap input.  Install it with:\n"
            "    pip install scapy"
        )

    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    print(f"[detection] Reading PCAP: {pcap_path}")

    flow_buckets: Dict[tuple, list] = {}
    total_packets = 0

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            total_packets += 1
            ts = float(pkt.time)

            if IP in pkt:
                src_ip = pkt[IP].src;  dst_ip = pkt[IP].dst;  proto = int(pkt[IP].proto)
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src; dst_ip = pkt[IPv6].dst; proto = int(pkt[IPv6].nh)
            else:
                continue

            src_port = dst_port = 0
            syn = ack = fin = rst = psh = urg = 0

            if TCP in pkt:
                src_port = int(pkt[TCP].sport); dst_port = int(pkt[TCP].dport)
                flags = pkt[TCP].flags
                syn = 1 if flags.S else 0; ack = 1 if flags.A else 0
                fin = 1 if flags.F else 0; rst = 1 if flags.R else 0
                psh = 1 if flags.P else 0; urg = 1 if flags.U else 0
            elif UDP in pkt:
                src_port = int(pkt[UDP].sport); dst_port = int(pkt[UDP].dport)

            flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
            flow_buckets.setdefault(flow_key, []).append({
                "ts": ts, "pkt_len": len(pkt),
                "syn": syn, "ack": ack, "fin": fin,
                "rst": rst, "psh": psh, "urg": urg,
            })

    print(f"[detection] Packets read : {total_packets:,}")
    print(f"[detection] Unique flows : {len(flow_buckets):,}")

    if not flow_buckets:
        print("[detection] No IP flows found in PCAP.")
        return pd.DataFrame()

    flow_rows = []

    for (src_ip, dst_ip, src_port, dst_port, proto), pkts in flow_buckets.items():
        timestamps  = [p["ts"] for p in pkts]
        start_ts    = min(timestamps)
        end_ts      = max(timestamps)
        duration_s  = max(end_ts - start_ts, 1e-6)

        total_bytes  = sum(p["pkt_len"] for p in pkts)
        total_pkts_f = len(pkts)
        fwd_pkts     = total_pkts_f
        fwd_bytes    = total_bytes

        rev_key   = (dst_ip, src_ip, dst_port, src_port, proto)
        rev_pkts  = flow_buckets.get(rev_key, [])
        bwd_pkts  = len(rev_pkts)
        bwd_bytes = sum(p["pkt_len"] for p in rev_pkts)

        flow_rows.append({
            "time_window": pd.Timestamp(start_ts, unit="s").floor(window_size),
            "src_ip":   src_ip,  "dst_ip":   dst_ip,
            "dst_port": dst_port, "proto":   proto,
            "flow_bytes_s":  total_bytes    / duration_s,
            "flow_pkts_s":   total_pkts_f   / duration_s,
            "flow_duration": duration_s * 1e6,
            "fwd_pkts":  fwd_pkts,  "bwd_pkts":  bwd_pkts,
            "fwd_bytes": fwd_bytes, "bwd_bytes": bwd_bytes,
            "pkt_len_mean": total_bytes / max(total_pkts_f, 1),
            "syn": sum(p["syn"] for p in pkts), "ack": sum(p["ack"] for p in pkts),
            "fin": sum(p["fin"] for p in pkts), "rst": sum(p["rst"] for p in pkts),
            "psh": sum(p["psh"] for p in pkts), "urg": sum(p["urg"] for p in pkts),
        })

    flows = pd.DataFrame(flow_rows)
    flows["is_tcp"]  = (flows["proto"] == 6).astype(int)
    flows["is_udp"]  = (flows["proto"] == 17).astype(int)
    flows["is_icmp"] = (flows["proto"] == 1).astype(int)

    grouped_rows = []

    for tw, g in flows.groupby("time_window"):
        flow_count = len(g)

        protocol_counts = g["proto"].value_counts()
        src_counts      = g["src_ip"].value_counts()
        dst_port_counts = g["dst_port"].value_counts()
        dst_ip_counts   = g["dst_ip"].value_counts()

        top_source_ip        = str(src_counts.index[0])      if not src_counts.empty      else ""
        top_destination_ip   = str(dst_ip_counts.index[0])   if not dst_ip_counts.empty   else ""
        top_destination_port = int(dst_port_counts.index[0]) if not dst_port_counts.empty else 0

        top_src_ip_ratio   = float(src_counts.iloc[0]      / flow_count) if flow_count else 0.0
        top_dst_ip_ratio   = float(dst_ip_counts.iloc[0]   / flow_count) if flow_count else 0.0
        top_dst_port_ratio = float(dst_port_counts.iloc[0] / flow_count) if flow_count else 0.0

        src_ip_entropy   = shannon_entropy_from_counts(src_counts)
        dst_port_entropy = shannon_entropy_from_counts(dst_port_counts)
        proto_entropy    = shannon_entropy_from_counts(protocol_counts)

        max_proto_entropy = math.log2(3)
        max_src_entropy   = math.log2(max(int(g["src_ip"].nunique()),  2))
        max_port_entropy  = math.log2(max(int(g["dst_port"].nunique()), 2))

        grouped_rows.append({
            "time_window":  tw,
            "flow_count":   flow_count,

            "tcp_flow_count":  int(g["is_tcp"].sum()),
            "udp_flow_count":  int(g["is_udp"].sum()),
            "icmp_flow_count": int(g["is_icmp"].sum()),

            "avg_flow_bytes_per_sec":   float(g["flow_bytes_s"].mean()),
            "total_flow_bytes_per_sec": float(g["flow_bytes_s"].sum()),
            "max_flow_bytes_per_sec":   float(g["flow_bytes_s"].max()),

            "avg_flow_packets_per_sec":   float(g["flow_pkts_s"].mean()),
            "total_flow_packets_per_sec": float(g["flow_pkts_s"].sum()),
            "max_flow_packets_per_sec":   float(g["flow_pkts_s"].max()),

            "avg_flow_duration": float(g["flow_duration"].mean()),
            "avg_packet_length": float(g["pkt_len_mean"].mean()),

            "total_fwd_packets": float(g["fwd_pkts"].sum()),
            "total_bwd_packets": float(g["bwd_pkts"].sum()),
            "total_fwd_bytes":   float(g["fwd_bytes"].sum()),
            "total_bwd_bytes":   float(g["bwd_bytes"].sum()),

            "total_syn_flags": float(g["syn"].sum()), "total_ack_flags": float(g["ack"].sum()),
            "total_fin_flags": float(g["fin"].sum()), "total_rst_flags": float(g["rst"].sum()),
            "total_psh_flags": float(g["psh"].sum()), "total_urg_flags": float(g["urg"].sum()),

            "unique_source_ips":        int(g["src_ip"].nunique()),
            "unique_destination_ips":   int(g["dst_ip"].nunique()),
            "unique_destination_ports": int(g["dst_port"].nunique()),

            "top_source_ip_ratio":        top_src_ip_ratio,
            "top_destination_ip_ratio":   top_dst_ip_ratio,
            "top_destination_port_ratio": top_dst_port_ratio,

            # ── NEW: actual top IP/port ──
            "top_source_ip":        top_source_ip,
            "top_destination_ip":   top_destination_ip,
            "top_destination_port": top_destination_port,

            "proto_entropy":            proto_entropy,
            "source_ip_entropy":        src_ip_entropy,
            "destination_port_entropy": dst_port_entropy,

            "proto_entropy_inverse": max(0.0, max_proto_entropy - proto_entropy),
            "ip_entropy_inverse":    max(0.0, max_src_entropy   - src_ip_entropy),
            "port_entropy_inverse":  max(0.0, max_port_entropy  - dst_port_entropy),
        })

    final = pd.DataFrame(grouped_rows).sort_values("time_window").reset_index(drop=True)

    print(f"[detection] Windows created: {len(final):,}")
    return final


# ══════════════════════════════════════════════════════════════════════════════
# REPORTING AND OUTPUTS
# ══════════════════════════════════════════════════════════════════════════════

def print_detection_summary(results: pd.DataFrame) -> None:
    total     = len(results)
    anomalies = int(results["is_anomaly"].sum()) if "is_anomaly" in results.columns else 0
    benign    = total - anomalies

    print("\n" + "=" * 72)
    print("  HYBRID DDoS DETECTION SUMMARY")
    print("=" * 72)

    if total == 0:
        print("  No windows to analyse.")
        print("=" * 72)
        return

    print(f"  Total windows analysed : {total}")
    print(f"  BENIGN windows         : {benign} ({100 * benign / total:.1f}%)")
    print(f"  Anomalous windows      : {anomalies} ({100 * anomalies / total:.1f}%)")
    print(f"  Composite threshold    : {COMPOSITE_THRESHOLD}")
    print(f"  Z-score threshold      : {Z_THRESHOLD}")

    report = adaptive_threshold_report(results["composite_score"])
    print("\n  Adaptive threshold report:")
    print(f"    Suspicious approx ≥ {report['adaptive_suspicious_threshold']}")
    print(f"    Attack approx     ≥ {report['adaptive_attack_threshold']}")

    if anomalies == 0:
        print("\n  No anomalies detected — traffic matches baseline.")
        print("=" * 72)
        return

    # ── attack type breakdown ────────────────────────────────────────────────
    print("\n  Attack type breakdown:")
    for atype, cnt in results[results["is_anomaly"]]["attack_type"].value_counts().items():
        mit = MITIGATION_RECOMMENDATIONS.get(atype, MITIGATION_RECOMMENDATIONS["Unknown_DDoS"])
        print(f"    {atype:<28} {cnt} window(s)")
        print(f"      {mit['description']}")

    # ── distinct attack events ───────────────────────────────────────────────
    if "attack_event_id" in results.columns:
        n_events = results[results["is_anomaly"]]["attack_event_id"].nunique()
        print(f"\n  Distinct attack events : {n_events}")

    # ── top anomalous windows ────────────────────────────────────────────────
    print("\n  Top anomalous windows:")
    top = results[results["is_anomaly"]].nlargest(5, "composite_score")

    for _, r in top.iterrows():
        print(f"\n    [Event {r.get('attack_event_id','?')}] "
              f"[{r.get('attack_type','Unknown')}] {r.get('time_window','?')}")
        print(f"      score            : {r.get('composite_score',0):.3f}")
        print(f"      severity         : {r.get('severity','?')}")
        print(f"      confidence       : {r.get('confidence','?')}")
        print(f"      triggered        : {r.get('triggered_signals','')}")
        print(f"      top source IP    : {r.get('top_source_ip','N/A')}")
        print(f"      top dest port    : {r.get('top_destination_port','N/A')}")
        print(f"      mitigation       : {r.get('mitigation_rate_limit','')}")
        print(f"      firewall rule    : {r.get('firewall_rule','')}")
        print(f"      justification    : {r.get('signal_details','')}")

    print("=" * 72)


def build_summary_json(results: pd.DataFrame, baseline_path: str) -> dict:
    total     = len(results)
    anomalies = int(results["is_anomaly"].sum()) if "is_anomaly" in results.columns else 0

    attack_breakdown = {}
    top_windows      = []

    if anomalies > 0:
        attack_breakdown = (
            results[results["is_anomaly"]]["attack_type"].value_counts().to_dict()
        )

        for _, r in results[results["is_anomaly"]].nlargest(10, "composite_score").iterrows():
            top_windows.append({
                "event_id":             int(r.get("attack_event_id", 0)),
                "time_window":          str(r.get("time_window", "")),
                "composite_score":      round(float(r.get("composite_score", 0.0)), 4),
                "severity":             r.get("severity", ""),
                "attack_type":          r.get("attack_type", ""),
                "confidence":           r.get("confidence", ""),
                "triggered_signals":    r.get("triggered_signals", ""),
                "signal_details":       r.get("signal_details", ""),
                "top_source_ip":        r.get("top_source_ip", ""),
                "top_destination_port": str(r.get("top_destination_port", "")),
                "mitigation":           r.get("mitigation_rate_limit", ""),
                "firewall_rule":        r.get("firewall_rule", ""),
                "safeguard":            r.get("mitigation_safeguard", ""),
            })

    signal_trigger_counts: dict = {}
    if "triggered_signals" in results.columns:
        for signals in results["triggered_signals"].dropna():
            if not signals:
                continue
            for s in str(signals).split("|"):
                signal_trigger_counts[s] = signal_trigger_counts.get(s, 0) + 1

    n_events = 0
    if "attack_event_id" in results.columns and anomalies > 0:
        n_events = int(results[results["is_anomaly"]]["attack_event_id"].nunique())

    return {
        "baseline_used":          baseline_path,
        "detector":               "hybrid_detection",
        "composite_threshold":    COMPOSITE_THRESHOLD,
        "z_threshold":            Z_THRESHOLD,
        "attack_gap_seconds":     ATTACK_GAP_SECONDS,
        "adaptive_threshold_report": adaptive_threshold_report(results["composite_score"]),
        "total_windows":          total,
        "benign_windows":         total - anomalies,
        "anomalous_windows":      anomalies,
        "distinct_attack_events": n_events,
        "attack_type_breakdown":  attack_breakdown,
        "signal_trigger_counts":  signal_trigger_counts,
        "top_anomalous_windows":  top_windows,
        "signal_weights":         SIGNAL_WEIGHTS,
        "attack_rules": {
            k: {feat: f"{op} {thr}" for feat, (op, thr) in rule.items()}
            for k, rule in ATTACK_RULES.items()
        },
        "mitigation_recommendations": MITIGATION_RECOMMENDATIONS,
        "notes": [
            "Main anomaly decision uses fixed composite threshold for stable TA explanation.",
            "Adaptive thresholds are reported for dashboard tuning, not the default decision boundary.",
            "Entropy and concentration signals strengthen protocol/IP/port anomaly detection.",
            "Alerts are de-duplicated: consecutive same-type windows are collapsed to one event.",
            "attack_event_id distinguishes separate attacks even of the same type.",
            "top_source_ip and top_destination_port are real values from traffic, not placeholders.",
        ],
    }


def save_outputs(results: pd.DataFrame, summary: dict, output_dir: str) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    results_path = out / "detection_results.csv"
    summary_path = out / "detection_summary.json"
    alerts_path  = out / "alerts.json"

    results.to_csv(results_path, index=False)

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)

    # ── de-duplicated alerts: one per attack event, not one per window ────────
    alerts = build_deduped_alerts(results)

    with open(alerts_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=4)

    # ── terminal alert printout (fallback for demo) ───────────────────────────
    if alerts:
        print("\n" + "=" * 72)
        print("  DE-DUPLICATED ALERTS  (one per distinct attack event)")
        print("=" * 72)
        for a in alerts:
            print(f"\n  [Event {a['event_id']}] {a['severity']} — {a['attack_type']}")
            print(f"    Start          : {a['start_time']}")
            print(f"    End            : {a['end_time']}")
            print(f"    Windows spanned: {a['duration_windows']}")
            print(f"    Peak score     : {a['peak_score']}")
            print(f"    Top source IP  : {a['top_source_ip'] or 'N/A'}")
            print(f"    Top dest port  : {a['top_destination_port'] or 'N/A'}")
            print(f"    Firewall rule  : {a['firewall_rule']}")
            print(f"    Justification  : {a['detection_justification']}")
        print("=" * 72)
    else:
        print("\n[detection] No anomalous events detected — no alerts generated.")

    print("\n[detection] Outputs saved:")
    print(f"    detection_results.csv  -> {results_path}")
    print(f"    detection_summary.json -> {summary_path}")
    print(f"    alerts.json            -> {alerts_path}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def run_detection(
    windows: pd.DataFrame,
    baseline: dict,
    baseline_path: str,
    output_dir: str,
) -> pd.DataFrame:
    print("\n" + "=" * 72)
    print("  HYBRID PART 2 — ANOMALY DETECTION PIPELINE")
    print("=" * 72)
    print(f"  Windows to analyse  : {len(windows):,}")
    print(f"  Composite threshold : {COMPOSITE_THRESHOLD}")
    print(f"  Z-score threshold   : {Z_THRESHOLD}")
    print(f"  Attack gap (s)      : {ATTACK_GAP_SECONDS}")

    if windows.empty:
        print("No windows found. Nothing to analyse.")
        return pd.DataFrame()

    print("\n[1] Adding protocol, entropy, concentration and asymmetry features ...")
    windows = _add_derived_features(windows)

    print("[2] Computing baseline z-scores and hybrid composite anomaly scores ...")
    scored = compute_signal_scores(windows, baseline)

    print("[3] Classifying attack type and adding mitigation recommendations ...")
    classified = classify_attack(scored)

    print("[4] Grouping windows into distinct attack events ...")
    results = group_attack_events(classified)

    print_detection_summary(results)

    summary = build_summary_json(results, baseline_path)
    save_outputs(results, summary, output_dir)

    print("\nHybrid detection complete.\n")
    return results


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hybrid DDoS Anomaly Detection & Attack Classification"
    )

    sub = parser.add_subparsers(dest="mode", required=True)

    p_win = sub.add_parser("windows", help="Detect on pre-aggregated monitoring windows CSV.")
    p_win.add_argument("--windows",  required=True)
    p_win.add_argument("--baseline", required=True)
    p_win.add_argument("--output",   default="detection_outputs")

    p_csv = sub.add_parser("csv", help="Detect on a raw CICIDS-format CSV using incremental aggregation.")
    p_csv.add_argument("--csv",       required=True)
    p_csv.add_argument("--baseline",  required=True)
    p_csv.add_argument("--output",    default="detection_outputs")
    p_csv.add_argument("--chunksize", type=int, default=50_000)
    p_csv.add_argument("--window-size", default="1s")

    p_pcap = sub.add_parser(
        "pcap",
        help="Detect on a raw PCAP/PCAPNG file (requires pip install scapy).",
    )
    p_pcap.add_argument("--pcap",        required=True)
    p_pcap.add_argument("--baseline",    required=True)
    p_pcap.add_argument("--output",      default="detection_outputs")
    p_pcap.add_argument("--window-size", default="1s",
                        help="Pandas time-floor string, e.g. '1s', '5s', '1min'. (default: 1s)")

    args = parser.parse_args()

    baseline = load_baseline(args.baseline)

    if args.mode == "windows":
        windows = load_windows(args.windows)
        run_detection(windows=windows, baseline=baseline,
                      baseline_path=args.baseline, output_dir=args.output)

    elif args.mode == "csv":
        windows = aggregate_raw_csv(
            csv_path=args.csv,
            chunksize=args.chunksize,
            window_size=args.window_size,
        )
        run_detection(windows=windows, baseline=baseline,
                      baseline_path=args.baseline, output_dir=args.output)

    elif args.mode == "pcap":
        windows = aggregate_pcap(
            pcap_path=args.pcap,
            window_size=args.window_size,
        )
        run_detection(windows=windows, baseline=baseline,
                      baseline_path=args.baseline, output_dir=args.output)


if __name__ == "__main__":
    main()