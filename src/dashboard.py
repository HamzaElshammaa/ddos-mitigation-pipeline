"""
dashboard.py
============
Integrated DDoS Mitigation Dashboard

This version directly imports backend modules (`baseline.py`, `detection.py`, `mitigation.py`) 
to run the pipeline live from the UI, satisfying all Project 1 requirements.

Prerequisites:
pip install streamlit pandas plotly scapy
"""

import os
import json
import tempfile
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import smtplib
from email.mime.text import MIMEText


# --- Import backend modules ---
try:
    from baseline import run_csv_pipeline
    from detection import load_baseline, aggregate_raw_csv, aggregate_pcap, run_detection
    from mitigation import MitigationEngine
except ImportError as e:
    st.error(f"Backend modules not found or failed to load. Error: {e}")
    st.stop()

# =====================================================================
# STATE & ENGINE INITIALIZATION
# =====================================================================
st.set_page_config(page_title="DDoS Mitigation Dashboard", layout="wide", page_icon="🛡️")

# Initialize mitigation engine — dry_run toggled from sidebar
if "dry_run" not in st.session_state:
    st.session_state.dry_run = True
mitigation_engine = MitigationEngine(output_dir="mitigation_outputs", dry_run=st.session_state.dry_run)

# Default paths used by the backend
BASELINE_DIR = "baseline_outputs"
BASELINE_METRICS_PATH = os.path.join(BASELINE_DIR, "baseline_metrics.json")
DETECTION_OUTPUT_DIR = "detection_outputs"
ALERTS_PATH = os.path.join(DETECTION_OUTPUT_DIR, "alerts.json")

if "results_df" not in st.session_state:
    st.session_state.results_df = None
if "baseline_summary" not in st.session_state:
    st.session_state.baseline_summary = None
if "alert_recipient" not in st.session_state:
    st.session_state.alert_recipient = "moaaz.samir.kamel@gmail.com"
if "alert_cooldown_minutes" not in st.session_state:
    st.session_state.alert_cooldown_minutes = 2.0
if "last_alert_signature" not in st.session_state:
    st.session_state.last_alert_signature = None
if "last_alert_sent_time" not in st.session_state:
    st.session_state.last_alert_sent_time = None
if "last_alerts_present" not in st.session_state:
    st.session_state.last_alerts_present = False
if "last_alerts_snapshot" not in st.session_state:
    st.session_state.last_alerts_snapshot = []
if "last_attack_end_signature" not in st.session_state:
    st.session_state.last_attack_end_signature = None


DEFAULT_ALERT_RECIPIENT = "moaaz.samir.kamel@gmail.com"
SENDER_EMAIL = "moaaz.samir.kamel@gmail.com"
SENDER_APP_PASSWORD = "eessuxunudwwrybb"


def build_alert_email_body(alerts, summary=False):
    if summary:
        header = "DDoS incident resolved. Final summary of the attack follow."
    else:
        header = "URGENT: DDoS attack detected on monitored network."

    lines = [
        header,
        "",
        f"Total distinct anomalous events: {len(alerts)}",
        "",
        "Summary of detected events:",
    ]

    for alert in alerts[:5]:
        triggered = alert.get("triggered_signals", "N/A")
        formatted_triggers = triggered.replace("|", ", ") if triggered else "N/A"
        lines.extend([
            f"- Event ID: {alert.get('event_id', 'N/A')} | Severity: {alert.get('severity', 'N/A')} | Type: {alert.get('attack_type', 'N/A')}",
            f"  Time Window: {alert.get('start_time', alert.get('time_window', 'N/A'))} → {alert.get('end_time', 'N/A')}",
            f"  Peak Score: {alert.get('peak_score', 'N/A')} | Top Source IP: {alert.get('top_source_ip', 'N/A')}",
            f"  Top Dest Port: {alert.get('top_destination_port', 'N/A')} | Triggered: {formatted_triggers}",
            f"  Suggested Action: {alert.get('safeguard', 'N/A')}",
            "",
        ])

    if len(alerts) > 5:
        lines.append(f"...and {len(alerts) - 5} more event(s). Review the dashboard for full details.")

    if summary:
        lines.extend([
            "",
            "This is the final summary for the ended incident.",
            "Review the mitigation dashboard and verify that no further anomalous events are present.",
        ])
    else:
        lines.extend([
            "",
            "Review the mitigation dashboard immediately and apply the suggested firewall rules.",
            "If this is a false positive, investigate the source IPs and adjust baseline thresholds.",
        ])
    return "\n".join(lines)


def build_alert_signature(alerts):
    events = []
    for alert in alerts:
        events.append(
            (
                str(alert.get("event_id", "")),
                alert.get("attack_type", ""),
                alert.get("top_source_ip", ""),
                str(alert.get("top_destination_port", "")),
                alert.get("severity", ""),
                str(alert.get("peak_score", "")),
            )
        )
    events.sort()
    return tuple(events)


def build_alert_subject(alerts, summary=False):
    if summary:
        return f"✅ DDoS Attack End Summary — {len(alerts)} event(s)"
    return f"🚨 DDoS Mitigation Alert — {len(alerts)} event(s) detected"


def send_real_email(recipient_email, alerts, summary=False):
    if not alerts:
        return False, "No alerts available to send."

    body = build_alert_email_body(alerts, summary=summary)
    subject = build_alert_subject(alerts, summary=summary)

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.send_message(msg)
        return True, None
    except Exception as e:
        return False, str(e)


def load_alerts_json():
    if not os.path.exists(ALERTS_PATH):
        return []
    with open(ALERTS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def get_alerts_file_stamp():
    if not os.path.exists(ALERTS_PATH):
        return None
    return os.path.getmtime(ALERTS_PATH)


def auto_send_alert_email_if_new(alerts):
    recipient = st.session_state.get("alert_recipient", DEFAULT_ALERT_RECIPIENT)
    if not recipient:
        return None

    if alerts:
        signature = build_alert_signature(alerts)
        now = datetime.now()
        cooldown_seconds = st.session_state.alert_cooldown_minutes * 60

        is_new_attack = not st.session_state.last_alerts_present or signature != st.session_state.last_alert_signature
        cooldown_expired = (
            st.session_state.last_alert_sent_time is None
            or (now - st.session_state.last_alert_sent_time).total_seconds() >= cooldown_seconds
        )

        if is_new_attack or cooldown_expired:
            success, error = send_real_email(recipient, alerts, summary=False)
            if success:
                st.session_state.last_alert_sent_time = now
                st.session_state.last_alert_signature = signature
                st.session_state.last_alerts_present = True
                st.session_state.last_alerts_snapshot = alerts
            return success, error

        return None

    # No active alerts now; maybe send final summary for a recently ended incident.
    if st.session_state.last_alerts_present and st.session_state.last_alerts_snapshot:
        signature = st.session_state.last_alert_signature
        if signature and signature != st.session_state.last_attack_end_signature:
            success, error = send_real_email(recipient, st.session_state.last_alerts_snapshot, summary=True)
            if success:
                st.session_state.last_attack_end_signature = signature
            st.session_state.last_alerts_present = False
            st.session_state.last_alerts_snapshot = []
            return success, error

    st.session_state.last_alerts_present = False
    return None
# =====================================================================
# SIDEBAR: MODE SELECTION & ACCESS CONTROL
# =====================================================================
with st.sidebar:
    st.title("🛡️ System Controls")

    app_mode = st.radio(
        "Operation Mode",
        ["1. Learning Mode (Baseline)", "2. Detection Mode", "3. Mitigation & Alerts"],
        help="Navigate through the system pipeline."
    )

    st.markdown("---")
    st.subheader("⚙️ iptables Execution Mode")
    dry_run_toggle = st.toggle(
        "Dry Run (log only)",
        value=st.session_state.dry_run,
        help="OFF = actually execute iptables rules inside the container (requires NET_ADMIN)."
    )
    if dry_run_toggle != st.session_state.dry_run:
        st.session_state.dry_run = dry_run_toggle
        mitigation_engine.iptables.dry_run = dry_run_toggle
    if dry_run_toggle:
        st.info("DRY RUN — rules are logged but not executed.")
    else:
        st.warning("LIVE MODE — iptables rules will execute for real.")

    st.markdown("---")
    st.subheader("📝 Access Control Lists")
    
    col_w1, col_w2 = st.columns(2)
    with col_w1:
        wl_ip = st.text_input("Add to Whitelist (IP)", key="add_whitelist_ip")
        if st.button("Whitelist IP", key="btn_add_whitelist") and wl_ip:
            mitigation_engine.add_whitelist(wl_ip)
            st.success(f"Added {wl_ip} to whitelist")

    with col_w2:
        remove_wl_ip = st.text_input("Remove from Whitelist (IP)", key="remove_whitelist_ip")
        if st.button("Remove from Whitelist", key="btn_remove_whitelist") and remove_wl_ip:
            mitigation_engine.remove_whitelist(remove_wl_ip)
            st.success(f"Removed {remove_wl_ip} from whitelist")
            
    col_b1, col_b2 = st.columns(2)
    with col_b1:
        bl_ip = st.text_input("Add to Blacklist (IP)", key="add_blacklist_ip")
        if st.button("Blacklist IP", key="btn_add_blacklist") and bl_ip:
            mitigation_engine.add_blacklist(bl_ip)
            st.success(f"Added {bl_ip} to blacklist")

    with col_b2:
        remove_bl_ip = st.text_input("Remove from Blacklist (IP)", key="remove_blacklist_ip")
        if st.button("Remove from Blacklist", key="btn_remove_blacklist") and remove_bl_ip:
            mitigation_engine.remove_blacklist(remove_bl_ip)
            st.success(f"Removed {remove_bl_ip} from blacklist")
            
    with st.expander("View Active Access Lists", expanded=True):
        st.write("**Whitelist (Trusted):**")
        for ip in mitigation_engine.get_whitelist():
            st.code(ip)
            
        st.write("**Blacklist (Blocked):**")
        for ip in mitigation_engine.get_blacklist():
            st.code(ip)

    st.markdown("---")
    st.subheader("📨 Alert Email Settings")
    recipient_email = st.text_input(
        "Alert recipient email",
        value=st.session_state.get("alert_recipient", DEFAULT_ALERT_RECIPIENT),
        help="Email address where automated DDoS alert summaries will be sent."
    )
    if recipient_email:
        st.session_state.alert_recipient = recipient_email.strip()

    cooldown_minutes = st.number_input(
        "Alert cool-down (minutes)",
        min_value=1.0,
        max_value=5.0,
        value=float(st.session_state.alert_cooldown_minutes),
        step=0.5,
        format="%.1f",
        help="Suppress repeated identical alerts for this interval."
    )
    st.session_state.alert_cooldown_minutes = float(cooldown_minutes)

# =====================================================================
# MODE 1: LEARNING MODE
# =====================================================================
if app_mode == "1. Learning Mode (Baseline)":
    st.header("🧠 Learning Mode: Establish Baseline")
    st.write("Upload a dataset containing **normal (benign) traffic** to establish network baselines. This triggers `baseline.py`.")
    
    baseline_file = st.file_uploader("Upload Benign Traffic (CSV)", type=["csv"], key="baseline_upload")
    
    if baseline_file and st.button("Build Baseline Profile", type="primary"):
        with st.spinner("Processing traffic and building statistical models..."):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
                tmp.write(baseline_file.getvalue())
                tmp_path = tmp.name
            
            try:
                baseline_data = run_csv_pipeline(csv_path=tmp_path, output_dir=BASELINE_DIR)
                st.success(f"✅ Baseline profile successfully built and saved to {BASELINE_DIR}!")
                
                # Show key baseline stats
                st.subheader("Baseline Metrics Snapshot")
                metrics = baseline_data.get("metrics", {})
                cols = st.columns(4)
                cols[0].metric("Avg Flow Bytes/s", f"{metrics.get('avg_flow_bytes_per_sec', {}).get('mean', 0):.2f}")
                cols[1].metric("Avg Packets/s", f"{metrics.get('avg_flow_packets_per_sec', {}).get('mean', 0):.2f}")
                cols[2].metric("TCP Flow Mean", f"{metrics.get('tcp_flow_count', {}).get('mean', 0):.2f}")
                cols[3].metric("UDP Flow Mean", f"{metrics.get('udp_flow_count', {}).get('mean', 0):.2f}")
                
            except Exception as e:
                st.error(f"Error building baseline: {e}")
            finally:
                os.remove(tmp_path)

# =====================================================================
# MODE 2: DETECTION MODE
# =====================================================================
elif app_mode == "2. Detection Mode":
    st.header("🔍 Detection Mode: Traffic Analysis")
    
    if not os.path.exists(BASELINE_METRICS_PATH):
        st.warning(f"No baseline found at `{BASELINE_METRICS_PATH}`. Please run Learning Mode first.")
        st.stop()
        
    st.success(f"✅ Baseline loaded from `{BASELINE_METRICS_PATH}`")
    
    # Allow PCAP uploads alongside CSV
    target_file = st.file_uploader("Upload Traffic for Analysis (CSV, PCAP, PCAPNG)", type=["csv", "pcap", "pcapng"], key="target_upload")
    
    if target_file and st.button("Run DDoS Detection Pipeline", type="primary"):
        with st.spinner("Parsing traffic, aggregating windows, and scoring anomalies..."):
            
            # Extract the file extension to route to the correct parser
            file_ext = os.path.splitext(target_file.name)[1].lower()
            
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp:
                tmp.write(target_file.getvalue())
                tmp_path = tmp.name
            
            try:
                baseline = load_baseline(BASELINE_METRICS_PATH)
                
                # Route to appropriate backend parser
                if file_ext in [".pcap", ".pcapng"]:
                    st.info("📡 Streaming PCAP file and aggregating flows (this may take a minute for large files)...")
                    windows = aggregate_pcap(pcap_path=tmp_path, window_size="1s")
                else:
                    st.info("📄 Aggregating raw CSV into time windows...")
                    windows = aggregate_raw_csv(csv_path=tmp_path, chunksize=50_000, window_size="1s")
                
                if not windows.empty:
                    st.info("🧠 Running hybrid detection algorithms...")
                    results_df = run_detection(
                        windows=windows, 
                        baseline=baseline, 
                        baseline_path=BASELINE_METRICS_PATH, 
                        output_dir=DETECTION_OUTPUT_DIR
                    )
                    
                    if "time_window" in results_df.columns:
                        results_df["time_window"] = pd.to_datetime(results_df["time_window"])
                        
                    st.session_state.results_df = results_df
                    st.session_state.baseline_summary = baseline
                    st.success("✅ Detection pipeline completed! Scroll down for telemetry.")

                    alerts = load_alerts_json()
                    send_result = auto_send_alert_email_if_new(alerts)
                    if send_result is not None:
                        success, error_msg = send_result
                        if success:
                            st.success(f"📩 Automated alert notification sent to {st.session_state.alert_recipient}.")
                        else:
                            st.error(f"❌ Failed to send automated alert email: {error_msg}")
                    elif alerts:
                        st.info(f"Alert cool-down active: repeated identical alerts will be suppressed for {st.session_state.alert_cooldown_minutes} minutes.")
                    else:
                        st.info("No active anomalies detected.")
                else:
                    st.warning("No network flows could be generated from the uploaded file.")
            except Exception as e:
                st.error(f"Detection pipeline failed: {e}")
            finally:
                os.remove(tmp_path)

    if st.session_state.results_df is not None:
        df = st.session_state.results_df
        threshold = st.session_state.baseline_summary.get("composite_threshold", 2.5) if st.session_state.baseline_summary else 2.5

        st.markdown("---")

        # TIME SLIDER (Requirement: Time navigation)
        min_t, max_t = df["time_window"].min(), df["time_window"].max()
        time_range = st.slider(
            "Filter Time Window",
            min_value=min_t.to_pydatetime(),
            max_value=max_t.to_pydatetime(),
            value=(min_t.to_pydatetime(), max_t.to_pydatetime()),
            format="HH:mm:ss"
        )

        mask = (df["time_window"] >= time_range[0]) & (df["time_window"] <= time_range[1])
        f_df = df.loc[mask]
        anomalies = f_df[f_df["is_anomaly"] == True]

        # FOUR GRAPHS
        st.subheader("📊 Traffic Telemetry & Detection Metrics")
        col_g1, col_g2 = st.columns(2)

        with col_g1:
            fig1 = px.line(f_df, x="time_window", y="composite_score", title="Composite Anomaly Score", template="plotly_dark")
            fig1.add_hline(y=threshold, line_dash="dot", annotation_text="Anomaly Threshold", line_color="red")
            if not anomalies.empty:
                fig1.add_scatter(x=anomalies["time_window"], y=anomalies["composite_score"], mode="markers", marker=dict(color="red", size=8), name="Alert")
            st.plotly_chart(fig1, use_container_width=True)
            
        with col_g2:
            fig2 = px.area(f_df, x="time_window", y="avg_flow_bytes_per_sec", title="Bandwidth Usage (Bytes/s)", template="plotly_dark")
            st.plotly_chart(fig2, use_container_width=True)
            
        col_g3, col_g4 = st.columns(2)
        
        with col_g3:
            fig3 = go.Figure()
            if "tcp_ratio" in f_df.columns:
                fig3.add_trace(go.Scatter(x=f_df["time_window"], y=f_df["tcp_ratio"], stackgroup='one', name='TCP'))
                fig3.add_trace(go.Scatter(x=f_df["time_window"], y=f_df["udp_ratio"], stackgroup='one', name='UDP'))
                fig3.add_trace(go.Scatter(x=f_df["time_window"], y=f_df["icmp_ratio"], stackgroup='one', name='ICMP'))
            fig3.update_layout(title="Protocol Distribution Shifts", template="plotly_dark")
            st.plotly_chart(fig3, use_container_width=True)
            
        with col_g4:
            fig4 = px.line(f_df, x="time_window", y="unique_source_ips", title="Source IP Counts (Botnet Indicator)", template="plotly_dark")
            st.plotly_chart(fig4, use_container_width=True)

# =====================================================================
# MODE 3: MITIGATION & ALERTS
# =====================================================================
elif app_mode == "3. Mitigation & Alerts":
    st.header("🚨 Incident Response & Mitigations")
    
    if not os.path.exists(ALERTS_PATH):
        st.info("No active alerts found. Run the Detection Mode pipeline first to generate alerts.")
    else:
        with open(ALERTS_PATH, "r") as f:
            alerts = json.load(f)
            
        auto_result = auto_send_alert_email_if_new(alerts)
        if auto_result is not None:
            success, error_msg = auto_result
            if success:
                st.success(f"📩 Automated alert notification sent to {st.session_state.alert_recipient}.")
            else:
                st.error(f"❌ Automated alert email failed: {error_msg}")
        elif alerts:
            st.info(f"Alert cooldown active: repeated identical alerts will be suppressed for {st.session_state.alert_cooldown_minutes} minutes.")

        if not alerts:
            st.success("Traffic is clean. No anomalies detected.")
        else:
            st.error(f"⚠️ {len(alerts)} Anomalous Events Awaiting Action")

            # Action Buttons
            col_a1, col_a2 = st.columns([1, 3])
            with col_a1:
                if st.button("🛡️ Apply Automated Mitigations", type="primary"):
                    with st.spinner("Applying iptables rules and rate limits..."):
                        # Process alerts using mitigation.py engine
                        windows_path = os.path.join(BASELINE_DIR, "all_monitoring_windows.csv")
                        mitigation_engine.process_alerts_file(ALERTS_PATH, windows_path)
                        st.success("✅ Firewall rules & token buckets applied successfully.")
                        
            with col_a2:
                st.write("**Live Alert Dispatcher**")
                
                # Text input for the TA-supplied address, pre-filled with yours
                target_email = st.text_input("Recipient Email", value="Example@gmail.com")
                
                if st.button("📨 Dispatch Live Email Alert", type="primary"):
                    with st.spinner(f"Sending email to {target_email}..."):
                        success, error_msg = send_real_email(target_email, alerts)
                        
                        if success:
                            st.success(f"✅ Email successfully delivered to {target_email} at {datetime.now().strftime('%H:%M:%S')}!")
                        else:
                            st.error(f"❌ Failed to send email: {error_msg}")
                            
            st.markdown("---")
            
            # Display Alerts and Suggested Rules (Requirement: Flag deviations, display scores, recommend actions)
            st.subheader("Detected Attacks & Suggested Firewall Rules")
            for i, al in enumerate(alerts[:20]): # Show top 20 to avoid massive DOM
                with st.expander(f"[{al['severity']}] {al['attack_type']} at {al.get('start_time', al.get('time_window', 'N/A'))} (Score: {al.get('peak_score', al.get('score', 'N/A'))})"):
                    col_dr1, col_dr2 = st.columns(2)
                    with col_dr1:
                        st.write("**Triggered Signals:**")
                        for sig in al['triggered_signals'].split('|'):
                            if sig: st.code(sig)
                        st.write("**Recommended Safeguard:**")
                        st.info(al['safeguard'])
                    with col_dr2:
                        st.write("**Rate Limiting Plan:**")
                        st.warning(al['mitigation'])
                        st.write("**Generated iptables Rule:**")
                        st.code(al['firewall_rule'], language="bash")
                        
            # Show Active Rules & Logs from Mitigation Engine
            st.markdown("---")
            st.subheader("📜 Mitigation Engine Logs")
            
            tab1, tab2 = st.tabs(["Active Firewall Rules (iptables)", "Action History Log"])
            
            with tab1:
                rules = mitigation_engine.get_active_rules()
                if rules:
                    st.dataframe(pd.DataFrame(rules)[["timestamp", "rule_type", "ip", "description", "command", "executed"]])
                else:
                    st.write("No firewall rules currently applied.")
                    
            with tab2:
                logs = mitigation_engine.get_mitigation_log()
                if logs:
                    st.dataframe(pd.DataFrame(logs))
                else:
                    st.write("No mitigation actions logged yet.")