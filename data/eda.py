"""
eda_baseline.py
================
Exploratory Data Analysis for the CIC-IDS Friday DDoS dataset.

Produces 6 figures saved as PNG files:
  1. Label distribution (how many BENIGN vs attack flows)
  2. Key feature distributions — BENIGN only (histograms)
  3. BENIGN vs ATTACK side-by-side box plots
  4. Feature correlation heatmap — BENIGN traffic
  5. Time-series: traffic rates over time
  6. Protocol flag comparison: BENIGN vs ATTACK

Run:
    python eda_baseline.py <path_to_csv>
    python eda_baseline.py Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
"""

import sys
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")               # no display needed — saves to file
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.ticker import FuncFormatter
import os

warnings.filterwarnings("ignore")

# ── Style ──────────────────────────────────────────────────────────────────
DARK_BG    = "#0d1117"
PANEL_BG   = "#161b22"
ACCENT     = "#58a6ff"
GREEN      = "#3fb950"
RED        = "#f85149"
YELLOW     = "#d29922"
PURPLE     = "#bc8cff"
TEXT       = "#e6edf3"
SUBTEXT    = "#8b949e"
GRID       = "#21262d"

plt.rcParams.update({
    "figure.facecolor":  DARK_BG,
    "axes.facecolor":    PANEL_BG,
    "axes.edgecolor":    GRID,
    "axes.labelcolor":   TEXT,
    "axes.titlecolor":   TEXT,
    "xtick.color":       SUBTEXT,
    "ytick.color":       SUBTEXT,
    "text.color":        TEXT,
    "grid.color":        GRID,
    "grid.linewidth":    0.6,
    "font.family":       "monospace",
    "figure.dpi":        130,
})

OUTPUT_DIR = "eda_outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def save(fig, name):
    path = os.path.join(OUTPUT_DIR, name)
    fig.savefig(path, bbox_inches="tight", facecolor=DARK_BG)
    plt.close(fig)
    print(f"  ✓  saved → {path}")


# ══════════════════════════════════════════════════════════════════════════════
# 1. LOAD
# ══════════════════════════════════════════════════════════════════════════════

def load(path: str) -> pd.DataFrame:
    print(f"\n[EDA] Loading {path} …")
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df["Label"] = df["Label"].str.strip()
    print(f"      Rows: {len(df):,}   Columns: {len(df.columns)}")
    print(f"      Labels found: {df['Label'].unique().tolist()}")
    return df


# ══════════════════════════════════════════════════════════════════════════════
# 2. BASIC STATS PRINTOUT
# ══════════════════════════════════════════════════════════════════════════════

def print_stats(df: pd.DataFrame):
    print("\n" + "═"*55)
    print("  DATASET OVERVIEW")
    print("═"*55)
    print(f"  Total flows      : {len(df):,}")

    counts = df["Label"].value_counts()
    for label, cnt in counts.items():
        pct = 100 * cnt / len(df)
        print(f"  {label:<20}: {cnt:>8,}  ({pct:.1f}%)")

    benign = df[df["Label"] == "BENIGN"]
    print(f"\n  ── BENIGN traffic statistics ──")

    key_features = [
        "Flow Bytes/s", "Flow Packets/s",
        "Packet Length Mean", "Flow Duration",
        "SYN Flag Count", "ACK Flag Count",
        "Total Fwd Packets", "Total Backward Packets",
    ]
    for feat in key_features:
        if feat not in benign.columns:
            continue
        col = benign[feat].dropna()
        print(f"\n  {feat}")
        print(f"    mean   = {col.mean():>14.2f}")
        print(f"    std    = {col.std():>14.2f}")
        print(f"    median = {col.median():>14.2f}")
        print(f"    p95    = {col.quantile(0.95):>14.2f}")
        print(f"    p99    = {col.quantile(0.99):>14.2f}")
        print(f"    max    = {col.max():>14.2f}")
    print("═"*55 + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 1 — Label Distribution
# ══════════════════════════════════════════════════════════════════════════════

def fig_label_distribution(df: pd.DataFrame):
    print("[EDA] Figure 1 — label distribution …")
    counts = df["Label"].value_counts()
    labels = counts.index.tolist()
    values = counts.values.tolist()

    colors = [GREEN if l == "BENIGN" else RED for l in labels]

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("Dataset Label Distribution", fontsize=15, color=TEXT,
                 fontweight="bold", y=1.02)

    # Bar chart
    ax = axes[0]
    bars = ax.barh(labels, values, color=colors, height=0.5, zorder=3)
    ax.set_xlabel("Number of Flows", color=SUBTEXT)
    ax.set_title("Flow Counts per Label", color=TEXT)
    ax.grid(axis="x", zorder=0)
    ax.set_axisbelow(True)
    for bar, val in zip(bars, values):
        ax.text(val + max(values)*0.01, bar.get_y() + bar.get_height()/2,
                f"{val:,}", va="center", color=TEXT, fontsize=9)

    # Pie chart
    ax2 = axes[1]
    wedges, texts, autotexts = ax2.pie(
        values, labels=labels, colors=colors,
        autopct="%1.1f%%", startangle=140,
        wedgeprops={"edgecolor": DARK_BG, "linewidth": 2},
        textprops={"color": TEXT},
    )
    for at in autotexts:
        at.set_fontsize(10)
        at.set_color(DARK_BG)
    ax2.set_title("Proportion of Labels", color=TEXT)
    ax2.set_facecolor(PANEL_BG)

    fig.tight_layout()
    save(fig, "1_label_distribution.png")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 2 — Key Feature Distributions (BENIGN only)
# ══════════════════════════════════════════════════════════════════════════════

def fig_feature_distributions(df: pd.DataFrame):
    print("[EDA] Figure 2 — BENIGN feature distributions …")
    benign = df[df["Label"] == "BENIGN"].copy()

    features = [
        ("Flow Bytes/s",        "Bytes/s",    ACCENT),
        ("Flow Packets/s",      "Packets/s",  PURPLE),
        ("Packet Length Mean",  "Bytes",      YELLOW),
        ("Flow Duration",       "μs",         GREEN),
        ("SYN Flag Count",      "Count",      RED),
        ("Total Fwd Packets",   "Packets",    "#ff9500"),
    ]
    features = [(f, u, c) for f, u, c in features if f in benign.columns]

    ncols = 3
    nrows = (len(features) + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(16, 4.5 * nrows))
    fig.suptitle("BENIGN Traffic — Feature Distributions",
                 fontsize=15, color=TEXT, fontweight="bold", y=1.01)
    axes = axes.flatten()

    for i, (feat, unit, color) in enumerate(features):
        ax = axes[i]
        data = benign[feat].dropna()

        # Cap at 99th percentile so extreme outliers don't squash the histogram
        cap = data.quantile(0.99)
        data_capped = data[data <= cap]

        ax.hist(data_capped, bins=60, color=color, alpha=0.85,
                edgecolor="none", zorder=3)

        # Mark mean and median
        mean_val   = data.mean()
        median_val = data.median()
        ymax = ax.get_ylim()[1]

        ax.axvline(mean_val,   color="white",  ls="--", lw=1.2,
                   label=f"mean={mean_val:.1f}")
        ax.axvline(median_val, color=YELLOW,   ls=":",  lw=1.2,
                   label=f"median={median_val:.1f}")

        ax.set_title(feat, color=TEXT, fontsize=9)
        ax.set_xlabel(unit, color=SUBTEXT, fontsize=8)
        ax.set_ylabel("Flows",  color=SUBTEXT, fontsize=8)
        ax.legend(fontsize=7, labelcolor=TEXT,
                  facecolor=PANEL_BG, edgecolor=GRID)
        ax.grid(axis="y", zorder=0)
        ax.set_axisbelow(True)

        # Annotation: total flows & std
        ax.text(0.97, 0.95,
                f"n={len(data):,}\nstd={data.std():.1f}",
                transform=ax.transAxes, ha="right", va="top",
                color=SUBTEXT, fontsize=7)

    # Hide any unused subplots
    for j in range(len(features), len(axes)):
        axes[j].set_visible(False)

    fig.tight_layout()
    save(fig, "2_benign_feature_distributions.png")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 3 — BENIGN vs ATTACK Box Plots
# ══════════════════════════════════════════════════════════════════════════════

def fig_boxplots_benign_vs_attack(df: pd.DataFrame):
    print("[EDA] Figure 3 — BENIGN vs ATTACK box plots …")

    features = [
        "Flow Bytes/s", "Flow Packets/s",
        "Packet Length Mean", "SYN Flag Count",
        "Flow Duration", "Total Fwd Packets",
    ]
    features = [f for f in features if f in df.columns]

    labels_present = df["Label"].unique().tolist()
    # We want BENIGN first, then everything else
    ordered = ["BENIGN"] + [l for l in labels_present if l != "BENIGN"]
    palette = [GREEN] + [RED] * (len(ordered) - 1)

    ncols = 3
    nrows = (len(features) + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(16, 5 * nrows))
    fig.suptitle("BENIGN vs ATTACK — Feature Comparison (Box Plots)",
                 fontsize=15, color=TEXT, fontweight="bold", y=1.01)
    axes = axes.flatten()

    for i, feat in enumerate(features):
        ax = axes[i]
        groups   = []
        gcolors  = []
        glabels  = []

        for lbl, col in zip(ordered, palette):
            subset = df[df["Label"] == lbl][feat].dropna()
            if subset.empty:
                continue
            # Cap at 99.5th percentile to keep boxes readable
            cap    = subset.quantile(0.995)
            groups.append(subset[subset <= cap].values)
            gcolors.append(col)
            glabels.append(lbl)

        bp = ax.boxplot(
            groups,
            patch_artist=True,
            medianprops={"color": "white", "linewidth": 2},
            whiskerprops={"color": SUBTEXT},
            capprops={"color": SUBTEXT},
            flierprops={"marker": ".", "markersize": 2,
                        "markerfacecolor": SUBTEXT, "alpha": 0.3},
        )
        for patch, color in zip(bp["boxes"], gcolors):
            patch.set_facecolor(color)
            patch.set_alpha(0.75)

        ax.set_xticklabels(glabels, fontsize=7, rotation=15)
        ax.set_title(feat, color=TEXT, fontsize=9)
        ax.set_ylabel("Value", color=SUBTEXT, fontsize=8)
        ax.grid(axis="y", zorder=0)
        ax.set_axisbelow(True)

    for j in range(len(features), len(axes)):
        axes[j].set_visible(False)

    fig.tight_layout()
    save(fig, "3_benign_vs_attack_boxplots.png")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 4 — Correlation Heatmap (BENIGN traffic)
# ══════════════════════════════════════════════════════════════════════════════

def fig_correlation_heatmap(df: pd.DataFrame):
    print("[EDA] Figure 4 — correlation heatmap (BENIGN) …")
    benign = df[df["Label"] == "BENIGN"].copy()

    features = [
        "Flow Bytes/s", "Flow Packets/s",
        "Fwd Packets/s", "Bwd Packets/s",
        "Packet Length Mean", "Packet Length Std",
        "Flow Duration", "Flow IAT Mean",
        "SYN Flag Count", "ACK Flag Count",
        "FIN Flag Count", "RST Flag Count",
        "Total Fwd Packets", "Total Backward Packets",
        "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    ]
    features = [f for f in features if f in benign.columns]

    corr = benign[features].dropna().corr()

    fig, ax = plt.subplots(figsize=(14, 11))
    fig.suptitle("Feature Correlation — BENIGN Traffic",
                 fontsize=14, color=TEXT, fontweight="bold")

    # Manual heatmap with imshow
    im = ax.imshow(corr.values, cmap="RdYlGn", vmin=-1, vmax=1,
                   aspect="auto")

    ax.set_xticks(range(len(features)))
    ax.set_yticks(range(len(features)))
    ax.set_xticklabels(features, rotation=45, ha="right", fontsize=7)
    ax.set_yticklabels(features, fontsize=7)

    # Annotate each cell
    for row in range(len(features)):
        for col in range(len(features)):
            val = corr.values[row, col]
            color = "black" if abs(val) > 0.5 else TEXT
            ax.text(col, row, f"{val:.2f}", ha="center", va="center",
                    fontsize=5.5, color=color)

    cbar = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    cbar.ax.tick_params(colors=SUBTEXT)
    cbar.set_label("Pearson r", color=SUBTEXT)

    fig.tight_layout()
    save(fig, "4_correlation_heatmap.png")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 5 — Time-Series Traffic Rates
# ══════════════════════════════════════════════════════════════════════════════

def fig_time_series(df: pd.DataFrame):
    print("[EDA] Figure 5 — time-series traffic rates …")

    if "Timestamp" not in df.columns:
        print("      (no Timestamp column — skipping)")
        return

    try:
        df = df.copy()
        df["_ts"] = pd.to_datetime(df["Timestamp"], format="mixed")
        df = df.sort_values("_ts").set_index("_ts")
    except Exception as e:
        print(f"      (timestamp parse failed: {e} — skipping)")
        return

    fig, axes = plt.subplots(3, 1, figsize=(16, 12), sharex=True)
    fig.suptitle("Traffic Over Time — All Labels",
                 fontsize=14, color=TEXT, fontweight="bold")

    # Panel A — Flow Bytes/s
    ax = axes[0]
    for lbl, color in [("BENIGN", GREEN)] + \
                      [(l, RED) for l in df["Label"].unique() if l != "BENIGN"]:
        sub = df[df["Label"] == lbl]
        if "Flow Bytes/s" not in sub.columns or sub.empty:
            continue
        resampled = sub["Flow Bytes/s"].resample("1s").mean().dropna()
        ax.plot(resampled.index, resampled.values,
                color=color, alpha=0.8, lw=0.8, label=lbl)
    ax.set_ylabel("Flow Bytes/s", color=SUBTEXT)
    ax.set_title("Bandwidth Rate", color=TEXT, fontsize=10)
    ax.legend(fontsize=8, facecolor=PANEL_BG, edgecolor=GRID,
              labelcolor=TEXT)
    ax.grid(True)

    # Panel B — Flow Packets/s
    ax = axes[1]
    for lbl, color in [("BENIGN", GREEN)] + \
                      [(l, ACCENT) for l in df["Label"].unique() if l != "BENIGN"]:
        sub = df[df["Label"] == lbl]
        if "Flow Packets/s" not in sub.columns or sub.empty:
            continue
        resampled = sub["Flow Packets/s"].resample("1s").mean().dropna()
        ax.plot(resampled.index, resampled.values,
                color=color, alpha=0.8, lw=0.8, label=lbl)
    ax.set_ylabel("Flow Packets/s", color=SUBTEXT)
    ax.set_title("Packet Rate", color=TEXT, fontsize=10)
    ax.legend(fontsize=8, facecolor=PANEL_BG, edgecolor=GRID,
              labelcolor=TEXT)
    ax.grid(True)

    # Panel C — SYN flag count
    ax = axes[2]
    for lbl, color in [("BENIGN", GREEN)] + \
                      [(l, RED) for l in df["Label"].unique() if l != "BENIGN"]:
        sub = df[df["Label"] == lbl]
        if "SYN Flag Count" not in sub.columns or sub.empty:
            continue
        resampled = sub["SYN Flag Count"].resample("1s").sum().dropna()
        ax.plot(resampled.index, resampled.values,
                color=color, alpha=0.8, lw=0.8, label=lbl)
    ax.set_ylabel("SYN Flags (sum/s)", color=SUBTEXT)
    ax.set_xlabel("Time", color=SUBTEXT)
    ax.set_title("SYN Flag Activity", color=TEXT, fontsize=10)
    ax.legend(fontsize=8, facecolor=PANEL_BG, edgecolor=GRID,
              labelcolor=TEXT)
    ax.grid(True)

    fig.autofmt_xdate()
    fig.tight_layout()
    save(fig, "5_time_series.png")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 6 — Protocol Flag Profile: BENIGN vs ATTACK
# ══════════════════════════════════════════════════════════════════════════════

def fig_flag_profile(df: pd.DataFrame):
    print("[EDA] Figure 6 — protocol flag profile …")

    flag_features = [
        "SYN Flag Count", "ACK Flag Count",
        "FIN Flag Count", "RST Flag Count",
        "PSH Flag Count", "URG Flag Count",
    ]
    flag_features = [f for f in flag_features if f in df.columns]

    labels_present = df["Label"].unique().tolist()
    ordered = ["BENIGN"] + [l for l in labels_present if l != "BENIGN"]
    palette = [GREEN] + [RED] * (len(ordered) - 1)

    # Compute mean flag count per label
    means = {}
    for lbl in ordered:
        sub = df[df["Label"] == lbl][flag_features].dropna()
        means[lbl] = sub.mean()

    x     = np.arange(len(flag_features))
    width = 0.8 / len(ordered)

    fig, ax = plt.subplots(figsize=(13, 6))
    fig.suptitle("Mean Protocol Flag Counts — BENIGN vs ATTACK",
                 fontsize=14, color=TEXT, fontweight="bold")

    for i, (lbl, color) in enumerate(zip(ordered, palette)):
        offset = (i - len(ordered)/2 + 0.5) * width
        bars = ax.bar(x + offset, means[lbl].values,
                      width=width * 0.9, color=color, alpha=0.85,
                      label=lbl, zorder=3)
        for bar in bars:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width()/2, h + 0.01,
                        f"{h:.2f}", ha="center", va="bottom",
                        fontsize=7, color=TEXT)

    ax.set_xticks(x)
    ax.set_xticklabels(flag_features, rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Mean Count per Flow", color=SUBTEXT)
    ax.legend(fontsize=9, facecolor=PANEL_BG, edgecolor=GRID,
              labelcolor=TEXT)
    ax.grid(axis="y", zorder=0)
    ax.set_axisbelow(True)

    fig.tight_layout()
    save(fig, "6_flag_profile.png")

def print_timestamp_counts(df: pd.DataFrame):
    print("[EDA] Unique timestamps and counts …")

    if "Timestamp" not in df.columns:
        print("      (no Timestamp column — skipping)")
        return

    try:
        df = df.copy()
        df["_ts"] = pd.to_datetime(df["Timestamp"], format="mixed")
    except Exception as e:
        print(f"      (timestamp parse failed: {e})")
        return

    # Count occurrences of each exact timestamp
    counts = df["_ts"].value_counts().sort_index()

    print(f"\nTotal unique timestamps: {len(counts)}\n")

    # Print first few (so your terminal doesn’t explode)
    print("First 20 timestamps:")
    print(counts.head(20))

    print("\nLast 20 timestamps:")
    print(counts.tail(20))

    # Optional: save full list to file
    counts.to_csv("eda_outputs/timestamp_counts.csv")
    print("\n  ✓ saved full timestamp counts → eda_outputs/timestamp_counts.csv")

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage: python eda_baseline.py <csv_path>")
        print("Example: python eda_baseline.py Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
        sys.exit(1)

    path = sys.argv[1]
    df   = load(path)

    print_stats(df)

    print_timestamp_counts(df)
    
    print("\n[EDA] Generating figures …")
    fig_label_distribution(df)
    fig_feature_distributions(df)
    fig_boxplots_benign_vs_attack(df)
    fig_correlation_heatmap(df)
    fig_time_series(df)
    fig_flag_profile(df)

    print(f"\n[EDA] All done. Check the '{OUTPUT_DIR}/' folder for your plots.")
    print("  1_label_distribution.png         — how many BENIGN vs attack flows")
    print("  2_benign_feature_distributions.png — histograms of key features")
    print("  3_benign_vs_attack_boxplots.png  — side-by-side comparison")
    print("  4_correlation_heatmap.png        — which features move together")
    print("  5_time_series.png                — traffic rates over time")
    print("  6_flag_profile.png               — SYN/ACK/FIN/RST per label")


if __name__ == "__main__":
    main()