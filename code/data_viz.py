#!/usr/bin/env python3
"""
summarize_noise.py
Summarise duplicate EDR passthrough alerts that were *all*
closed without escalation, highlighting easy suppression targets.

Usage
-----
$ python summarize_noise.py                  # reads notables.csv
$ python summarize_noise.py mydata.csv 60 8  # custom CSV, 60-day window,
                                             # show clusters ≥8 alerts
"""
from __future__ import annotations
import sys
from datetime import datetime, timedelta

import pandas as pd

# ── Defaults (override via CLI) ───────────────────────────────────────────────
CSV_IN         = "/Users/lukewescott/Documents/dev_link/automate-splunk-suppression/data/synthetic_data/notables.csv"
LOOKBACK_DAYS  = 30           # rolling window
MIN_CLUSTER    = 5            # min alerts to consider “noisy”
GROUP_COLS = ["src", "dest", "user", "signature", "severity"]
# ──────────────────────────────────────────────────────────────────────────────

def parse_cli() -> None:
    """Allow simple overrides: csv, days, min_cluster."""
    global CSV_IN, LOOKBACK_DAYS, MIN_CLUSTER
    if len(sys.argv) > 1:
        CSV_IN = sys.argv[1]
    if len(sys.argv) > 2:
        LOOKBACK_DAYS = int(sys.argv[2])
    if len(sys.argv) > 3:
        MIN_CLUSTER = int(sys.argv[3])

def main() -> None:
    parse_cli()

    df = pd.read_csv(CSV_IN, parse_dates=["_time"])

    # 1) focus on last N days & non-escalated alerts
    cutoff = datetime.today() - timedelta(days=LOOKBACK_DAYS)
    filt = (df["_time"] >= cutoff) & (df["status_label"] == "closed without escalation")
    focus = df.loc[filt, GROUP_COLS]

    if focus.empty:
        print("No matching alerts in window; nothing to report.")
        sys.exit()

    # 2) group by the repetitive dimensions → count
    summary = (focus
               .value_counts()
               .reset_index(name="alert_count")      # pandas ≥1.4
               .query("alert_count >= @MIN_CLUSTER")
               .sort_values("alert_count", ascending=False))

    if summary.empty:
        print(f"No clusters ≥ {MIN_CLUSTER} alerts. Try lowering MIN_CLUSTER.")
        sys.exit()

    # 3) prettify: use tabulate-style padding for console readability
    print("\n⊕ Duplicate alert clusters (non-escalated) ⊕\n")
    print(summary.to_string(index=False))

if __name__ == "__main__":
    main()