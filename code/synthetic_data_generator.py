#!/usr/bin/env python3
"""
synthetic_edr_notables.py
Generate 90 days of synthetic “EDR passthrough” notable events
and write them to CSV.  Edit the CONFIG section or any helper
functions to quickly change volumes, field pools, or behaviour.

Usage
-----
$ python synthetic_edr_notables.py          # writes notables.csv
$ python synthetic_edr_notables.py 50000    # 50 k rows → out.csv
"""

from __future__ import annotations
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
import itertools
import ipaddress
import pandas as pd

# ── CONFIG ────────────────────────────────────────────────────────────────────
ROWS_DEFAULT           = 20_000          # baseline # of rows to emit
PROOF_DUPLICATE_RATIO  = 0.05            # pct. rows that are perfect dupes
CSV_OUT                = Path("notables.csv")

SRC_NET                = ipaddress.ip_network("10.0.0.0/16")
DEST_NET               = ipaddress.ip_network("192.168.0.0/16")
SIGNATURES             = [
    "EICAR-TEST-FILE", "Meterpreter Beacon", "Cobalt Strike Loader",
    "Unknown Hash Hit", "Suspicious PowerShell", "Ransomware Behaviour"
]
CATEGORIES             = ["malware", "command-and-control", "lateral-movement",
                          "priv-esc", "persistence", "exfiltration"]
FILENAMES              = [
    "calc.exe", "svchost.exe", "powershell.exe", "runme.tmp",
    "install.ps1", "invoice.docx", "setup.msi"
]
SEVERITIES             = ["low", "medium", "high", "critical"]
USERS                  = [f"CORP\\user{i:03}" for i in range(1, 201)]

STATUS_WEIGHTS = {
    "closed without escalation": 0.8,
    "closed with escalation":    0.2,
}
# ──────────────────────────────────────────────────────────────────────────────


def random_ip(net: ipaddress.IPv4Network) -> str:
    """Return a random IPv4 address inside *net* (skip .0 & .255)."""
    host_int = random.randint(1, net.num_addresses - 2)
    return str(net[host_int])


def synth_row(day_offset: int) -> dict[str, str]:
    """Return one synthetic notable dict."""
    event_time = (datetime.today() - timedelta(days=day_offset)).isoformat()
    return {
        "_time":        event_time,
        "src":          random_ip(SRC_NET),
        "dest":         random_ip(DEST_NET),
        "signature":    random.choice(SIGNATURES),
        "category":     random.choice(CATEGORIES),
        "file_name":    random.choice(FILENAMES),
        "severity":     random.choices(SEVERITIES, weights=[4, 4, 2, 1])[0],
        "user":         random.choice(USERS),
        "status_label": random.choices(list(STATUS_WEIGHTS),
                                       weights=STATUS_WEIGHTS.values())[0],
    }


def generate_notables(rows: int = ROWS_DEFAULT) -> pd.DataFrame:
    """
    Build *rows* synthetic events spanning the last 90 days.
    A small fraction (PROOF_DUPLICATE_RATIO) will be exact duplicates
    with status “closed without escalation” — demonstrable tuning targets.
    """
    per_day = rows // 90 or 1
    remainder = rows - per_day * 90

    # Generate non-duplicate set
    records: list[dict] = []
    for offset in range(90):               # loop over days
        for _ in range(per_day):           # fixed rows per day
            records.append(synth_row(offset))

    # add the remainder
    for _ in range(remainder):
        records.append(synth_row(day_offset=random.randint(0, 89)))

    df = pd.DataFrame(records)

    # Inject perfect duplicates flagged as “closed without escalation”
    dupe_count = int(rows * PROOF_DUPLICATE_RATIO)
    if dupe_count:
        dupe_sample = df.sample(dupe_count).copy()
        dupe_sample["status_label"] = "closed without escalation"
        df = pd.concat([df, dupe_sample], ignore_index=True)

    return df.sample(frac=1).reset_index(drop=True)  # shuffle


def main() -> None:
    total_rows = int(sys.argv[1]) if len(sys.argv) > 1 else ROWS_DEFAULT
    df = generate_notables(total_rows)
    out = CSV_OUT if len(sys.argv) <= 2 else Path(sys.argv[2])
    df.to_csv(out, index=False)
    print(f"[+] Wrote {len(df):,} notables → {out}")


if __name__ == "__main__":
    main()