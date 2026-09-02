#!/usr/bin/env python3
"""Reads results/*/*.json (one file per (implementation, security-level, n, t)
run) and writes results/summary.csv + results/summary.md.

Stdlib only — no third-party dependencies. See ../schema/SCHEMA.md for the
result schema and the non-comparability caveats reproduced at the top of the
generated summary.md.
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
SCHEMA_MD = ROOT / "schema" / "SCHEMA.md"

CSV_COLUMNS = [
    "implementation", "protocol_name", "security_label", "enc_scheme", "enc_modulus_bits",
    "curve_security_bits", "enc_security_bits", "overall_security_bits",
    "n", "t", "signers",
    "setup_mean_ms", "dkg_or_keygen_mean_ms", "sign_mean_ms", "sign_stddev_ms", "verify_mean_ms",
    "throughput_sig_per_sec",
    "bandwidth_total_bytes", "bandwidth_per_party_bytes",
    "sig_bytes", "ec_pubkey_bytes", "ec_share_bytes",
    "enc_pubkey_bytes", "enc_share_bytes", "enc_ciphertext_bytes",
    "all_signatures_valid", "git_commit", "notes",
]

# NIST SP 800-57 Part 1 Rev. 5, Table 2: symmetric-equivalent security level ->
# (minimum IFC/FFC modulus bits, minimum ECC group-order bits) required to
# reach that level. IFC/FFC covers RSA/DH-style factoring/discrete-log
# problems, which Paillier's security also reduces to.
_SECURITY_TIERS = [  # (bits, min_ifc_ffc_modulus_bits, min_ecc_order_bits)
    (256, 15360, 512),
    (192, 7680, 384),
    (128, 3072, 256),
    (112, 2048, 224),
    (80, 1024, 160),
]

# secp256k1's group order is a 256-bit value (~2^256).
_SECP256K1_ORDER_BITS = 256


def _ifc_ffc_security_bits(modulus_bits):
    if modulus_bits is None:
        return None
    for bits, min_modulus, _ in _SECURITY_TIERS:
        if modulus_bits >= min_modulus:
            return bits
    return 0


def _ecc_security_bits(order_bits):
    for bits, _, min_order in _SECURITY_TIERS:
        if order_bits >= min_order:
            return bits
    return 0


def security_bits(r):
    """(curve_bits, enc_bits, overall_bits) for one result row, per NIST SP
    800-57's symmetric-equivalence tiers.

    tr-ecdsa parameterizes both its EC curve and its CL-HSM group directly
    from the requested security level (see GroupParams::Impl in the TR-ECDSA
    repo: `ec_group(sec_level)` and `cl_pp` are both built from the same
    `sec_level`) -- the two components are matched by construction, so the
    label already *is* the overall bit strength; no lookup needed.

    tss-lib is fixed to secp256k1 (a 256-bit curve -> 128-bit tier) paired
    with a static Paillier-2048 modulus (-> 112-bit tier) -- the two
    components are NOT matched, so the overall strength is capped by the
    weaker one (min), not the label "secp256k1" the schema otherwise reports.
    """
    impl = r["implementation"]
    if impl == "tr-ecdsa":
        bits = int(r["security"]["label"])
        return bits, bits, bits
    if impl == "tss-lib":
        curve_bits = _ecc_security_bits(_SECP256K1_ORDER_BITS)
        enc_bits = _ifc_ffc_security_bits(r["security"]["enc_modulus_bits"])
        overall = None if enc_bits is None else min(curve_bits, enc_bits)
        return curve_bits, enc_bits, overall
    return None, None, None


def load_results():
    rows = []
    for impl_dir in ("tr-ecdsa", "tss-lib"):
        for f in sorted((RESULTS / impl_dir).glob("*.json")):
            try:
                rows.append(json.loads(f.read_text()))
            except (json.JSONDecodeError, OSError) as e:
                print(f"skipping {f}: {e}", file=sys.stderr)
    return rows


def stat_or_none(d, key, subkey="mean"):
    v = d.get(key)
    return None if v is None else v.get(subkey)


def to_csv_row(r):
    t = r["timing_ms"]
    curve_bits, enc_bits, overall_bits = security_bits(r)
    return {
        "implementation": r["implementation"],
        "protocol_name": r["protocol_name"],
        "security_label": r["security"]["label"],
        "enc_scheme": r["security"]["enc_scheme"],
        "enc_modulus_bits": r["security"]["enc_modulus_bits"],
        "curve_security_bits": curve_bits,
        "enc_security_bits": enc_bits,
        "overall_security_bits": overall_bits,
        "n": r["params"]["n"],
        "t": r["params"]["t"],
        "signers": r["params"]["signers"],
        "setup_mean_ms": stat_or_none(t, "setup"),
        "dkg_or_keygen_mean_ms": stat_or_none(t, "dkg_or_keygen"),
        "sign_mean_ms": stat_or_none(t, "sign"),
        "sign_stddev_ms": stat_or_none(t, "sign", "stddev"),
        "verify_mean_ms": stat_or_none(t, "verify"),
        "throughput_sig_per_sec": r["throughput_sig_per_sec"],
        "bandwidth_total_bytes": r["bandwidth_bytes"]["total"],
        "bandwidth_per_party_bytes": r["bandwidth_bytes"]["per_party"],
        "sig_bytes": r["object_sizes_bytes"]["signature"],
        "ec_pubkey_bytes": r["object_sizes_bytes"]["ec_public_key"],
        "ec_share_bytes": r["object_sizes_bytes"]["ec_key_share"],
        "enc_pubkey_bytes": r["object_sizes_bytes"]["enc_public_key"],
        "enc_share_bytes": r["object_sizes_bytes"]["enc_key_share"],
        "enc_ciphertext_bytes": r["object_sizes_bytes"]["enc_ciphertext"],
        "all_signatures_valid": r["correctness"]["all_signatures_valid"],
        "git_commit": r["git_commit"],
        "notes": r["notes"],
    }


def write_csv(rows, path):
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow(to_csv_row(r))


def fmt(v, digits=1):
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (int, float)):
        return f"{v:,.{digits}f}"
    return str(v)


def caveats_section():
    if not SCHEMA_MD.exists():
        return ""
    text = SCHEMA_MD.read_text()
    marker = "## Non-comparability caveats"
    idx = text.find(marker)
    if idx == -1:
        return ""
    return text[idx:].strip()


def write_markdown(rows, path):
    # Group by (n, t) but keep every row within a group — tr-ecdsa contributes
    # multiple rows per (n, t), one per security level swept; keying on impl
    # alone would silently drop all but the last-loaded level (a real bug we
    # hit on the first full-grid run: only the 128-bit row survived).
    by_nt = {}
    for r in rows:
        key = (r["params"]["n"], r["params"]["t"])
        by_nt.setdefault(key, []).append(r)

    def group_rows(n, t):
        return sorted(by_nt[(n, t)], key=lambda r: (r["implementation"], r["security"]["label"]))

    lines = []
    lines.append("# Threshold-signature evaluation: comparative results\n")
    lines.append(
        "Generated by aggregator/aggregate.py from results/tr-ecdsa/*.json and "
        "results/tss-lib/*.json. **Read the caveats at the bottom before comparing "
        "any two rows** — the two implementations run genuinely different protocols.\n"
    )

    lines.append("## Timing & throughput\n")
    lines.append("| n | t | Impl | SecLvl | Overall bits | Setup (ms) | DKG/Keygen (ms) | Sign (ms) | ±σ (ms) | "
                  "Verify (ms) | Throughput (sig/s) |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for (n, t) in sorted(by_nt):
        for r in group_rows(n, t):
            c = to_csv_row(r)
            lines.append(
                f"| {n} | {t} | {c['implementation']} | {c['security_label']} | "
                f"{fmt(c['overall_security_bits'], 0)} | "
                f"{fmt(c['setup_mean_ms'])} | "
                f"{fmt(c['dkg_or_keygen_mean_ms'])} | {fmt(c['sign_mean_ms'])} | "
                f"{fmt(c['sign_stddev_ms'])} | {fmt(c['verify_mean_ms'], 3)} | "
                f"{fmt(c['throughput_sig_per_sec'], 2)} |"
            )

    lines.append("\n## Security strength (NIST SP 800-57 equivalence)\n")
    lines.append(
        "`Overall bits` is `min(curve bits, encryption-modulus bits)`, not the raw "
        "`security.label`. tr-ecdsa scales its EC curve and its CL-HSM group together "
        "from the same requested level, so its two components always match. tss-lib is "
        "fixed to secp256k1 (a 256-bit curve, 128-bit tier) paired with a static "
        "Paillier-2048 modulus (112-bit tier per the IFC/FFC table) — a mismatched pair, "
        "so its real-world strength is capped at 112 bits regardless of the curve.\n"
    )
    lines.append("| Impl | SecLvl | Curve bits | Enc bits | Overall bits |")
    lines.append("|---|---|---|---|---|")
    seen = set()
    for (n, t) in sorted(by_nt):
        for r in group_rows(n, t):
            key = (r["implementation"], r["security"]["label"])
            if key in seen:
                continue
            seen.add(key)
            c = to_csv_row(r)
            lines.append(
                f"| {c['implementation']} | {c['security_label']} | "
                f"{fmt(c['curve_security_bits'], 0)} | {fmt(c['enc_security_bits'], 0)} | "
                f"{fmt(c['overall_security_bits'], 0)} |"
            )

    lines.append("\n## Bandwidth (one signing operation)\n")
    lines.append("| n | t | Impl | SecLvl | Total (B) | Per-party (B) |")
    lines.append("|---|---|---|---|---|---|")
    for (n, t) in sorted(by_nt):
        for r in group_rows(n, t):
            c = to_csv_row(r)
            lines.append(
                f"| {n} | {t} | {c['implementation']} | {c['security_label']} | "
                f"{fmt(c['bandwidth_total_bytes'], 0)} | "
                f"{fmt(c['bandwidth_per_party_bytes'], 0)} |"
            )

    lines.append("\n## Object sizes (bytes)\n")
    lines.append("| n | t | Impl | SecLvl | Sig | EC PK | EC share | Enc PK | Enc share | Enc ctext |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for (n, t) in sorted(by_nt):
        for r in group_rows(n, t):
            c = to_csv_row(r)
            lines.append(
                f"| {n} | {t} | {c['implementation']} | {c['security_label']} | "
                f"{fmt(c['sig_bytes'], 0)} | {fmt(c['ec_pubkey_bytes'], 0)} | "
                f"{fmt(c['ec_share_bytes'], 0)} | {fmt(c['enc_pubkey_bytes'], 0)} | "
                f"{fmt(c['enc_share_bytes'], 0)} | {fmt(c['enc_ciphertext_bytes'], 0)} |"
            )

    lines.append("\n## Correctness\n")
    lines.append("| n | t | Impl | SecLvl | All signatures valid |")
    lines.append("|---|---|---|---|---|")
    for (n, t) in sorted(by_nt):
        for r in group_rows(n, t):
            lines.append(
                f"| {n} | {t} | {r['implementation']} | {r['security']['label']} | "
                f"{fmt(r['correctness']['all_signatures_valid'])} |"
            )

    lines.append("\n---\n")
    lines.append(caveats_section())
    lines.append("")

    path.write_text("\n".join(lines))


def main():
    rows = load_results()
    if not rows:
        print("no result files found under results/tr-ecdsa or results/tss-lib", file=sys.stderr)
        sys.exit(1)
    write_csv(rows, RESULTS / "summary.csv")
    write_markdown(rows, RESULTS / "summary.md")
    print(f"aggregated {len(rows)} result file(s) -> results/summary.csv, results/summary.md")


if __name__ == "__main__":
    main()
