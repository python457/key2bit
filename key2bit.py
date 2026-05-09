#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Key2Bit v2.1
Cryptographic key classification, analysis and optimization CLI utility.
Licensed Under Kenobi.
"""

import argparse
import base64
import csv
import hashlib
import json
import math
import pydoc
import secrets
import string
import time
from pathlib import Path

VERSION = "2.1"
LICENSE = "Kenobi"

DEATH_STAR = r"""
      ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
      ⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠋⠉⠁⠀⠀⠀⠀⠈⢉⣙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
      ⣿⣿⣿⣿⣿⡿⠋⠁⠀⠀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⢻⣿⣿⣿⣿⣿⣿
      ⣿⣿⣿⣿⠏⠀⠀⠀⣴⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⢠⣤⣤⣼⣿⣿⣿⣿⣿
      ⣿⣿⣿⠃⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿
      ⣿⣿⡏⠀⠀⠀⠀⠘⢿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⣀⣠⣤⣾⣿⣿⣿⣿⣿
      ⣿⣿⠁⠀⠀⠀⠀⠀⠀⠉⠛⠛⠋⠁⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠉⣿⣿
      ⣿⣿⠶⣶⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣶⠶⣿⣿
      ⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⣀⣀⣿⣿
      ⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⣤⣴⣶⣿⣿⣿⣿
      ⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠛⠛⢻⣿⣿⣿⣿
      ⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿
      ⣿⣿⣿⣿⣿⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢻⣿⣿⣿⣿⣿⣿⣿⣿
      ⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣄⣀⡀⠀⠀⠀⠀⣠⣶⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿
      ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
"""

TITLE = r"""
 ██╗  ██╗███████╗██╗   ██╗██████╗ ██████╗ ██╗████████╗
 ██║ ██╔╝██╔════╝╚██╗ ██╔╝╚════██╗██╔══██╗██║╚══██╔══╝
 █████╔╝ █████╗   ╚████╔╝  █████╔╝██████╔╝██║   ██║
 ██╔═██╗ ██╔══╝    ╚██╔╝  ██╔═══╝ ██╔══██╗██║   ██║
 ██║  ██╗███████╗   ██║   ███████╗██████╔╝██║   ██║
 ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═════╝ ╚═╝   ╚═╝
"""

MAIN_SCREEN = f"""
{DEATH_STAR}
{TITLE}
                  Key2Bit v{VERSION} | Licensed Under {LICENSE}
              Cryptographic Key Classification & Optimization

+--------------------------------------------------------------------------+
| Version  : {VERSION:<60} |
| License  : {LICENSE:<60} |
| Platform : Kali Linux / Linux CLI                                         |
+--------------------------------------------------------------------------+

[+] Main commands

  generate    - Generate cryptographic style key
  analyze     - Analyze one key without showing banner
  classify    - Classify keys from file
  scan        - Detect weak keys from file
  optimize    - Recommend optimized crypto profile
  benchmark   - Run lightweight benchmark
  report      - Export CSV/JSON report
  demo        - Run demo mode
  deathstar   - Show Death Star console
  --version   - Show version

[+] Examples

  key2bit generate --type aes --bits 256
  key2bit generate --type random --length 32
  key2bit analyze --key "A7f9@demoKey2026!"
  key2bit classify --file keys.txt
  key2bit scan --file keys.txt
  key2bit optimize --environment bank --target 384
  key2bit benchmark --rounds 10000
  key2bit report --file keys.txt --output report.csv --format csv
  key2bit report --file keys.txt --output report.json --format json

Tip: This main screen opens in a pager. Use arrows/PageUp/PageDown to scroll and q to exit.
"""

def show_main_screen():
    pydoc.pager(MAIN_SCREEN)

def entropy_bits_per_char(value: str) -> float:
    if not value:
        return 0.0
    freq = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def charset_size(value: str) -> int:
    size = 0
    if any(c.islower() for c in value):
        size += 26
    if any(c.isupper() for c in value):
        size += 26
    if any(c.isdigit() for c in value):
        size += 10
    if any(c in string.punctuation for c in value):
        size += len(string.punctuation)
    return max(size, 1)

def estimate_strength(value: str) -> dict:
    length = len(value)
    has_lower = any(c.islower() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_digit = any(c.isdigit() for c in value)
    has_symbol = any(c in string.punctuation for c in value)
    repeated = length != len(set(value)) and length > 0
    entropy_char = entropy_bits_per_char(value)
    estimated_search_bits = math.log2(charset_size(value)) * length if length else 0

    score = 0
    if length >= 12: score += 20
    if length >= 16: score += 15
    if length >= 24: score += 15
    if has_lower: score += 10
    if has_upper: score += 10
    if has_digit: score += 10
    if has_symbol: score += 10
    if entropy_char >= 3.2: score += 10
    if repeated: score -= 8
    if any(p in value.lower() for p in ["password", "admin", "qwerty", "123456", "key", "test"]):
        score -= 20

    score = max(0, min(100, score))
    if score < 35:
        level, cls = "WEAK", "low security key"
    elif score < 60:
        level, cls = "MEDIUM", "standard key"
    elif score < 80:
        level, cls = "STRONG", "secure key"
    else:
        level, cls = "VERY STRONG", "optimized secure key"

    recommendations = []
    if length < 16:
        recommendations.append("Increase key length to at least 16 characters.")
    if not has_upper:
        recommendations.append("Add uppercase characters.")
    if not has_digit:
        recommendations.append("Add digits.")
    if not has_symbol:
        recommendations.append("Add special symbols.")
    if repeated:
        recommendations.append("Avoid repeated characters and simple patterns.")
    if not recommendations:
        recommendations.append("Key quality is acceptable for general usage.")

    return {
        "key": value,
        "length": length,
        "score": score,
        "level": level,
        "classification": cls,
        "entropy_bits_per_char": round(entropy_char, 3),
        "estimated_search_bits": round(estimated_search_bits, 2),
        "recommendations": recommendations,
    }

def generate_key(args):
    if args.type == "aes":
        bits = args.bits
        if bits not in [128, 192, 256]:
            print("[!] AES supports 128, 192, or 256 bits.")
            return
        raw = secrets.token_bytes(bits // 8)
        key = raw.hex() if args.format == "hex" else base64.urlsafe_b64encode(raw).decode().rstrip("=")
    elif args.type == "rsa":
        bits = args.bits if args.bits else 2048
        seed = secrets.token_hex(64)
        key = f"RSA-{bits}-SIM-{hashlib.sha256(seed.encode()).hexdigest()}"
    elif args.type == "ecc":
        bits = args.bits if args.bits else 256
        seed = secrets.token_hex(48)
        key = f"ECC-{bits}-SIM-{hashlib.sha256(seed.encode()).hexdigest()[:64]}"
    else:
        alphabet = string.ascii_letters + string.digits + string.punctuation
        key = "".join(secrets.choice(alphabet) for _ in range(args.length))
    print("[+] Generated Key")
    print("-" * 72)
    print(f"Type    : {args.type.upper()}")
    print(f"Version : {VERSION}")
    print(f"Key     : {key}")

def analyze_key(args):
    result = estimate_strength(args.key)
    print("[+] Key Analysis")
    print("-" * 72)
    for k in ["length", "score", "level", "classification", "entropy_bits_per_char", "estimated_search_bits"]:
        print(f"{k:24}: {result[k]}")
    print("\n[+] Recommendations")
    for rec in result["recommendations"]:
        print(f"  - {rec}")

def classify_file(args):
    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {args.file}")
        return
    keys = [line.strip() for line in path.read_text(errors="ignore").splitlines() if line.strip()]
    print("[+] Classification Result")
    print("-" * 92)
    print(f"{'No':<5}{'Length':<10}{'Score':<10}{'Level':<16}{'Classification':<24}Key Preview")
    print("-" * 92)
    for i, key in enumerate(keys, 1):
        r = estimate_strength(key)
        preview = key[:18] + ("..." if len(key) > 18 else "")
        print(f"{i:<5}{r['length']:<10}{r['score']:<10}{r['level']:<16}{r['classification']:<24}{preview}")

def scan_file(args):
    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {args.file}")
        return
    keys = [line.strip() for line in path.read_text(errors="ignore").splitlines() if line.strip()]
    weak = []
    for key in keys:
        r = estimate_strength(key)
        if r["level"] in ["WEAK", "MEDIUM"]:
            weak.append(r)
    print("[+] Weak Key Scan")
    print("-" * 72)
    print(f"Total keys scanned : {len(keys)}")
    print(f"Weak/medium found  : {len(weak)}")
    for r in weak:
        print(f"\nKey preview: {r['key'][:20]}{'...' if len(r['key']) > 20 else ''}")
        print(f"Level      : {r['level']}")
        print(f"Score      : {r['score']}")
        print(f"Advice     : {r['recommendations'][0]}")

def optimize(args):
    env = args.environment.lower()
    target = args.target
    profiles = {
        "mobile": ("ECC-256 + AES-128", "low resource usage with strong security"),
        "server": ("AES-256 + RSA-3072", "high security for server-side systems"),
        "iot": ("ECC-256 + AES-128", "balanced for limited CPU and memory"),
        "bank": ("AES-256 + RSA-4096 or ECC-384", "maximum protection for sensitive financial data"),
        "general": ("AES-256", "simple and strong default configuration"),
    }
    recommended, reason = profiles.get(env, profiles["general"])
    if target:
        if target <= 128:
            recommended, reason = "AES-128 or ECC-256", "target prioritizes speed and acceptable baseline security"
        elif target <= 256:
            recommended, reason = "AES-256 or ECC-256", "target balances strong security and performance"
        else:
            recommended, reason = "RSA-4096 or ECC-384", "target prioritizes stronger long-term protection"
    print("[+] Optimization Recommendation")
    print("-" * 72)
    print(f"Environment : {env}")
    print(f"Target bits : {target if target else 'auto'}")
    print(f"Recommended : {recommended}")
    print(f"Reason      : {reason}")
    print("\n[+] Practical Advice")
    print("  - Rotate keys periodically.")
    print("  - Avoid storing keys in plain text.")
    print("  - Use stronger profiles for long-term confidential data.")

def benchmark(args):
    rounds = args.rounds
    tests = [
        ("AES-128 simulation", 16),
        ("AES-256 simulation", 32),
        ("ECC-256 simulation", 32),
        ("RSA-2048 simulation", 256),
        ("RSA-4096 simulation", 512),
    ]
    print("[+] Benchmark")
    print("-" * 72)
    print(f"{'Test':<24}{'Rounds':<12}{'Time(sec)':<14}{'Ops/sec'}")
    print("-" * 72)
    for name, size in tests:
        start = time.perf_counter()
        for _ in range(rounds):
            data = secrets.token_bytes(size)
            hashlib.sha256(data).digest()
        elapsed = time.perf_counter() - start
        ops = rounds / elapsed if elapsed > 0 else 0
        print(f"{name:<24}{rounds:<12}{elapsed:<14.5f}{ops:.2f}")

def report(args):
    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {args.file}")
        return
    keys = [line.strip() for line in path.read_text(errors="ignore").splitlines() if line.strip()]
    data = [estimate_strength(k) for k in keys]
    out = Path(args.output)
    if args.format == "json":
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    else:
        with out.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["key", "length", "score", "level", "classification", "entropy_bits_per_char", "estimated_search_bits"])
            writer.writeheader()
            for r in data:
                writer.writerow({k: r[k] for k in writer.fieldnames})
    print(f"[+] Report saved: {out}")

def demo(args):
    print("[+] Demo Mode")
    print("-" * 72)
    samples = ["12345678", "adminKey2024", "A7f9@demoKey2026!", secrets.token_urlsafe(32)]
    for key in samples:
        r = estimate_strength(key)
        print(f"{key[:28]:<32} -> {r['level']:<12} score={r['score']}")

def deathstar(args):
    pydoc.pager(DEATH_STAR + TITLE + f"\nKey2Bit v{VERSION} | Licensed Under {LICENSE}\n\nThe key is strong with this one.\nMode: Death Star console online.\n")

def build_parser():
    parser = argparse.ArgumentParser(prog="key2bit", add_help=True)
    parser.add_argument("--version", action="version", version=f"Key2Bit {VERSION} | License: {LICENSE}")
    sub = parser.add_subparsers(dest="command")
    p = sub.add_parser("generate")
    p.add_argument("--type", choices=["random", "aes", "rsa", "ecc"], default="random")
    p.add_argument("--length", type=int, default=32)
    p.add_argument("--bits", type=int, default=None)
    p.add_argument("--format", choices=["hex", "base64"], default="hex")
    p.set_defaults(func=generate_key)
    p = sub.add_parser("analyze")
    p.add_argument("--key", required=True)
    p.set_defaults(func=analyze_key)
    p = sub.add_parser("classify")
    p.add_argument("--file", required=True)
    p.set_defaults(func=classify_file)
    p = sub.add_parser("scan")
    p.add_argument("--file", required=True)
    p.set_defaults(func=scan_file)
    p = sub.add_parser("optimize")
    p.add_argument("--environment", default="general")
    p.add_argument("--target", type=int, default=None)
    p.set_defaults(func=optimize)
    p = sub.add_parser("benchmark")
    p.add_argument("--rounds", type=int, default=50000)
    p.set_defaults(func=benchmark)
    p = sub.add_parser("report")
    p.add_argument("--file", required=True)
    p.add_argument("--output", default="key2bit_report.csv")
    p.add_argument("--format", choices=["csv", "json"], default="csv")
    p.set_defaults(func=report)
    p = sub.add_parser("demo")
    p.set_defaults(func=demo)
    p = sub.add_parser("deathstar")
    p.set_defaults(func=deathstar)
    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        show_main_screen()

if __name__ == "__main__":
    main()
