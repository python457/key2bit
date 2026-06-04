#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Key2Bit v4.0
Cryptographic key generation, classification, S-AES subkey analysis and optimization CLI utility.
Licensed Under MIT.
"""

import argparse
import csv
import hashlib
import json
import math
import os
import random
import secrets
import string
import sys
import time
from pathlib import Path

VERSION = "4.0"
LICENSE = "MIT"

TITLE = r"""
 ██╗  ██╗███████╗██╗   ██╗██████╗ ██████╗ ██╗████████╗
 ██║ ██╔╝██╔════╝╚██╗ ██╔╝╚════██╗██╔══██╗██║╚══██╔══╝
 █████╔╝ █████╗   ╚████╔╝  █████╔╝██████╔╝██║   ██║
 ██╔═██╗ ██╔══╝    ╚██╔╝  ██╔═══╝ ██╔══██╗██║   ██║
 ██║  ██╗███████╗   ██║   ███████╗██████╔╝██║   ██║
 ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═════╝ ╚═╝   ╚═╝
"""

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



WEAK_WORDS = [
    "password", "qwerty", "admin", "root", "letmein", "welcome", "dragon",
    "football", "monkey", "abc123", "123456", "111111", "654321", "azerty",
]

CHARSETS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()-_=+[]{};:,.?/",
}


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def charset_size(key: str) -> int:
    size = 0
    if any(c.islower() for c in key):
        size += 26
    if any(c.isupper() for c in key):
        size += 26
    if any(c.isdigit() for c in key):
        size += 10
    if any(c in CHARSETS["symbols"] for c in key):
        size += len(CHARSETS["symbols"])
    return max(size, 1)


def repeated_ratio(key: str) -> float:
    if not key:
        return 1.0
    return 1.0 - (len(set(key)) / len(key))


def has_sequence(key: str) -> bool:
    low = key.lower()
    sequences = [
        "1234", "2345", "3456", "4567", "5678", "6789", "7890",
        "abcd", "bcde", "cdef", "qwer", "asdf", "zxcv", "9876", "4321"
    ]
    return any(seq in low for seq in sequences)


def weak_pattern(key: str) -> bool:
    low = key.lower()
    if any(word in low for word in WEAK_WORDS):
        return True
    if has_sequence(key):
        return True
    if len(set(key)) <= max(2, len(key) // 4):
        return True
    return False


def analyze_key(key: str, optimized: bool = True) -> dict:
    length = len(key)
    entropy = shannon_entropy(key)
    pool = charset_size(key)
    estimated_bits = math.log2(pool ** max(length, 1))
    diversity = 0
    diversity += int(any(c.islower() for c in key))
    diversity += int(any(c.isupper() for c in key))
    diversity += int(any(c.isdigit() for c in key))
    diversity += int(any(c in CHARSETS["symbols"] for c in key))
    repeat = repeated_ratio(key)
    pattern = weak_pattern(key)

    if optimized:
        score = 0
        score += min(length * 3.0, 40)
        score += min(entropy * 10.0, 30)
        score += diversity * 7
        score += min(estimated_bits / 5.0, 20)
        score -= repeat * 20
        if pattern:
            score -= 25
    else:
        score = length * 4 + diversity * 8
        if pattern:
            score -= 10
    score = int(max(0, min(100, round(score))))

    if score < 35:
        level = "WEAK"
    elif score < 60:
        level = "MEDIUM"
    elif score < 80:
        level = "STRONG"
    else:
        level = "VERY_STRONG"

    if pattern or length < 8:
        classification = "weak key"
    elif level in ("WEAK", "MEDIUM"):
        classification = "standard key"
    else:
        classification = "high entropy key"

    rec = []
    if length < 12:
        rec.append("Kalit uzunligini kamida 12-16 belgigacha oshirish tavsiya qilinadi.")
    if diversity < 3:
        rec.append("Katta harf, kichik harf, raqam va maxsus belgilarni aralashtirish kerak.")
    if pattern:
        rec.append("Oddiy so'zlar, ketma-ket sonlar va takrorlanuvchi naqshlardan foydalanmaslik kerak.")
    if not rec:
        rec.append("Kalit umumiy talablar bo'yicha yaxshi ko'rinadi, lekin uni himoyalangan joyda saqlash zarur.")

    return {
        "key": key,
        "length": length,
        "score": score,
        "level": level,
        "classification": classification,
        "entropy_bits_per_char": round(entropy, 3),
        "estimated_search_bits": round(estimated_bits, 2),
        "charset_size": pool,
        "diversity_groups": diversity,
        "repeated_ratio": round(repeat, 3),
        "weak_pattern": pattern,
        "recommendations": rec,
    }


def generate_key(kind: str, bits: int = 256, length: int = 32) -> str:
    if kind == "aes":
        return secrets.token_hex(bits // 8)
    if kind == "rsa":
        return "RSA-KEY-" + secrets.token_hex(max(32, bits // 16))
    if kind == "ecc":
        return "ECC-KEY-" + secrets.token_hex(32)
    alphabet = string.ascii_letters + string.digits + CHARSETS["symbols"]
    return "".join(secrets.choice(alphabet) for _ in range(length))


def synthetic_key(label: str) -> str:
    if label == "WEAK":
        base = random.choice(WEAK_WORDS + ["123456", "qwerty123", "admin2026", "11111111"])
        if random.random() < 0.4:
            base += str(random.randint(1, 99))
        return base
    if label == "MEDIUM":
        chars = string.ascii_lowercase + string.digits
        return "".join(random.choice(chars) for _ in range(random.randint(10, 14)))
    if label == "STRONG":
        chars = string.ascii_letters + string.digits
        return "".join(random.choice(chars) for _ in range(random.randint(14, 20)))
    chars = string.ascii_letters + string.digits + CHARSETS["symbols"]
    return "".join(random.choice(chars) for _ in range(random.randint(24, 40)))


def generate_dataset(samples: int, output: str) -> None:
    labels = ["WEAK", "MEDIUM", "STRONG", "VERY_STRONG"]
    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["key", "expected_label"])
        writer.writeheader()
        for i in range(samples):
            label = labels[i % len(labels)]
            writer.writerow({"key": synthetic_key(label), "expected_label": label})


def read_keys_from_file(path: str):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    keys = []
    for line in lines:
        line = line.strip()
        if not line or line.lower().startswith("key,"):
            continue
        if "," in line:
            keys.append(line.split(",")[0].strip())
        else:
            keys.append(line)
    return keys


def level_to_class(level: str) -> str:
    if level == "VERY_STRONG":
        return "STRONG"
    return level


def experiment(samples: int, output: str | None = None) -> dict:
    labels = ["WEAK", "MEDIUM", "STRONG", "VERY_STRONG"]
    rows = []
    start = time.perf_counter()
    correct_basic = 0
    correct_opt = 0
    summary = {label: {"count": 0, "avg_entropy": 0.0, "detected": 0} for label in labels}

    for i in range(samples):
        expected = labels[i % len(labels)]
        key = synthetic_key(expected)
        basic = analyze_key(key, optimized=False)
        opt = analyze_key(key, optimized=True)
        b_level = basic["level"]
        o_level = opt["level"]
        if level_to_class(b_level) == level_to_class(expected):
            correct_basic += 1
        if level_to_class(o_level) == level_to_class(expected):
            correct_opt += 1
        summary[expected]["count"] += 1
        summary[expected]["avg_entropy"] += opt["entropy_bits_per_char"]
        if level_to_class(o_level) == level_to_class(expected):
            summary[expected]["detected"] += 1
        rows.append({
            "key": key,
            "expected_label": expected,
            "basic_level": b_level,
            "optimized_level": o_level,
            "score": opt["score"],
            "entropy": opt["entropy_bits_per_char"],
            "estimated_bits": opt["estimated_search_bits"],
            "weak_pattern": opt["weak_pattern"],
        })

    elapsed = time.perf_counter() - start
    for label in labels:
        count = summary[label]["count"] or 1
        summary[label]["avg_entropy"] = round(summary[label]["avg_entropy"] / count, 3)
        summary[label]["accuracy"] = round(summary[label]["detected"] * 100 / count, 2)

    result = {
        "samples": samples,
        "basic_accuracy": round(correct_basic * 100 / samples, 2),
        "optimized_accuracy": round(correct_opt * 100 / samples, 2),
        "improvement": round((correct_opt - correct_basic) * 100 / samples, 2),
        "processing_time_sec": round(elapsed, 4),
        "keys_per_second": round(samples / elapsed, 2) if elapsed else samples,
        "summary": summary,
    }

    if output:
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    return result


def print_table(rows, headers):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, h in enumerate(headers):
            widths[i] = max(widths[i], len(str(row.get(h, ""))))
    line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    print(line)
    print("|" + "|".join(f" {headers[i]:<{widths[i]}} " for i in range(len(headers))) + "|")
    print(line)
    for row in rows:
        print("|" + "|".join(f" {str(row.get(headers[i], '')):<{widths[i]}} " for i in range(len(headers))) + "|")
    print(line)


def cmd_analyze(args):
    data = analyze_key(args.key, optimized=True)
    print("[+] Key Analysis")
    for k in ["length", "score", "level", "classification", "entropy_bits_per_char", "estimated_search_bits", "charset_size", "diversity_groups", "weak_pattern"]:
        print(f"{k:25}: {data[k]}")
    print("\n[+] Tavsiyalar")
    for r in data["recommendations"]:
        print(f"  - {r}")


def cmd_generate(args):
    print(generate_key(args.type, args.bits, args.length))


def cmd_classify(args):
    keys = read_keys_from_file(args.file)
    rows = []
    for key in keys:
        a = analyze_key(key)
        rows.append({"key": key[:20] + ("..." if len(key) > 20 else ""), "length": a["length"], "score": a["score"], "level": a["level"], "entropy": a["entropy_bits_per_char"]})
    print_table(rows, ["key", "length", "score", "level", "entropy"])


def cmd_scan(args):
    keys = read_keys_from_file(args.file)
    rows = []
    for key in keys:
        a = analyze_key(key)
        if a["level"] in ("WEAK", "MEDIUM") or a["weak_pattern"]:
            rows.append({"key": key[:24] + ("..." if len(key) > 24 else ""), "level": a["level"], "score": a["score"], "reason": "pattern/low entropy" if a["weak_pattern"] else "low score"})
    if rows:
        print_table(rows, ["key", "level", "score", "reason"])
    else:
        print("No weak keys detected.")


def cmd_dataset(args):
    generate_dataset(args.samples, args.output)
    print(f"Dataset created: {args.output} ({args.samples} samples)")


def cmd_experiment(args):
    result = experiment(args.samples, args.output)
    print("[+] Key2Bit v3.0 Research Experiment")
    print(f"Samples              : {result['samples']}")
    print(f"Basic accuracy       : {result['basic_accuracy']}%")
    print(f"Optimized accuracy   : {result['optimized_accuracy']}%")
    print(f"Improvement          : {result['improvement']}%")
    print(f"Processing time      : {result['processing_time_sec']} sec")
    print(f"Keys per second      : {result['keys_per_second']}")
    rows = []
    for label, info in result["summary"].items():
        rows.append({"class": label, "count": info["count"], "avg_entropy": info["avg_entropy"], "accuracy": str(info["accuracy"]) + "%"})
    print("\n[+] Classification summary")
    print_table(rows, ["class", "count", "avg_entropy", "accuracy"])
    if args.output:
        print(f"\nCSV saved to: {args.output}")


def cmd_optimize(args):
    if args.dataset:
        keys = read_keys_from_file(args.dataset)
        before_scores = []
        after_scores = []
        for key in keys:
            before_scores.append(analyze_key(key, optimized=False)["score"])
            after_scores.append(analyze_key(key, optimized=True)["score"])
        print("[+] Optimization report for dataset")
        print(f"Keys analyzed        : {len(keys)}")
        print(f"Avg score before     : {round(sum(before_scores)/len(before_scores), 2)}")
        print(f"Avg score after      : {round(sum(after_scores)/len(after_scores), 2)}")
        print(f"Score improvement    : {round((sum(after_scores)-sum(before_scores))/len(after_scores), 2)}")
        print("Method               : entropy + diversity + pattern penalty")
    else:
        print("[+] Recommended crypto profile")
        env = args.environment.lower()
        if env == "bank":
            print("Environment          : bank")
            print("Recommended          : AES-256 + RSA-4096 or ECC-384")
            print("Reason               : high confidentiality and long-term security")
        elif env == "mobile":
            print("Environment          : mobile")
            print("Recommended          : AES-128/256 + ECC-256")
            print("Reason               : balance between security and low resource usage")
        elif env == "iot":
            print("Environment          : iot")
            print("Recommended          : lightweight AES-128 + ECC-256")
            print("Reason               : limited CPU, memory and energy")
        else:
            print("Environment          : general")
            print("Recommended          : AES-256 + ECC-256")
            print("Reason               : stable default security profile")


def cmd_benchmark(args):
    tests = ["sha256", "sha512", "blake2b"]
    rows = []
    data = os.urandom(64)
    for name in tests:
        start = time.perf_counter()
        for _ in range(args.rounds):
            if name == "sha256":
                hashlib.sha256(data).hexdigest()
            elif name == "sha512":
                hashlib.sha512(data).hexdigest()
            else:
                hashlib.blake2b(data).hexdigest()
        elapsed = time.perf_counter() - start
        rows.append({"algorithm": name, "rounds": args.rounds, "time_sec": round(elapsed, 4), "ops_sec": round(args.rounds / elapsed, 2)})
    print_table(rows, ["algorithm", "rounds", "time_sec", "ops_sec"])


def cmd_report(args):
    keys = read_keys_from_file(args.file)
    rows = []
    for key in keys:
        a = analyze_key(key)
        rows.append({k: a[k] for k in ["key", "length", "score", "level", "classification", "entropy_bits_per_char", "estimated_search_bits", "weak_pattern"]})
    if args.format == "json":
        Path(args.output).write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        with open(args.output, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    print(f"Report saved: {args.output}")



# -----------------------------
# Key2Bit v4.0: S-AES module
# -----------------------------
SBOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_SBOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]


def _clean_bit_or_hex(value: str) -> int:
    """Accept 16-bit binary or 4-hex-char value and return integer."""
    v = value.strip().replace(" ", "").replace("_", "")
    if v.lower().startswith("0b"):
        v = v[2:]
    if v.lower().startswith("0x"):
        v = v[2:]
    if set(v) <= {"0", "1"} and len(v) == 16:
        return int(v, 2)
    if all(c in "0123456789abcdefABCDEF" for c in v) and len(v) == 4:
        return int(v, 16)
    raise ValueError("Value must be 16-bit binary or 4 hex chars, for example 1010101010101010 or A3F1")


def _bits16(x: int) -> str:
    return format(x & 0xFFFF, "016b")


def _hex4(x: int) -> str:
    return format(x & 0xFFFF, "04X")


def _nibbles(x: int) -> list[int]:
    return [(x >> 12) & 0xF, (x >> 8) & 0xF, (x >> 4) & 0xF, x & 0xF]


def _from_nibbles(n: list[int]) -> int:
    return ((n[0] & 0xF) << 12) | ((n[1] & 0xF) << 8) | ((n[2] & 0xF) << 4) | (n[3] & 0xF)


def _sub_nibbles(x: int, inv: bool = False) -> int:
    box = INV_SBOX if inv else SBOX
    return _from_nibbles([box[n] for n in _nibbles(x)])


def _shift_rows(x: int) -> int:
    # state is [n0 n1; n2 n3]. Shift second row left: [n0 n1; n3 n2]
    n = _nibbles(x)
    return _from_nibbles([n[0], n[1], n[3], n[2]])


def _gf_mul(a: int, b: int) -> int:
    # GF(2^4), irreducible polynomial x^4 + x + 1 (0b10011)
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        carry = a & 0x8
        a = (a << 1) & 0xF
        if carry:
            a ^= 0x3
        b >>= 1
    return p & 0xF


def _mix_columns(x: int, inv: bool = False) -> int:
    n = _nibbles(x)
    if not inv:
        # matrix [[1,4],[4,1]] applied to columns
        c0 = n[0] ^ _gf_mul(4, n[2])
        c1 = n[1] ^ _gf_mul(4, n[3])
        c2 = _gf_mul(4, n[0]) ^ n[2]
        c3 = _gf_mul(4, n[1]) ^ n[3]
    else:
        # inverse matrix [[9,2],[2,9]]
        c0 = _gf_mul(9, n[0]) ^ _gf_mul(2, n[2])
        c1 = _gf_mul(9, n[1]) ^ _gf_mul(2, n[3])
        c2 = _gf_mul(2, n[0]) ^ _gf_mul(9, n[2])
        c3 = _gf_mul(2, n[1]) ^ _gf_mul(9, n[3])
    return _from_nibbles([c0, c1, c2, c3])


def _rot_nib(byte: int) -> int:
    return ((byte & 0xF) << 4) | ((byte >> 4) & 0xF)


def _sub_byte(byte: int) -> int:
    return (SBOX[(byte >> 4) & 0xF] << 4) | SBOX[byte & 0xF]


def _key_expansion(master_key: int) -> tuple[int, int, int]:
    w0 = (master_key >> 8) & 0xFF
    w1 = master_key & 0xFF
    w2 = w0 ^ 0x80 ^ _sub_byte(_rot_nib(w1))
    w3 = w2 ^ w1
    w4 = w2 ^ 0x30 ^ _sub_byte(_rot_nib(w3))
    w5 = w4 ^ w3
    k0 = (w0 << 8) | w1
    k1 = (w2 << 8) | w3
    k2 = (w4 << 8) | w5
    return k0, k1, k2


def saes_encrypt_block(plaintext: int, master_key: int) -> tuple[int, dict]:
    k0, k1, k2 = _key_expansion(master_key)
    states = {}
    s = plaintext ^ k0
    states["add_round_key_0"] = s
    s = _sub_nibbles(s)
    states["sub_nibbles_1"] = s
    s = _shift_rows(s)
    states["shift_rows_1"] = s
    s = _mix_columns(s)
    states["mix_columns_1"] = s
    s ^= k1
    states["add_round_key_1"] = s
    s = _sub_nibbles(s)
    states["sub_nibbles_2"] = s
    s = _shift_rows(s)
    states["shift_rows_2"] = s
    s ^= k2
    states["ciphertext"] = s
    return s, {"k0": k0, "k1": k1, "k2": k2, "states": states}


def saes_decrypt_block(ciphertext: int, master_key: int) -> int:
    k0, k1, k2 = _key_expansion(master_key)
    s = ciphertext ^ k2
    s = _shift_rows(s)  # self-inverse
    s = _sub_nibbles(s, inv=True)
    s ^= k1
    s = _mix_columns(s, inv=True)
    s = _shift_rows(s)
    s = _sub_nibbles(s, inv=True)
    s ^= k0
    return s & 0xFFFF


def bit_balance(bitstr: str) -> tuple[int, int, float]:
    ones = bitstr.count("1")
    zeros = bitstr.count("0")
    total = len(bitstr) or 1
    return zeros, ones, round(abs(ones - zeros) / total, 3)


def bit_entropy(bitstr: str) -> float:
    if not bitstr:
        return 0.0
    zeros = bitstr.count("0") / len(bitstr)
    ones = bitstr.count("1") / len(bitstr)
    h = 0.0
    for p in (zeros, ones):
        if p > 0:
            h -= p * math.log2(p)
    return round(h, 3)


def classify_segment(bits: str) -> str:
    h = bit_entropy(bits)
    _, _, imbalance = bit_balance(bits)
    if h >= 0.95 and imbalance <= 0.25:
        return "STRONG"
    if h >= 0.75 and imbalance <= 0.5:
        return "MEDIUM"
    return "WEAK"


def segment_key_bits(bitstr: str, block: int = 16) -> list[str]:
    return [bitstr[i:i+block] for i in range(0, len(bitstr), block) if bitstr[i:i+block]]


def saes_quality(master_key: int) -> dict:
    k0, k1, k2 = _key_expansion(master_key)
    rows = []
    for name, val in [("K1", k0), ("K2", k1), ("K3", k2)]:
        bits = _bits16(val)
        zeros, ones, imbalance = bit_balance(bits)
        entropy = bit_entropy(bits)
        level = classify_segment(bits)
        rows.append({"subkey": name, "hex": _hex4(val), "bits": bits, "zeros": zeros, "ones": ones, "entropy": entropy, "imbalance": imbalance, "level": level})
    avg_entropy = round(sum(r["entropy"] for r in rows) / len(rows), 3)
    weak_count = sum(1 for r in rows if r["level"] == "WEAK")
    score = int(max(0, min(100, round(avg_entropy * 100 - weak_count * 15))))
    if score < 50:
        key_level = "WEAK"
    elif score < 75:
        key_level = "MEDIUM"
    elif score < 90:
        key_level = "STRONG"
    else:
        key_level = "VERY_STRONG"
    rec = "Key structure is acceptable."
    if weak_count:
        rec = "Weak subkey detected. Regenerate master key or choose a key with better bit balance."
    elif avg_entropy < 0.9:
        rec = "Average entropy is not high. New random master key is recommended."
    return {"rows": rows, "avg_entropy": avg_entropy, "score": score, "level": key_level, "recommendation": rec}


def cmd_segment(args):
    raw = args.key.strip().replace(" ", "")
    if all(c in "01" for c in raw):
        bits = raw
    elif all(c in "0123456789abcdefABCDEF" for c in raw):
        bits = bin(int(raw, 16))[2:].zfill(len(raw)*4)
    else:
        raise ValueError("Use binary or hexadecimal key value.")
    rows = []
    for i, seg in enumerate(segment_key_bits(bits, args.block), 1):
        z, o, imb = bit_balance(seg)
        rows.append({"segment": f"K{i}", "bits": seg, "zeros": z, "ones": o, "entropy": bit_entropy(seg), "level": classify_segment(seg)})
    print(f"[+] Segment analysis | total_bits={len(bits)} | block={args.block}")
    print_table(rows, ["segment", "bits", "zeros", "ones", "entropy", "level"])


def cmd_saes(args):
    pt = _clean_bit_or_hex(args.plaintext)
    key = _clean_bit_or_hex(args.key)
    ct, info = saes_encrypt_block(pt, key)
    recovered = saes_decrypt_block(ct, key)
    q = saes_quality(key)

    print("[+] S-AES encryption/decryption test")
    print(f"Plaintext            : {_bits16(pt)}  (0x{_hex4(pt)})")
    print(f"Master key           : {_bits16(key)}  (0x{_hex4(key)})")
    print("\n[+] Key expansion")
    print(f"K1                   : {_bits16(info['k0'])}  (0x{_hex4(info['k0'])})")
    print(f"K2                   : {_bits16(info['k1'])}  (0x{_hex4(info['k1'])})")
    print(f"K3                   : {_bits16(info['k2'])}  (0x{_hex4(info['k2'])})")
    print("\n[+] Encryption rounds")
    for name, value in info["states"].items():
        print(f"{name:22}: {_bits16(value)}  (0x{_hex4(value)})")
    print("\n[+] Decryption comparison")
    print(f"Ciphertext           : {_bits16(ct)}  (0x{_hex4(ct)})")
    print(f"Recovered plaintext  : {_bits16(recovered)}  (0x{_hex4(recovered)})")
    print(f"Match result         : {'SUCCESS' if recovered == pt else 'FAILED'}")
    print("\n[+] Subkey classification")
    print_table(q["rows"], ["subkey", "hex", "zeros", "ones", "entropy", "imbalance", "level"])
    print("\n[+] Optimization recommendation")
    print(f"Average entropy      : {q['avg_entropy']}")
    print(f"Key quality score    : {q['score']}")
    print(f"Key quality level    : {q['level']}")
    print(f"Recommendation       : {q['recommendation']}")


def cmd_saes_compare(args):
    pt = _clean_bit_or_hex(args.plaintext)
    if args.keys_file:
        candidates = read_keys_from_file(args.keys_file)
    else:
        candidates = [x.strip() for x in args.keys.split(",") if x.strip()]
    rows = []
    for i, kstr in enumerate(candidates, 1):
        try:
            key = _clean_bit_or_hex(kstr)
            ct, _ = saes_encrypt_block(pt, key)
            rec = saes_decrypt_block(ct, key)
            q = saes_quality(key)
            rows.append({"id": f"Key{i}", "key_hex": _hex4(key), "cipher_hex": _hex4(ct), "match": "OK" if rec == pt else "FAIL", "avg_entropy": q["avg_entropy"], "score": q["score"], "level": q["level"]})
        except Exception as e:
            rows.append({"id": f"Key{i}", "key_hex": kstr[:16], "cipher_hex": "-", "match": "ERROR", "avg_entropy": "-", "score": 0, "level": str(e)[:16]})
    print("[+] S-AES key comparison")
    print(f"Plaintext            : {_bits16(pt)}  (0x{_hex4(pt)})")
    print_table(rows, ["id", "key_hex", "cipher_hex", "match", "avg_entropy", "score", "level"])
    valid = [r for r in rows if isinstance(r.get("score"), int) and r.get("match") == "OK"]
    if valid:
        best = max(valid, key=lambda r: r["score"])
        print("\n[+] Optimization result")
        print(f"Recommended key      : {best['id']} | 0x{best['key_hex']}")
        print(f"Reason               : highest subkey entropy and classification score")


def main():
    parser = argparse.ArgumentParser(description="Key2Bit v4.0 - Encryption key classification, S-AES analysis and optimization utility")
    parser.add_argument("--version", action="version", version=f"Key2Bit v{VERSION} | License: {LICENSE}")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("generate", help="Generate cryptographic style key")
    p.add_argument("--type", choices=["aes", "rsa", "ecc", "random"], default="random")
    p.add_argument("--bits", type=int, default=256)
    p.add_argument("--length", type=int, default=32)
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("analyze", help="Analyze one key")
    p.add_argument("--key", required=True)
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("classify", help="Classify keys from file")
    p.add_argument("--file", required=True)
    p.set_defaults(func=cmd_classify)

    p = sub.add_parser("scan", help="Detect weak keys from file")
    p.add_argument("--file", required=True)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("dataset", help="Generate labeled dataset for research")
    p.add_argument("--samples", type=int, default=1000)
    p.add_argument("--output", default="key2bit_dataset.csv")
    p.set_defaults(func=cmd_dataset)

    p = sub.add_parser("experiment", help="Run classification experiment with before/after optimization")
    p.add_argument("--samples", type=int, default=2048)
    p.add_argument("--output", default=None)
    p.set_defaults(func=cmd_experiment)

    p = sub.add_parser("optimize", help="Recommend profile or optimize dataset scoring")
    p.add_argument("--environment", default="general")
    p.add_argument("--dataset", default=None)
    p.set_defaults(func=cmd_optimize)

    p = sub.add_parser("benchmark", help="Run lightweight benchmark")
    p.add_argument("--rounds", type=int, default=10000)
    p.set_defaults(func=cmd_benchmark)

    p = sub.add_parser("report", help="Export key analysis report")
    p.add_argument("--file", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--format", choices=["csv", "json"], default="csv")
    p.set_defaults(func=cmd_report)


    p = sub.add_parser("segment", help="Split binary/hex key into K1..Kn segments and classify each part")
    p.add_argument("--key", required=True)
    p.add_argument("--block", type=int, default=16)
    p.set_defaults(func=cmd_segment)

    p = sub.add_parser("saes", help="Run S-AES encryption/decryption and K1/K2/K3 subkey analysis")
    p.add_argument("--plaintext", required=True, help="16-bit binary or 4 hex chars")
    p.add_argument("--key", required=True, help="16-bit binary or 4 hex chars")
    p.set_defaults(func=cmd_saes)

    p = sub.add_parser("saes-compare", help="Compare several S-AES keys and recommend the best one")
    p.add_argument("--plaintext", required=True, help="16-bit binary or 4 hex chars")
    p.add_argument("--keys", default="", help="Comma-separated 16-bit binary or 4-hex keys")
    p.add_argument("--keys-file", default=None)
    p.set_defaults(func=cmd_saes_compare)

    p = sub.add_parser("deathstar", help="Show console banner")
    p.set_defaults(func=lambda args: print(DEATH_STAR + TITLE + f"Key2Bit v{VERSION} | Licensed Under {LICENSE}"))

    args = parser.parse_args()
    if not args.cmd:
        print(TITLE)
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
