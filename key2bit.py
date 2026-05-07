#!/usr/bin/env python3
import argparse
import random
import string

BANNER = r"""
██████████████████████████████████████████████████████████████████████
█                                                                    █
█   KEY2BIT  -  Licensed Under Kenobi                               █
█                                                                    █
█              ◉ DEATH STAR SECURITY CONSOLE ◉                      █
█                                                                    █
██████████████████████████████████████████████████████████████████████
"""

def generate(length):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    key = ''.join(random.choice(chars) for _ in range(length))
    print("\n[+] Generated Key:\n")
    print(key)

def analyze(key):
    score = 0
    if len(key) >= 16:
        score += 1
    if any(c.isdigit() for c in key):
        score += 1
    if any(c.isupper() for c in key):
        score += 1
    if any(c in "!@#$%^&*" for c in key):
        score += 1

    levels = {
        1: "Weak",
        2: "Medium",
        3: "Strong",
        4: "Very Strong"
    }

    print("\n[+] Analysis Result")
    print(f"Length: {len(key)}")
    print(f"Security: {levels.get(score, 'Weak')}")

def main():
    parser = argparse.ArgumentParser(description="Key2Bit CLI")
    sub = parser.add_subparsers(dest="cmd")

    gen = sub.add_parser("generate")
    gen.add_argument("--length", type=int, default=32)

    ana = sub.add_parser("analyze")
    ana.add_argument("--key", required=True)

    args = parser.parse_args()

    print(BANNER)

    if args.cmd == "generate":
        generate(args.length)
    elif args.cmd == "analyze":
        analyze(args.key)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
