# Key2Bit v2.0

**Key2Bit** is a Kali Linux friendly CLI utility for cryptographic key generation, classification, weak key scanning, optimization recommendations, benchmarking and report export.

License: **Kenobi**

## Install

```bash
git clone https://github.com/python457/key2bit.git
cd key2bit
sudo bash install.sh
```

## Commands

```bash
key2bit
key2bit --version
key2bit generate --type aes --bits 256
key2bit generate --type random --length 32
key2bit analyze --key "A7f9@demoKey2026!"
key2bit classify --file keys.txt
key2bit scan --file keys.txt
key2bit optimize --environment mobile
key2bit optimize --environment bank --target 384
key2bit benchmark --rounds 50000
key2bit report --file keys.txt --output report.csv --format csv
key2bit report --file keys.txt --output report.json --format json
key2bit demo
key2bit deathstar
```

## Purpose

This project was created as an educational cybersecurity CLI tool for a diploma project about cryptographic key classification and optimization methods.

## Note

RSA and ECC generation modes in this version are educational simulations for classification and optimization demonstration. For production cryptography use verified libraries and official standards.
