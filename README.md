# Key2Bit v3.0

Key2Bit is a Kali Linux friendly CLI utility for encryption key generation, analysis, classification, weak key scanning, optimization experiments, benchmarking and report export.

License: Kenobi

## Install

```bash
git clone https://github.com/python457/key2bit.git
cd key2bit
sudo bash install.sh
```

Local zip install:

```bash
unzip key2bit_v3.zip
cd key2bit_v3
sudo bash install.sh
```

## Main commands

```bash
key2bit --version
key2bit generate --type aes --bits 256
key2bit generate --type random --length 32
key2bit analyze --key "A7f9@demoKey2026!"
key2bit classify --file keys.txt
key2bit scan --file keys.txt
key2bit optimize --environment bank
key2bit benchmark --rounds 10000
key2bit report --file keys.txt --output report.csv --format csv
```

## Research mode

Generate dataset:

```bash
key2bit dataset --samples 2048 --output dataset.csv
```

Run classification experiment:

```bash
key2bit experiment --samples 2048 --output experiment_results.csv
```

Optimize dataset scoring:

```bash
key2bit optimize --dataset dataset.csv
```

## What was added in v3.0

- Synthetic dataset generation
- Before/after classification experiment
- Optimized scoring model based on entropy, diversity and weak-pattern penalty
- CSV export for experiment results
- Research-ready terminal outputs for screenshots and diploma tables
