# Key2Bit v4.0

Key2Bit is a Kali Linux friendly CLI utility for encryption key generation, classification, S-AES subkey analysis, encryption/decryption comparison, optimization experiments, benchmarking and report export.

License: Kenobi

## Install

```bash
git clone https://github.com/python457/key2bit.git
cd key2bit
sudo bash install.sh
```

Local zip install:

```bash
unzip key2bit_v4.zip
cd key2bit_v4
sudo bash install.sh
```

## Classic key analysis commands

```bash
key2bit --version
key2bit generate --type aes --bits 256
key2bit generate --type random --length 32
key2bit analyze --key "A7f9@demoKey2026!"
key2bit dataset --samples 20 --output test_keys.txt
key2bit classify --file test_keys.txt
key2bit optimize --dataset test_keys.txt
key2bit benchmark --rounds 10000
key2bit report --file test_keys.txt --output report.csv --format csv
```

## v4.0 S-AES cryptographic key mode

S-AES mode works with a real educational encryption algorithm: 16-bit plaintext and 16-bit master key. The tool creates K1, K2 and K3 subkeys, encrypts plaintext, decrypts ciphertext back, compares the result, then classifies every subkey by entropy and bit balance.

```bash
key2bit saes --plaintext 1010101111001101 --key 0100101011110101
```

Hex input is also supported:

```bash
key2bit saes --plaintext ABCD --key 4AF5
```

Split and classify any binary/hex key into segments:

```bash
key2bit segment --key 2B7E151628AED2A6ABF7158809CF4F3C --block 16
```

Compare several S-AES keys and recommend the best one:

```bash
key2bit saes-compare --plaintext ABCD --keys 4AF5,A3F1,FFFF,1234
```

## What was added in v4.0

- S-AES encryption/decryption test
- Automatic K1, K2, K3 subkey generation
- Subkey entropy and bit balance classification
- Original plaintext vs recovered plaintext comparison
- Multi-key comparison and best-key recommendation
- Generic key segmentation mode for AES-style key parts
