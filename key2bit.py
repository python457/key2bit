#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Key2Bit v2.0 - Licensed Under Kenobi."""
import argparse, base64, csv, hashlib, json, math, os, secrets, string, time
from pathlib import Path
VERSION="2.0"
LICENSE="Kenobi"
BANNER=r'''
                          .          .
                     .          .                  .
                 .        _.-^^---....,,--
                      _--                  --_
                     <                        >)
                     |                         |
                      \._                   _./
                         ```--. . , ; .--'''
                               | |   |
                            .-=||  | |=-.
                            `-=#$%&%$#=-'
                               | ;  :|
                      _____.,-#%&$@%#&#~,._____

 ██╗  ██╗███████╗██╗   ██╗██████╗ ██████╗ ██╗████████╗
 ██║ ██╔╝██╔════╝╚██╗ ██╔╝╚════██╗██╔══██╗██║╚══██╔══╝
 █████╔╝ █████╗   ╚████╔╝  █████╔╝██████╔╝██║   ██║
 ██╔═██╗ ██╔══╝    ╚██╔╝  ██╔═══╝ ██╔══██╗██║   ██║
 ██║  ██╗███████╗   ██║   ███████╗██████╔╝██║   ██║
 ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═════╝ ╚═╝   ╚═╝

                  Key2Bit v2.0 | Licensed Under Kenobi
              Cryptographic Key Classification & Optimization
'''
def print_banner(): print(BANNER)
def entropy_bits_per_char(v):
    if not v: return 0.0
    f={}
    for c in v: f[c]=f.get(c,0)+1
    e=0.0
    for n in f.values():
        p=n/len(v); e-=p*math.log2(p)
    return e
def charset_size(v):
    s=0
    if any(c.islower() for c in v): s+=26
    if any(c.isupper() for c in v): s+=26
    if any(c.isdigit() for c in v): s+=10
    if any(c in string.punctuation for c in v): s+=len(string.punctuation)
    if any(c.isspace() for c in v): s+=1
    if any(c not in string.ascii_letters+string.digits+string.punctuation+' ' for c in v): s+=32
    return max(s,1)
def estimate_strength(v):
    l=len(v); lower=any(c.islower() for c in v); upper=any(c.isupper() for c in v); digit=any(c.isdigit() for c in v); sym=any(c in string.punctuation for c in v)
    rep=l!=len(set(v)) and l>0; ent=entropy_bits_per_char(v); bits=math.log2(charset_size(v))*l if l else 0
    score=0
    if l>=12: score+=20
    if l>=16: score+=15
    if l>=24: score+=15
    if lower: score+=10
    if upper: score+=10
    if digit: score+=10
    if sym: score+=10
    if ent>=3.2: score+=10
    if rep: score-=8
    if any(p in v.lower() for p in ['password','admin','qwerty','123456','key','test']): score-=20
    score=max(0,min(100,score))
    if score<35: level='WEAK'; cls='low security key'
    elif score<60: level='MEDIUM'; cls='standard key'
    elif score<80: level='STRONG'; cls='secure key'
    else: level='VERY STRONG'; cls='optimized secure key'
    rec=[]
    if l<16: rec.append('Increase key length to at least 16 characters.')
    if not upper: rec.append('Add uppercase characters.')
    if not digit: rec.append('Add digits.')
    if not sym: rec.append('Add special symbols.')
    if rep: rec.append('Avoid repeated characters and simple patterns.')
    if not rec: rec.append('Key quality is acceptable for general usage.')
    return {'key':v,'length':l,'score':score,'level':level,'classification':cls,'entropy_bits_per_char':round(ent,3),'estimated_search_bits':round(bits,2),'has_lower':lower,'has_upper':upper,'has_digit':digit,'has_symbol':sym,'recommendations':rec}
def generate_key(a):
    if a.type=='aes':
        bits=a.bits or 256
        if bits not in [128,192,256]: print('[!] AES supports 128, 192, or 256 bits.'); return
        raw=secrets.token_bytes(bits//8); key=raw.hex() if a.format=='hex' else base64.urlsafe_b64encode(raw).decode().rstrip('=')
    elif a.type=='rsa':
        bits=a.bits or 2048; seed=secrets.token_hex(64); key=f'RSA-{bits}-SIM-'+hashlib.sha256(seed.encode()).hexdigest()
    elif a.type=='ecc':
        bits=a.bits or 256; seed=secrets.token_hex(48); key=f'ECC-{bits}-SIM-'+hashlib.sha256(seed.encode()).hexdigest()[:64]
    else:
        alphabet=string.ascii_letters+string.digits+string.punctuation; key=''.join(secrets.choice(alphabet) for _ in range(a.length))
    print_banner(); print('[+] Generated Key'); print('-'*72); print(f'Type    : {a.type.upper()}'); print(f'Version : {VERSION}'); print(f'Key     : {key}')
def analyze_key(a):
    print_banner(); r=estimate_strength(a.key); print('[+] Key Analysis'); print('-'*72)
    for k in ['length','score','level','classification','entropy_bits_per_char','estimated_search_bits']: print(f'{k:24}: {r[k]}')
    print('\n[+] Recommendations')
    for rec in r['recommendations']: print('  - '+rec)
def classify_file(a):
    print_banner(); p=Path(a.file)
    if not p.exists(): print(f'[!] File not found: {a.file}'); return
    keys=[x.strip() for x in p.read_text(errors='ignore').splitlines() if x.strip()]
    print('[+] Classification Result'); print('-'*92); print(f"{'No':<5}{'Length':<10}{'Score':<10}{'Level':<16}{'Classification':<24}Key Preview"); print('-'*92)
    for i,k in enumerate(keys,1):
        r=estimate_strength(k); prev=k[:18]+('...' if len(k)>18 else '')
        print(f"{i:<5}{r['length']:<10}{r['score']:<10}{r['level']:<16}{r['classification']:<24}{prev}")
def scan_file(a):
    print_banner(); p=Path(a.file)
    if not p.exists(): print(f'[!] File not found: {a.file}'); return
    keys=[x.strip() for x in p.read_text(errors='ignore').splitlines() if x.strip()]; weak=[]
    for k in keys:
        r=estimate_strength(k)
        if r['level'] in ['WEAK','MEDIUM']: weak.append(r)
    print('[+] Weak Key Scan'); print('-'*72); print(f'Total keys scanned : {len(keys)}'); print(f'Weak/medium found  : {len(weak)}')
    for r in weak:
        print(f"\nKey preview: {r['key'][:20]}{'...' if len(r['key'])>20 else ''}"); print(f"Level      : {r['level']}"); print(f"Score      : {r['score']}"); print(f"Advice     : {r['recommendations'][0]}")
def optimize(a):
    print_banner(); env=a.environment.lower(); target=a.target
    profiles={'mobile':('ECC-256 + AES-128','low resource usage with strong security'),'server':('AES-256 + RSA-3072','high security for server-side systems'),'iot':('ECC-256 + AES-128','balanced for limited CPU and memory'),'bank':('AES-256 + RSA-4096 or ECC-384','maximum protection for sensitive financial data'),'general':('AES-256','simple and strong default configuration')}
    rec,reason=profiles.get(env,profiles['general'])
    if target:
        if target<=128: rec='AES-128 or ECC-256'; reason='target prioritizes speed and acceptable baseline security'
        elif target<=256: rec='AES-256 or ECC-256'; reason='target balances strong security and performance'
        else: rec='RSA-4096 or ECC-384'; reason='target prioritizes stronger long-term protection'
    print('[+] Optimization Recommendation'); print('-'*72); print(f'Environment : {env}'); print(f'Target bits : {target if target else "auto"}'); print(f'Recommended : {rec}'); print(f'Reason      : {reason}'); print('\n[+] Practical Advice\n  - Rotate keys periodically.\n  - Avoid storing keys in plain text.\n  - Use stronger profiles for long-term confidential data.')
def benchmark(a):
    print_banner(); tests=[('AES-128 simulation',16),('AES-256 simulation',32),('ECC-256 simulation',32),('RSA-2048 simulation',256),('RSA-4096 simulation',512)]
    print('[+] Benchmark'); print('-'*72); print(f"{'Test':<24}{'Rounds':<12}{'Time(sec)':<14}{'Ops/sec'}"); print('-'*72)
    for name,size in tests:
        st=time.perf_counter()
        for _ in range(a.rounds): hashlib.sha256(secrets.token_bytes(size)).digest()
        el=time.perf_counter()-st; ops=a.rounds/el if el>0 else 0
        print(f'{name:<24}{a.rounds:<12}{el:<14.5f}{ops:.2f}')
def report(a):
    print_banner(); p=Path(a.file)
    if not p.exists(): print(f'[!] File not found: {a.file}'); return
    data=[estimate_strength(x.strip()) for x in p.read_text(errors='ignore').splitlines() if x.strip()]; out=Path(a.output)
    if a.format=='json': out.write_text(json.dumps(data,indent=2),encoding='utf-8')
    else:
        with out.open('w',newline='',encoding='utf-8') as f:
            fields=['key','length','score','level','classification','entropy_bits_per_char','estimated_search_bits']; w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
            for r in data: w.writerow({k:r[k] for k in fields})
    print(f'[+] Report saved: {out}')
def demo(a):
    print_banner(); print('[+] Demo Mode'); print('-'*72)
    for k in ['12345678','adminKey2024','A7f9@demoKey2026!',secrets.token_urlsafe(32)]:
        r=estimate_strength(k); print(f'{k[:28]:<32} -> {r["level"]:<12} score={r["score"]}')
def deathstar(a): print_banner(); print('The key is strong with this one.'); print('Mode: Death Star console online.')
def build_parser():
    parser=argparse.ArgumentParser(prog='key2bit',description='Key2Bit v2.0 - Cryptographic key classification and optimization CLI utility')
    parser.add_argument('--version',action='version',version=f'Key2Bit {VERSION} | License: {LICENSE}')
    sub=parser.add_subparsers(dest='command')
    p=sub.add_parser('generate',help='Generate cryptographic style key'); p.add_argument('--type',choices=['random','aes','rsa','ecc'],default='random'); p.add_argument('--length',type=int,default=32); p.add_argument('--bits',type=int,default=None); p.add_argument('--format',choices=['hex','base64'],default='hex'); p.set_defaults(func=generate_key)
    p=sub.add_parser('analyze',help='Analyze one key'); p.add_argument('--key',required=True); p.set_defaults(func=analyze_key)
    p=sub.add_parser('classify',help='Classify keys from file'); p.add_argument('--file',required=True); p.set_defaults(func=classify_file)
    p=sub.add_parser('scan',help='Detect weak keys from file'); p.add_argument('--file',required=True); p.set_defaults(func=scan_file)
    p=sub.add_parser('optimize',help='Recommend optimized crypto profile'); p.add_argument('--environment',default='general',help='mobile/server/iot/bank/general'); p.add_argument('--target',type=int,default=None); p.set_defaults(func=optimize)
    p=sub.add_parser('benchmark',help='Run lightweight benchmark'); p.add_argument('--rounds',type=int,default=50000); p.set_defaults(func=benchmark)
    p=sub.add_parser('report',help='Export report from keys file'); p.add_argument('--file',required=True); p.add_argument('--output',default='key2bit_report.csv'); p.add_argument('--format',choices=['csv','json'],default='csv'); p.set_defaults(func=report)
    p=sub.add_parser('demo',help='Run demo mode'); p.set_defaults(func=demo)
    p=sub.add_parser('deathstar',help='Show Death Star console'); p.set_defaults(func=deathstar)
    return parser
def main():
    parser=build_parser(); a=parser.parse_args()
    if hasattr(a,'func'): a.func(a)
    else: print_banner(); parser.print_help()
if __name__=='__main__': main()
