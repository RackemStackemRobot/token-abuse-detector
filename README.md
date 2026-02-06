# Token Abuse Detector (MVP)

A small CLI tool that scans JSONL logs and flags common token abuse signals.

It does not print raw tokens. It prints a short stable fingerprint instead.

## What it detects (current MVP)

- Token reuse across multiple IPs  
- Token reuse across multiple user agents  
- Simple risk score per token  

## Expected log formats

Each line must be valid JSON.

The tool will read tokens from either:

1) Direct fields:  
- token  
- ip  
- user_agent  

2) Or common header fields:  
- headers.Authorization or headers.authorization (supports "Bearer <token>")  
- headers.X-Forwarded-For (first hop is treated as client IP)  
- headers.User-Agent  

## Install

```bash
pip install -r requirements.txt
```

If pip fails on Windows:

```bash
python -m pip install -r requirements.txt
```

## Run

Basic run:

```bash
python token_abuse_detector.py --log sample_logs.jsonl
```

Write a JSON report:

```bash
python token_abuse_detector.py --log sample_logs.jsonl --out report.json
```

## Output

Console output shows:

- Lines with tokens  
- Unique tokens  
- Tokens ranked by risk  
- Warning lines for multi-IP and multi-user-agent reuse  

JSON report includes:

- tokens[] with risk and counts  
- warnings[] with details  

## Notes

- This is a heuristic detector.  
- It does not validate JWT signatures.  
- It is designed to be simple, readable, and easy to extend.
