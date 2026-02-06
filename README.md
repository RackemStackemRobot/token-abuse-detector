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
