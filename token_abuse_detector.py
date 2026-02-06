import argparse
import json
import hashlib


def token_fingerprint(token: str) -> str:
    # We do not print raw tokens, we print a short stable fingerprint instead
    return hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()[:16]


def main() -> int:
    ap = argparse.ArgumentParser(description="Token Abuse Detector (MVP)")
    ap.add_argument("--log", required=True, help="Path to JSONL log file")
    args = ap.parse_args()

    token_counts = {}
    lines_seen = 0

    with open(args.log, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(event, dict):
                continue

            # For MVP, we only support a simple "token" field.
            token = event.get("token")
            if not isinstance(token, str) or not token.strip():
                continue

            lines_seen += 1
            fp = token_fingerprint(token.strip())
            token_counts[fp] = token_counts.get(fp, 0) + 1

    print("")
    print("Token Abuse Detector (MVP)")
    print(f"Lines with tokens: {lines_seen}")
    print(f"Unique tokens seen: {len(token_counts)}")
    print("")

    if not token_counts:
        print("No tokens found.")
        print("")
        return 0

    print("Top tokens by frequency:")
    for fp, count in sorted(token_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
        print(f"- {fp}: {count}")

    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
