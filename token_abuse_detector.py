import argparse
import json
import hashlib


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()[:16]


def main() -> int:
    ap = argparse.ArgumentParser(description="Token Abuse Detector (MVP)")
    ap.add_argument("--log", required=True, help="Path to JSONL log file")
    args = ap.parse_args()

    token_counts = {}
    token_ips = {}
    token_uas = {}
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

            token = event.get("token")
            ip = event.get("ip")
            ua = event.get("user_agent")

            if not isinstance(token, str) or not token.strip():
                continue

            token = token.strip()
            lines_seen += 1

            fp = token_fingerprint(token)
            token_counts[fp] = token_counts.get(fp, 0) + 1

            if fp not in token_ips:
                token_ips[fp] = set()
            if fp not in token_uas:
                token_uas[fp] = set()

            if isinstance(ip, str) and ip.strip():
                token_ips[fp].add(ip.strip())

            if isinstance(ua, str) and ua.strip():
                token_uas[fp].add(ua.strip())

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
    for fp, count in sorted(token_counts.items(), key=lambda x: x[1], reverse=True):
        ip_count = len(token_ips.get(fp, set()))
        ua_count = len(token_uas.get(fp, set()))
        print(f"- {fp}: {count} uses from {ip_count} IP(s), {ua_count} user-agent(s)")

    print("")
    print("Potential abuse signals:")
    found_any = False

    for fp, ips in token_ips.items():
        if len(ips) > 1:
            found_any = True
            print(f"WARNING: Token {fp} used from multiple IPs: {', '.join(sorted(ips))}")

    for fp, uas in token_uas.items():
        if len(uas) > 1:
            found_any = True
            print(f"WARNING: Token {fp} used from multiple user agents: {', '.join(sorted(uas))}")

    if not found_any:
        print("No multi-IP or multi-user-agent reuse detected.")

    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
