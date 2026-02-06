import argparse
import json
import hashlib


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()[:16]


def compute_risk(ip_count: int, ua_count: int, use_count: int) -> int:
    score = 0

    if ip_count > 1:
        score += 30

    if ua_count > 1:
        score += 20

    if use_count > 10:
        score += 10

    if score > 100:
        score = 100

    return score


def extract_token(event: dict):
    token = event.get("token")
    if isinstance(token, str) and token.strip():
        return token.strip()

    headers = event.get("headers")
    if isinstance(headers, dict):
        auth = headers.get("Authorization") or headers.get("authorization")
        if isinstance(auth, str) and auth.strip():
            auth = auth.strip()
            if auth.lower().startswith("bearer "):
                return auth.split(" ", 1)[1].strip()
            return auth

    return None


def extract_ip(event: dict):
    ip = event.get("ip")
    if isinstance(ip, str) and ip.strip():
        return ip.strip()

    headers = event.get("headers")
    if isinstance(headers, dict):
        xff = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
        if isinstance(xff, str) and xff.strip():
            return xff.split(",")[0].strip()

        xri = headers.get("X-Real-IP") or headers.get("x-real-ip")
        if isinstance(xri, str) and xri.strip():
            return xri.strip()

    return None


def extract_user_agent(event: dict):
    ua = event.get("user_agent")
    if isinstance(ua, str) and ua.strip():
        return ua.strip()

    headers = event.get("headers")
    if isinstance(headers, dict):
        hua = headers.get("User-Agent") or headers.get("user-agent")
        if isinstance(hua, str) and hua.strip():
            return hua.strip()

    return None


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

            token = extract_token(event)
            if not token:
                continue

            ip = extract_ip(event) or "unknown_ip"
            ua = extract_user_agent(event) or "unknown_ua"

            lines_seen += 1

            fp = token_fingerprint(token)
            token_counts[fp] = token_counts.get(fp, 0) + 1

            if fp not in token_ips:
                token_ips[fp] = set()
            if fp not in token_uas:
                token_uas[fp] = set()

            token_ips[fp].add(ip)
            token_uas[fp].add(ua)

    print("")
    print("Token Abuse Detector (MVP)")
    print(f"Lines with tokens: {lines_seen}")
    print(f"Unique tokens seen: {len(token_counts)}")
    print("")

    if not token_counts:
        print("No tokens found.")
        print("")
        return 0

    ranked = []
    for fp, use_count in token_counts.items():
        ip_count = len(token_ips.get(fp, set()))
        ua_count = len(token_uas.get(fp, set()))
        risk = compute_risk(ip_count, ua_count, use_count)
        ranked.append((risk, fp, use_count, ip_count, ua_count))

    ranked.sort(reverse=True)

    print("Tokens ranked by risk:")
    for risk, fp, use_count, ip_count, ua_count in ranked:
        print(f"- {fp}: risk={risk} uses={use_count} ips={ip_count} uas={ua_count}")

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

