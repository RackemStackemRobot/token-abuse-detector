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


def extract_token(event: dict) -> str | None:
    # Direct field
    token = event.get("token")
    if isinstance(token, str) and token.strip():
        return token.strip()

    # Header formats
    headers = event.get("headers")
    if isinstance(headers, dict):
        auth = headers.get("Authorization") or headers.get("authorization")
        if isinstance(auth, str) and auth.strip():
            auth = auth.strip()
            if auth.lower().startswith("bearer "):
                return auth.split(" ", 1)[1].strip()
            return auth

    return None


def extract_ip(event: dict) -> str | None:
    # Direct field
    ip = event.get("ip")
    if isinstance(ip, str) and ip.strip():
        return ip.strip()

    # Proxy headers
    headers = event.get("headers")
    if isinstance(headers, dict):
        xff = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
        if isinstance(xff, str) and xff.strip():
            # first hop is usually the client
            return xff.split(",")[0].strip()

        xri = headers.get("X-Real-IP") or headers.get("x-real-ip")
        if isinstance(xri, str) and xri.strip():
            return xri.strip()

    return None


def extract_user_agent(event: dict) -> str | None:
    # Direct field
    ua = event.get("user_agent")
    if isinstance(ua, str) and ua.strip():
        return ua.strip()

    # Header format
    headers = event.get("headers")
    if isinstance(headers, dict):
        hua = headers.get("User-Agent") or headers.get("user-agent")
        if isinstance(hua, str) and hua.strip():
            return hua.strip()

    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Token Abuse Detector (MVP)")
    ap.add_argument("--log", required=True, help="Pat_
