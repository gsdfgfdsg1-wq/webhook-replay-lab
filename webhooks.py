#!/usr/bin/env python3
"""Verify, sanitize, and prepare webhook events for controlled replay."""
import argparse
import hashlib
import hmac
import json
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlparse


def verify(body, signature, secret):
    expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.removeprefix("sha256="))


def sanitize(event, paths):
    output = deepcopy(event)
    for path in paths:
        target = output
        parts = path.strip("/").split("/")
        for part in parts[:-1]:
            target = target.get(part, {}) if isinstance(target, dict) else {}
        if isinstance(target, dict) and parts[-1] in target:
            target[parts[-1]] = "[REDACTED]"
    return output


def replay_request(event, target, allowed_hosts):
    host = urlparse(target).netloc
    if host not in allowed_hosts:
        raise ValueError(f"target host is not allowed: {host}")
    return {"url": target, "method": "POST", "headers": {"Content-Type": "application/json", "Idempotency-Key": event.get("id", "")}, "body": event}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event"); parser.add_argument("--redact", action="append", default=[])
    args = parser.parse_args()
    print(json.dumps(sanitize(json.loads(Path(args.event).read_text()), args.redact), indent=2))


if __name__ == "__main__":
    main()
