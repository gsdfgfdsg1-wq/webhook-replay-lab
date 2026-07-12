# webhook-replay-lab

A dependency-free toolkit for verifying webhook signatures, sanitizing captured events, and preparing controlled replay requests.

## Quick start

```bash
python webhooks.py event.json --redact /data/email --redact /payment/token
```

The library verifies SHA-256 HMAC signatures, redacts selected JSON paths without mutating source events, and creates replay request descriptors only for an explicit host allowlist. It never sends HTTP requests itself.

## Test

```bash
python -m unittest discover -v
```

## License

MIT.
