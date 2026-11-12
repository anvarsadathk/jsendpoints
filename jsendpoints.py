#!/usr/bin/env python3
"""
jsendpoints - extract endpoints and leaked secrets from JavaScript.

Point it at a URL, a local .js file, or a list of either. It pulls out
relative/absolute paths, full URLs, and high-signal secret patterns
(API keys, tokens, JWTs, cloud keys) for an authorized recon workflow.

Author: Anvar Sadath K.  |  License: MIT
Only analyze assets you own or are explicitly authorized to assess.
"""
import argparse
import re
import sys
import urllib.request

# --- endpoint patterns ------------------------------------------------------
ENDPOINT_RE = re.compile(r"""
    (?:"|')                       # opening quote
    (
        (?:/|\.\./|\./)[^"'\s><]{1,}      # relative path
        |
        [a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}   # path-like
        |
        https?://[^"'\s><]{3,}            # absolute URL
    )
    (?:"|')
""", re.VERBOSE)

# --- secret patterns (name -> regex) ---------------------------------------
SECRETS = {
    "AWS Access Key":    re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key":    re.compile(r"(?i)aws(.{0,20})?(secret|private).{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Google API Key":    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack Token":       re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "GitHub Token":      re.compile(r"gh[pousr]_[0-9A-Za-z]{36}"),
    "Stripe Key":        re.compile(r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}"),
    "JWT":               re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "Generic API Key":   re.compile(r"(?i)(?:api[_-]?key|apikey|secret)['\"\s:=]{1,6}['\"][0-9a-zA-Z\-_]{16,45}['\"]"),
    "Private Key Block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "Firebase URL":      re.compile(r"[a-z0-9\-]+\.firebaseio\.com"),
}


def load(source: str, timeout: int = 20) -> str:
    if source.startswith("http://") or source.startswith("https://"):
        req = urllib.request.Request(source, headers={"User-Agent": "jsendpoints/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    with open(source, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def extract(content: str):
    endpoints = sorted({m.group(1) for m in ENDPOINT_RE.finditer(content)
                        if len(m.group(1)) > 1 and not m.group(1).startswith("//")})
    secrets = []
    for name, rx in SECRETS.items():
        for m in rx.finditer(content):
            secrets.append((name, m.group(0)[:80]))
    return endpoints, secrets


def main():
    p = argparse.ArgumentParser(description="Extract endpoints and secrets from JavaScript.")
    p.add_argument("source", nargs="?", help="URL or path to a .js file")
    p.add_argument("-l", "--list", help="file with one URL/path per line")
    p.add_argument("--secrets-only", action="store_true", help="only print secret findings")
    p.add_argument("-o", "--output", help="write endpoints to file")
    args = p.parse_args()

    sources = []
    if args.list:
        with open(args.list) as f:
            sources += [x.strip() for x in f if x.strip() and not x.startswith("#")]
    if args.source:
        sources.append(args.source)
    if not sources:
        p.error("provide a source URL/file or --list")

    all_endpoints, all_secrets = set(), []
    for src in sources:
        try:
            content = load(src)
        except Exception as e:
            print(f"[!] {src}: {e}", file=sys.stderr)
            continue
        eps, secs = extract(content)
        all_endpoints.update(eps)
        for name, val in secs:
            all_secrets.append((src, name, val))

    if all_secrets:
        print("[!] POTENTIAL SECRETS", file=sys.stderr)
        for src, name, val in all_secrets:
            print(f"[SECRET] {name}: {val}  ({src})")

    if not args.secrets_only:
        for ep in sorted(all_endpoints):
            print(ep)

    print(f"[+] {len(all_endpoints)} endpoints, {len(all_secrets)} secret hits", file=sys.stderr)
    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(sorted(all_endpoints)) + "\n")
        print(f"[+] Endpoints saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
