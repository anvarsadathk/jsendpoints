# jsendpoints

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Category](https://img.shields.io/badge/recon-js--analysis-orange)

Mines JavaScript for **hidden API endpoints** and **leaked secrets**. Feed it a live `.js` URL, a local file, or a list — it returns de-duplicated endpoints plus high-signal secret matches (AWS/GCP keys, Slack/GitHub/Stripe tokens, JWTs, private-key blocks, Firebase URLs).

## Features
- Endpoint extraction: relative paths, path-like strings, absolute URLs
- 10 secret detectors tuned for low false positives
- `--secrets-only` mode for triage
- Works on URLs **or** local files, single or `--list`
- Zero dependencies

## Install
```bash
git clone https://github.com/anvarsadathk/jsendpoints.git
cd jsendpoints
python3 jsendpoints.py --help
```

## Usage
```bash
# A single live script
python3 jsendpoints.py https://example.com/static/app.js

# A local bundle
python3 jsendpoints.py ./main.bundle.js -o endpoints.txt

# Many scripts at once, secrets only
python3 jsendpoints.py -l js_urls.txt --secrets-only
```

Typical recon chain:
```bash
# collect JS URLs however you like, then:
python3 jsendpoints.py -l js_urls.txt -o endpoints.txt
```

## ⚠️ Responsible use
Secret matches can be live credentials. **Never** use found secrets to access systems — report them through the program's disclosure channel. Analyze only in-scope assets.

## License
MIT © Anvar Sadath K.
