# Threat Intelligence Dashboard

A Flask web app that queries multiple threat intelligence APIs for a given IP, domain, or URL and returns a composite threat score.

![Dashboard screenshot](screenshot.png)

## What it does

Enter an IP address, domain, or URL and the app queries all configured sources in parallel, then returns the raw results alongside a weighted threat score from 0 to 100. Results are cached for one hour in a local SQLite database and scan history is persisted across restarts. The frontend streams results as each source responds so you see data as it arrives.

## Data sources

| Source | What it provides | Free tier |
|---|---|---|
| VirusTotal | Malicious detection count, reputation score from security vendor scans | Yes (4 lookups/min) |
| AbuseIPDB | Abuse confidence score and total report count for an IP | Yes (1,000 checks/day) |
| GreyNoise | IP noise classification (benign/malicious/unknown), whether IP is internet scanner traffic | Yes |
| CrowdSec | Community-sourced IP reputation, attack behaviors, overall score | Yes |
| URLhaus | Whether a URL appears in the URLhaus malicious URL database | Yes (no key needed) |
| IPInfo | Geolocation, hostname, ASN, and org for an IP | Yes (50,000 req/month) |
| WHOIS | Domain registrar, creation date, expiration date, name servers | No key needed |
| DNS | A, AAAA, MX, NS, TXT, SOA records for a domain | No key needed |
| SSL | Certificate subject, issuer, and validity window for a domain | No key needed |
| crt.sh | Subdomain enumeration from certificate transparency logs | No key needed |

## Threat score

The score is calculated in `calculate_threat_score()` and capped at 100.

VirusTotal contributes 30%: the per-source sub-score is `min(100, malicious_detections × 3 + abs(reputation) × 2)` — capped at 100 before weighting — then multiplied by 0.30.

AbuseIPDB contributes 30%: the raw `abuse_confidence_score` (0–100) multiplied by 0.30.

GreyNoise adds flat points: +20 if the IP is classified malicious, +10 if it is tagged as internet background noise.

CrowdSec adds flat points: +25 if the IP has a bad reputation flag, +15 if its overall score exceeds 50.

URLhaus contributes 10%: 100 if a URL is listed as a threat, 0 otherwise, multiplied by 0.10.

WHOIS, DNS, and SSL each contribute small adjustments (under 1.5 points total) based on missing records or certificates.

## Setup

1. Requires Python 3.8+ and pip.

2. Clone the repository:
   ```bash
   git clone https://github.com/Ham0091/Threat-Intelligence-Dashboard.git
   cd Threat-Intelligence-Dashboard
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Copy the env template and fill in your API keys:
   ```bash
   cp .env.example .env
   ```

5. Where to get each key:
   - VirusTotal: https://www.virustotal.com/gui/settings/api
   - AbuseIPDB: https://www.abuseipdb.com/api
   - GreyNoise: https://www.greynoise.io/
   - CrowdSec: https://app.crowdsec.net/
   - IPInfo: https://ipinfo.io/

6. Run the app:
   ```bash
   python app.py
   ```
   Open http://localhost:5001 in a browser.

## API keys: required vs optional

VirusTotal and AbuseIPDB are effectively required for a useful score. Without those keys the app continues running but skips those sources, leaving up to 60% of the threat score unweighted. The result panels for those sources will show an error.

GreyNoise, CrowdSec, and IPInfo degrade gracefully: those result panels will show an error but the rest of the results still return. URLhaus works without a key (the default value is `public`).

WHOIS, DNS, SSL, and crt.sh require no keys and always run.

## Known limitations

- VirusTotal free tier is limited to 4 lookups per minute. Rapid successive queries will hit rate limits.
- AbuseIPDB free tier allows 1,000 checks per day. Heavy usage will exhaust the quota quickly.
- GreyNoise and CrowdSec only return useful data for IPs. They are skipped for domain and URL queries.
- URLhaus is only queried for URL inputs. It does not check bare IPs or domains.
- The threat score does not account for false positives. A high VirusTotal detection count on a well-known CDN IP will still produce a high score.
- The 1-hour cache means re-scanning a recently checked indicator returns stale data.
- crt.sh occasionally returns 503 errors and has no SLA for availability.

## Project structure

```
Threat-Intelligence-Dashboard/
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── static/
│   ├── style.css
│   └── script.js
├── templates/
│   └── index.html
└── tests/
```

## License

MIT
