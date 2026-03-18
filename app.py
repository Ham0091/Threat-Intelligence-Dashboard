import os
import re
import socket
import requests
from flask import Flask, jsonify, render_template, request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')

app = Flask(__name__, static_folder='static', template_folder='templates')

IP_REGEX = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
DOMAIN_REGEX = r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z0-9-]{1,63})*$'


def resolve_domain_to_ip(query: str) -> str:
    """Resolve a domain to an IP address. If query is already an IP, return it."""
    if re.match(IP_REGEX, query):
        return query
    try:
        ip = socket.gethostbyname(query)
        return ip
    except socket.gaierror as e:
        raise ValueError(f'Could not resolve domain "{query}" to IP address.')


def is_valid_query(query: str) -> bool:
    query = query.strip()
    if not query:
        return False
    if re.match(IP_REGEX, query):
        parts = query.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    if re.match(DOMAIN_REGEX, query):
        return True
    return False


def query_virustotal(query: str) -> dict:
    if not VT_API_KEY:
        raise ValueError('VirusTotal API key not configured')

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{query}' if re.match(IP_REGEX, query) else f'https://www.virustotal.com/api/v3/domains/{query}'
    headers = {'x-apikey': VT_API_KEY}
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    data = resp.json().get('data', {})

    stats = data.get('attributes', {}).get('last_analysis_stats', {})
    score = data.get('attributes', {}).get('reputation', None)
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)

    return {
        'valid': True,
        'reputation_score': score,
        'malicious_detections': malicious,
        'suspicious_detections': suspicious,
        'raw': data,
    }


def query_abuseipdb(ip_or_domain: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        raise ValueError('AbuseIPDB API key not configured')

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': ip_or_domain,
        'maxAgeInDays': 365,
    }
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY,
    }

    resp = requests.get(url, headers=headers, params=params, timeout=15)
    resp.raise_for_status()
    data = resp.json().get('data', {})

    confidence = data.get('abuseConfidenceScore', None)
    total_reports = data.get('totalReports', None)
    country = data.get('countryCode', '')

    return {
        'valid': True,
        'abuse_confidence_score': confidence,
        'total_reports': total_reports,
        'country': country,
        'raw': data,
    }


def query_shodan(ip_or_domain: str) -> dict:
    if not SHODAN_API_KEY:
        raise ValueError('Shodan API key not configured')

    url = f'https://api.shodan.io/shodan/host/{ip_or_domain}'
    params = {'key': SHODAN_API_KEY}
    resp = requests.get(url, params=params, timeout=15)
    if resp.status_code == 404:
        return {'valid': True, 'open_ports': [], 'organization': None, 'raw': {}}
    resp.raise_for_status()
    data = resp.json()

    return {
        'valid': True,
        'open_ports': data.get('ports', []),
        'organization': data.get('org', ''),
        'hostnames': data.get('hostnames', []),
        'raw': data,
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/lookup', methods=['POST'])
def lookup():
    payload = request.get_json(force=True)
    query = payload.get('query', '').strip()

    if not is_valid_query(query):
        return jsonify({'error': 'Invalid IP address or domain'}), 400

    # Resolve domain to IP for AbuseIPDB and Shodan (which work better with IPs)
    resolved_ip = None
    try:
        resolved_ip = resolve_domain_to_ip(query)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    tasks = {}
    tasks['virustotal'] = lambda: query_virustotal(query)
    
    # AbuseIPDB only accepts IPs
    tasks['abuseipdb'] = lambda: query_abuseipdb(resolved_ip)
    
    # Shodan works better with IPs
    tasks['shodan'] = lambda: query_shodan(resolved_ip)

    results = {}
    errors = {}

    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_source = {executor.submit(fn): source for source, fn in tasks.items()}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                results[source] = future.result()
            except Exception as ex:
                errors[source] = str(ex)

    return jsonify({'results': results, 'errors': errors if errors else None})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
