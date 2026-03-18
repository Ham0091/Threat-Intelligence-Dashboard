import os
import re
import socket
import requests
import json
import hashlib
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from pathlib import Path
from sqlalchemy import create_engine, Column, String, DateTime, Float, Integer, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
URLHAUS_API_KEY = os.getenv('URLHAUS_API_KEY', 'public')
OTXAPI_KEY = os.getenv('OTXAPI_KEY')

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# Database setup
db_path = Path(__file__).parent / 'threat_intel.db'
engine = create_engine(f'sqlite:///{db_path}', echo=False)
Base = declarative_base()
Session = sessionmaker(bind=engine)

# Models
class ScanResult(Base):
    __tablename__ = 'scan_results'
    id = Column(Integer, primary_key=True)
    query = Column(String(255), unique=False, index=True)
    query_hash = Column(String(64), unique=False, index=True)
    query_type = Column(String(10))  # 'ip', 'domain', 'url'
    threat_score = Column(Float, default=0.0)
    results = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    expires_at = Column(DateTime)

Base.metadata.create_all(engine)

IP_REGEX = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
DOMAIN_REGEX = r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z0-9-]{1,63})*$'
URL_REGEX = r'^https?://[^\s/$.?#].[^\s]*$'

CACHE_TTL = 3600  # 1 hour


def get_query_type(query: str) -> str:
    """Determine if query is IP, domain, or URL"""
    if re.match(URL_REGEX, query):
        return 'url'
    if re.match(IP_REGEX, query):
        return 'ip'
    if re.match(DOMAIN_REGEX, query):
        return 'domain'
    return 'unknown'


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
    if re.match(URL_REGEX, query):
        return True
    if re.match(IP_REGEX, query):
        parts = query.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    if re.match(DOMAIN_REGEX, query):
        return True
    return False


def get_cached_result(query_hash: str) -> dict:
    """Check if we have a cached result that's still valid"""
    session = Session()
    result = session.query(ScanResult).filter(
        ScanResult.query_hash == query_hash,
        ScanResult.expires_at > datetime.utcnow()
    ).first()
    session.close()
    return result.results if result else None


def cache_result(query: str, query_type: str, threat_score: float, results: dict):
    """Cache scan results"""
    query_hash = hashlib.sha256(query.lower().encode()).hexdigest()
    session = Session()
    scan = ScanResult(
        query=query,
        query_hash=query_hash,
        query_type=query_type,
        threat_score=threat_score,
        results=results,
        expires_at=datetime.utcnow() + timedelta(seconds=CACHE_TTL)
    )
    session.add(scan)
    session.commit()
    session.close()


def calculate_threat_score(results: dict) -> float:
    """Calculate composite threat score (0-100)"""
    score = 0.0
    weight_counts = {
        'virustotal': 0.35,
        'abuseipdb': 0.35,
        'shodan': 0.20,
        'urlhaus': 0.10
    }
    
    # VirusTotal
    if results.get('virustotal') and results['virustotal'].get('valid'):
        vt_malicious = results['virustotal'].get('malicious_detections', 0)
        vt_reputation = results['virustotal'].get('reputation_score', 0)
        vt_score = min(100, vt_malicious * 3 + abs(vt_reputation) * 2)
        score += vt_score * weight_counts['virustotal']
    
    # AbuseIPDB
    if results.get('abuseipdb') and results['abuseipdb'].get('valid'):
        abuse_score = results['abuseipdb'].get('abuse_confidence_score', 0)
        score += abuse_score * weight_counts['abuseipdb']
    
    # Shodan
    if results.get('shodan') and results['shodan'].get('valid'):
        ports = results['shodan'].get('open_ports', [])
        shodan_score = min(100, len(ports) * 5)
        score += shodan_score * weight_counts['shodan']
    
    # URLhaus
    if results.get('urlhaus') and results['urlhaus'].get('valid'):
        urlhaus_score = results['urlhaus'].get('threat_score', 0)
        score += urlhaus_score * weight_counts['urlhaus']
    
    return min(100, score)


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


def query_urlhaus(url: str) -> dict:
    """Query URLhaus for malicious URL information"""
    try:
        api_url = 'https://urlhaus-api.abuse.ch/v1/url/'
        params = {'url': url}
        resp = requests.get(api_url, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        
        if data.get('query_status') == 'ok':
            return {
                'valid': True,
                'threat_score': 100 if data.get('threat') else 0,
                'threat': data.get('threat'),
                'status': data.get('status'),
                'raw': data,
            }
        return {'valid': True, 'threat_score': 0, 'threat': None, 'raw': {}}
    except Exception as e:
        return {'valid': False, 'error': str(e)}


def query_otx(query: str) -> dict:
    """Query AlienVault OTX for threat intelligence"""
    try:
        if not OTXAPI_KEY:
            return {'valid': False, 'error': 'OTX API key not configured'}
        
        query_type = 'IPv4' if re.match(IP_REGEX, query) else 'domain'
        url = f'https://otx.alienvault.com/api/v1/indicators/{query_type}/{query}/general'
        headers = {'X-OTX-API-KEY': OTXAPI_KEY}
        
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            return {'valid': True, 'found': False, 'raw': {}}
        resp.raise_for_status()
        data = resp.json()
        
        return {
            'valid': True,
            'found': True,
            'pulse_count': data.get('pulse_count', 0),
            'reputation': data.get('reputation'),
            'raw': data,
        }
    except Exception as e:
        return {'valid': False, 'error': str(e)}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/lookup', methods=['POST'])
def lookup():
    payload = request.get_json(force=True)
    query = payload.get('query', '').strip()

    if not is_valid_query(query):
        return jsonify({'error': 'Invalid IP address, domain, or URL'}), 400

    query_type = get_query_type(query)
    query_hash = hashlib.sha256(query.lower().encode()).hexdigest()
    
    # Check cache
    cached = get_cached_result(query_hash)
    if cached:
        return jsonify({'results': cached, 'from_cache': True})

    # Resolve domain to IP for services that need it
    resolved_ip = None
    if query_type in ['domain', 'url']:
        try:
            resolved_ip = resolve_domain_to_ip(query)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
    else:
        resolved_ip = query

    tasks = {}
    if query_type in ['ip', 'domain']:
        tasks['virustotal'] = lambda: query_virustotal(query)
        tasks['abuseipdb'] = lambda: query_abuseipdb(resolved_ip)
        tasks['shodan'] = lambda: query_shodan(resolved_ip)
        tasks['otx'] = lambda: query_otx(query)
    elif query_type == 'url':
        tasks['virustotal'] = lambda: query_virustotal(query)
        tasks['urlhaus'] = lambda: query_urlhaus(query)

    results = {}
    errors = {}

    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_source = {executor.submit(fn): source for source, fn in tasks.items()}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                results[source] = future.result()
            except Exception as ex:
                errors[source] = str(ex)

    # Calculate threat score
    threat_score = calculate_threat_score(results)
    
    # Cache results
    response_data = {
        'results': results,
        'threat_score': threat_score,
        'query': query,
        'query_type': query_type,
        'timestamp': datetime.utcnow().isoformat(),
        'errors': errors if errors else None
    }
    cache_result(query, query_type, threat_score, response_data)
    
    return jsonify(response_data)


@app.route('/api/history', methods=['GET'])
def get_history():
    """Get scan history"""
    limit = request.args.get('limit', 50, type=int)
    session = Session()
    results = session.query(ScanResult).order_by(
        ScanResult.created_at.desc()
    ).limit(limit).all()
    session.close()
    
    history = [{
        'query': r.query,
        'query_type': r.query_type,
        'threat_score': r.threat_score,
        'timestamp': r.created_at.isoformat()
    } for r in results]
    
    return jsonify(history)


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    session = Session()
    
    total_scans = session.query(ScanResult).count()
    avg_threat_score = session.query(
        __import__('sqlalchemy').func.avg(ScanResult.threat_score)
    ).scalar() or 0
    
    query_type_counts = session.query(
        ScanResult.query_type,
        __import__('sqlalchemy').func.count(ScanResult.id)
    ).group_by(ScanResult.query_type).all()
    
    session.close()
    
    return jsonify({
        'total_scans': total_scans,
        'average_threat_score': round(avg_threat_score, 2),
        'query_types': dict(query_type_counts)
    })


@app.route('/api/export', methods=['POST'])
def export_results():
    """Export scan results as JSON"""
    payload = request.get_json(force=True)
    data = payload.get('data')
    
    if not data:
        return jsonify({'error': 'No data to export'}), 400
    
    filename = f"threat_intel_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    
    return jsonify({
        'success': True,
        'filename': filename,
        'data': data
    })


@app.route('/api/compare', methods=['POST'])
def compare_queries():
    """Compare multiple queries"""
    payload = request.get_json(force=True)
    queries = payload.get('queries', [])
    
    if len(queries) < 2:
        return jsonify({'error': 'Need at least 2 queries to compare'}), 400
    
    comparison_results = {}
    
    for query in queries:
        query_hash = hashlib.sha256(query.lower().encode()).hexdigest()
        cached = get_cached_result(query_hash)
        if cached:
            comparison_results[query] = cached
    
    return jsonify(comparison_results)


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
