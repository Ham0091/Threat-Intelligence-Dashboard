import os
import re
import socket
import requests
import json
import hashlib
import time
import logging
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from flask import Flask, jsonify, render_template, request, Response, stream_with_context
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError
from queue import Queue
from dotenv import load_dotenv
from pathlib import Path
from sqlalchemy import create_engine, Column, String, DateTime, Float, Integer, Text, JSON, func
from sqlalchemy.orm import declarative_base, sessionmaker
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # stderr by default
    ]
)
logger = logging.getLogger(__name__)

env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

VT_API_KEY = os.getenv('VT_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
URLHAUS_API_KEY = os.getenv('URLHAUS_API_KEY', 'public')
GREYNOISE_API_KEY = os.getenv('GREYNOISE_API_KEY')
CROWDSEC_API_KEY = os.getenv('CROWDSEC_API_KEY')
IPINFO_TOKEN = os.getenv('IPINFO_TOKEN')


def serialize_for_db(obj):
    """JSON serializer for objects not serializable by the default encoder."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def make_json_safe(obj):
    """Recursively convert a dict/list to be JSON-safe (e.g. datetime -> isoformat)."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [make_json_safe(i) for i in obj]
    return obj


app = Flask(__name__, static_folder='static', template_folder='templates')

# Restrict CORS to localhost only
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://localhost:*",
            "http://127.0.0.1:*",
            "http://[::1]:*"  # IPv6 localhost
        ],
        "methods": ["GET", "POST", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# Configure requests session with retry adapter
retry_strategy = Retry(
    total=2,
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503],
    allowed_methods=['GET', 'POST']
)
adapter = HTTPAdapter(max_retries=retry_strategy)
http_session = requests.Session()
http_session.mount('http://', adapter)
http_session.mount('https://', adapter)


def _timed_query(fn):
    """Execute fn and inject duration_ms (int, milliseconds) into the returned dict."""
    start = time.perf_counter()
    result = fn()
    result['duration_ms'] = round((time.perf_counter() - start) * 1000)
    return result


def _check_response(resp):
    """Raise ValueError with specific HTTP error detail if the response is not 2xx."""
    if not resp.ok:
        hint = ''
        if resp.status_code in (401, 403):
            hint = ' — check API key'
        elif resp.status_code == 429:
            hint = ' — rate limited'
        raise ValueError(f'HTTP {resp.status_code} {resp.reason}{hint}')


# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[]
)

# Database setup
db_path = Path(__file__).parent / 'threat_intel.db'
engine = create_engine(f'sqlite:///{db_path}', echo=False)
Base = declarative_base()
Session = sessionmaker(bind=engine)

@contextmanager
def get_db_session():
    """Context manager for database sessions - ensures proper cleanup"""
    session = Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

# Models
class ScanResult(Base):
    __tablename__ = 'scan_results'
    id = Column(Integer, primary_key=True)
    query = Column(String(255), unique=False, index=True)
    query_hash = Column(String(64), unique=False, index=True)
    query_type = Column(String(10))  # 'ip', 'domain', 'url'
    threat_score = Column(Float, default=0.0)
    results = Column(JSON)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    expires_at = Column(DateTime)

Base.metadata.create_all(engine)


def check_api_keys():
    """Check that all required API keys are configured and log warnings for missing ones"""
    api_keys = {
        'VT_API_KEY': 'VirusTotal',
        'ABUSEIPDB_API_KEY': 'AbuseIPDB',
        'GREYNOISE_API_KEY': 'GreyNoise',
        'CROWDSEC_API_KEY': 'CrowdSec CTI',
        'IPINFO_TOKEN': 'IPinfo',
    }
    
    logger.info('Checking API key configuration...')
    missing_keys = []
    
    for env_var, source_name in api_keys.items():
        key_value = os.getenv(env_var)
        if not key_value:
            logger.warning(f'Missing API key: {env_var} - {source_name} will be unavailable')
            missing_keys.append(source_name)
    
    if not missing_keys:
        logger.info('All required API keys are configured')
    else:
        logger.warning(f'Configuration incomplete: {len(missing_keys)} source(s) will be unavailable')


# Check API keys on startup
check_api_keys()

IP_REGEX = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
IPV6_REGEX = r'^(([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}|::1|::(?:[0-9a-fA-F]{0,4}:){0,6}[0-9a-fA-F]{0,4})$'
DOMAIN_REGEX = r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z0-9-]{1,63})+$'
URL_REGEX = r'^https?://[^\s/$.?#].[^\s]*$'

CACHE_TTL = 3600  # 1 hour


def route_input(query: str) -> dict:
    """
    Smart input router that detects input type and validates routing.
    Returns a dict with 'query_type', 'valid', and optionally 'error'.
    """
    query = query.strip()
    
    # Detect input type
    if re.match(URL_REGEX, query):
        query_type = 'url'
    elif re.match(IP_REGEX, query):
        # Validate IPv4 octets are 0-255
        parts = query.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            query_type = 'ipv4'
        else:
            return {'valid': False, 'error': 'Invalid IPv4 address (octets must be 0-255)'}
    elif re.match(IPV6_REGEX, query):
        query_type = 'ipv6'
    elif re.match(DOMAIN_REGEX, query):
        query_type = 'domain'
    else:
        return {
            'valid': False,
            'error': 'Unrecognized input. Expected: IPv4, IPv6, domain name, or URL (http/https)'
        }
    
    return {'valid': True, 'query_type': query_type}


def sanitize_input(query: str) -> tuple[bool, str]:
    """
    Sanitize input by rejecting dangerous shell special characters.
    Returns (valid: bool, error_msg: str)
    """
    dangerous_chars = {
        ';': 'semicolon',
        '`': 'backtick',
        '|': 'pipe',
        "'": 'single quote',
        '"': 'double quote',
        '$': 'dollar sign',
        '&': 'ampersand',
        '<': 'less-than',
        '>': 'greater-than',
        '(': 'parenthesis',
        ')': 'parenthesis',
        '{': 'brace',
        '}': 'brace',
        '\\': 'backslash',
        '\n': 'newline',
        '\r': 'carriage return',
        '\0': 'null byte',
    }
    
    for char, name in dangerous_chars.items():
        if char in query:
            return False, f'Invalid character detected: {name} ({repr(char)})'
    
    return True, ''


def get_query_type(query: str) -> str:
    """Determine if query is IP (v4/v6), domain, or URL"""
    if re.match(URL_REGEX, query):
        return 'url'
    if re.match(IP_REGEX, query):
        return 'ip'
    if re.match(IPV6_REGEX, query):
        return 'ip'
    if re.match(DOMAIN_REGEX, query):
        return 'domain'
    return 'unknown'


def resolve_domain_to_ip(query: str) -> str:
    """Resolve a domain to an IP address. If query is already an IP, return it."""
    if re.match(IP_REGEX, query):
        return query
    # Extract domain from URL if needed
    domain = query
    if query.startswith('http://') or query.startswith('https://'):
        try:
            from urllib.parse import urlparse
            domain = urlparse(query).netloc
        except:
            domain = query
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        raise ValueError(f'Could not resolve domain "{domain}" to IP address.')


def is_valid_query(query: str) -> bool:
    query = query.strip()
    if not query:
        return False
    if len(query) > 255:
        return False
    if re.match(URL_REGEX, query):
        return True
    if re.match(IP_REGEX, query):
        parts = query.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    if re.match(IPV6_REGEX, query):
        return True
    if re.match(DOMAIN_REGEX, query):
        return True
    return False


def get_cached_result(query_hash: str) -> dict:
    """Check if we have a cached result that's still valid"""
    with get_db_session() as session:
        result = session.query(ScanResult).filter(
            ScanResult.query_hash == query_hash,
            ScanResult.expires_at > datetime.now(timezone.utc)
        ).first()
        return result.results if result else None


def cache_result(query: str, query_type: str, threat_score: float, results: dict):
    """Cache scan results"""
    query_hash = hashlib.sha256(query.lower().encode()).hexdigest()
    with get_db_session() as session:
        safe_results = make_json_safe(results)
        scan = ScanResult(
            query=query,
            query_hash=query_hash,
            query_type=query_type,
            threat_score=threat_score,
            results=safe_results,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=CACHE_TTL)
        )
        session.add(scan)


def calculate_threat_score(results: dict) -> float:
    """Calculate composite threat score (0-100)"""
    score = 0.0

    # VirusTotal (weight: 0.30)
    if results.get('virustotal') and results['virustotal'].get('valid'):
        vt_malicious = results['virustotal'].get('malicious_detections', 0)
        vt_reputation = results['virustotal'].get('reputation_score', 0)
        vt_score = min(100, vt_malicious * 3 + abs(vt_reputation) * 2)
        score += vt_score * 0.30

    # AbuseIPDB (weight: 0.30)
    if results.get('abuseipdb') and results['abuseipdb'].get('valid'):
        abuse_score = results['abuseipdb'].get('abuse_confidence_score', 0)
        score += abuse_score * 0.30

    # GreyNoise — flat point additions
    if results.get('greynoise') and results['greynoise'].get('valid'):
        gn = results['greynoise']
        if gn.get('classification') == 'malicious':
            score += 20
        if gn.get('noise'):
            score += 10

    # CrowdSec CTI — flat point additions
    if results.get('crowdsec') and results['crowdsec'].get('valid'):
        cs = results['crowdsec']
        if cs.get('is_bad'):
            score += 25
        elif (cs.get('overall_score') or 0) > 50:
            score += 15

    # URLhaus (weight: 0.10)
    if results.get('urlhaus') and results['urlhaus'].get('valid'):
        urlhaus_score = results['urlhaus'].get('threat_score', 0)
        score += urlhaus_score * 0.10

    # WHOIS
    if results.get('whois') and results['whois'].get('valid') and not results['whois'].get('is_ip'):
        expiration = results['whois'].get('expiration_date', 'N/A')
        if 'expiration_date' in results['whois'] and expiration != 'N/A':
            score += 5 * 0.10

    # DNS
    if results.get('dns') and results['dns'].get('valid') and not results['dns'].get('is_ip'):
        records = results['dns'].get('records', {})
        if not records.get('A'):
            score += 10 * 0.03

    # SSL
    if results.get('ssl') and results['ssl'].get('valid') and not results['ssl'].get('is_ip'):
        if not results['ssl'].get('certificate'):
            score += 15 * 0.02

    return min(100, score)


def query_virustotal(query: str) -> dict:
    if not VT_API_KEY:
        raise ValueError('VirusTotal API key not configured')

    # Extract domain from URL if necessary
    check_query = query
    if query.startswith('http://') or query.startswith('https://'):
        try:
            from urllib.parse import urlparse
            check_query = urlparse(query).netloc
        except:
            check_query = query
    
    if re.match(IP_REGEX, check_query):
        api_url = f'https://www.virustotal.com/api/v3/ip_addresses/{check_query}'
    else:
        api_url = f'https://www.virustotal.com/api/v3/domains/{check_query}'
    
    headers = {'x-apikey': VT_API_KEY}
    resp = http_session.get(api_url, headers=headers, timeout=15)
    _check_response(resp)
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

    resp = http_session.get(url, headers=headers, params=params, timeout=15)
    _check_response(resp)
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


def query_greynoise(ip: str) -> dict:
    """Query GreyNoise Community API for IP noise/classification data"""
    try:
        if not GREYNOISE_API_KEY:
            return {'valid': False, 'error': 'GreyNoise API key not configured'}

        url = f'https://api.greynoise.io/v3/community/{ip}'
        headers = {'key': GREYNOISE_API_KEY}
        resp = requests.get(url, headers=headers, timeout=8)
        if resp.status_code == 404:
            # IP not in GreyNoise dataset
            return {
                'valid': True,
                'classification': 'unknown',
                'noise': False,
                'riot': False,
                'name': None,
                'last_seen': None,
                'raw': {},
            }
        _check_response(resp)
        data = resp.json()
        return {
            'valid': True,
            'classification': data.get('classification', 'unknown'),
            'noise': data.get('noise', False),
            'riot': data.get('riot', False),
            'name': data.get('name'),
            'last_seen': data.get('last_seen'),
            'raw': data,
        }
    except Exception as e:
        return {'valid': False, 'error': str(e)}


def query_urlhaus(url: str) -> dict:
    """Query URLhaus for malicious URL information"""
    try:
        api_url = 'https://urlhaus-api.abuse.ch/v1/url/'
        params = {'url': url}
        resp = http_session.get(api_url, params=params, timeout=15)
        _check_response(resp)
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


def query_crowdsec(ip: str) -> dict:
    """Query CrowdSec CTI API for IP threat intelligence"""
    try:
        if not CROWDSEC_API_KEY:
            return {'valid': False, 'error': 'CrowdSec API key not configured'}

        url = f'https://cti.api.crowdsec.net/v2/smoke/{ip}'
        headers = {'x-api-key': CROWDSEC_API_KEY}
        resp = requests.get(url, headers=headers, timeout=8)
        if resp.status_code == 404:
            # IP not in CrowdSec dataset
            return {
                'valid': True,
                'is_bad': False,
                'overall_score': 0,
                'behaviors': [],
                'last_seen': None,
                'raw': {},
            }
        _check_response(resp)
        data = resp.json()

        behaviors = [d.get('name', '') for d in (data.get('attack_details') or []) if d.get('name')]
        overall_score = (data.get('scores') or {}).get('overall', {}).get('score', 0)
        reputation = data.get('reputation', '')
        is_bad = reputation in ('malicious', 'suspicious', 'known_attacker')
        history = data.get('history') or {}
        last_seen = history.get('last_seen')

        return {
            'valid': True,
            'is_bad': is_bad,
            'overall_score': overall_score,
            'behaviors': behaviors,
            'last_seen': last_seen,
            'reputation': reputation,
            'raw': data,
        }
    except Exception as e:
        return {'valid': False, 'error': str(e)}


def query_whois(domain: str) -> dict:
    """Query WHOIS information for a domain"""
    try:
        import whois
        
        # Extract domain from URL if necessary
        check_domain = domain
        if domain.startswith('http://') or domain.startswith('https://'):
            try:
                from urllib.parse import urlparse
                check_domain = urlparse(domain).netloc
            except:
                check_domain = domain
        
        # Skip WHOIS for IP addresses (they need IP WHOIS, not domain WHOIS)
        if re.match(IP_REGEX, check_domain):
            return {'valid': True, 'is_ip': True, 'raw': {}}
        
        # NOTE: signal.alarm() cannot be used reliably in worker threads.
        # Rely on the caller to enforce timeouts via the thread/future API.
        whois_data = whois.whois(check_domain)

        return {
            'valid': True,
            'domain_name': whois_data.get('domain_name', [None])[0] if isinstance(whois_data.get('domain_name'), list) else whois_data.get('domain_name'),
            'registrar': whois_data.get('registrar', 'N/A'),
            'creation_date': str(whois_data.get('creation_date', 'N/A')),
            'expiration_date': str(whois_data.get('expiration_date', 'N/A')),
            'name_servers': whois_data.get('name_servers', []),
            'registrant_country': whois_data.get('registrant_country', 'N/A'),
            'raw': dict(whois_data),
        }
    except Exception as e:
        return {'valid': False, 'error': str(e), 'raw': {}}


def query_dns(domain: str) -> dict:
    """Query DNS records for a domain"""
    try:
        import dns.resolver
        
        # Extract domain from URL if necessary
        check_domain = domain
        if domain.startswith('http://') or domain.startswith('https://'):
            try:
                from urllib.parse import urlparse
                check_domain = urlparse(domain).netloc
            except:
                check_domain = domain
        
        # Skip DNS for IP addresses
        if re.match(IP_REGEX, check_domain):
            return {'valid': True, 'is_ip': True, 'raw': {}}
        
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        resolver.timeout = 5
        dns_records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'SOA': []
        }
        
        # Query each record type
        for record_type in dns_records.keys():
            try:
                answers = resolver.resolve(check_domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
                pass
            except Exception:
                pass
        
        return {
            'valid': True,
            'records': dns_records,
            'domain': check_domain,
            'raw': dns_records,
        }
    except Exception as e:
        return {'valid': False, 'error': str(e), 'raw': {}}


def query_ssl(domain: str) -> dict:
    """Query SSL certificate information for a domain"""
    try:
        import ssl
        import socket
        from OpenSSL import crypto
        
        # Extract domain from URL if necessary
        check_domain = domain
        if domain.startswith('http://') or domain.startswith('https://'):
            try:
                from urllib.parse import urlparse
                check_domain = urlparse(domain).netloc
            except:
                check_domain = domain
        
        # Skip SSL check for IP addresses
        if re.match(IP_REGEX, check_domain):
            return {'valid': True, 'is_ip': True, 'raw': {}}
        
        context = ssl.create_default_context()
        with socket.create_connection((check_domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=check_domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
                
                subject = dict(x509.get_subject().get_components())
                issuer = dict(x509.get_issuer().get_components())
                
                # Convert bytes to strings
                subject = {k.decode() if isinstance(k, bytes) else k: 
                          v.decode() if isinstance(v, bytes) else v 
                          for k, v in subject.items()}
                issuer = {k.decode() if isinstance(k, bytes) else k: 
                         v.decode() if isinstance(v, bytes) else v 
                         for k, v in issuer.items()}
                
                cert_info = {
                    'subject': subject,
                    'issuer': issuer,
                    'version': x509.get_version(),
                    'serial_number': str(x509.get_serial_number()),
                    'not_before': x509.get_notBefore().decode() if isinstance(x509.get_notBefore(), bytes) else str(x509.get_notBefore()),
                    'not_after': x509.get_notAfter().decode() if isinstance(x509.get_notAfter(), bytes) else str(x509.get_notAfter()),
                    'signature_algorithm': x509.get_signature_algorithm().decode() if isinstance(x509.get_signature_algorithm(), bytes) else str(x509.get_signature_algorithm()),
                }
                
                return {
                    'valid': True,
                    'certificate': cert_info,
                    'domain': check_domain,
                    'raw': cert_info,
                }
    except socket.timeout:
        return {'valid': False, 'error': 'SSL connection timeout', 'raw': {}}
    except ConnectionRefusedError:
        return {'valid': False, 'error': 'SSL connection refused (port 443 not open)', 'raw': {}}
    except ssl.SSLError as e:
        return {'valid': False, 'error': f'SSL error: {str(e)}', 'raw': {}}
    except Exception as e:
        return {'valid': False, 'error': str(e), 'raw': {}}


def query_crtsh(domain: str) -> dict:
    """Query crt.sh for subdomain enumeration (free, no API key)"""
    try:
        # Extract domain from URL if necessary
        check_domain = domain
        if domain.startswith('http://') or domain.startswith('https://'):
            try:
                from urllib.parse import urlparse
                check_domain = urlparse(domain).netloc
            except:
                check_domain = domain
        
        # Skip crt.sh for IP addresses
        if re.match(IP_REGEX, check_domain) or re.match(IPV6_REGEX, check_domain):
            return {'valid': True, 'is_ip': True, 'raw': {}}
        
        # Get base domain
        parts = check_domain.split('.')
        base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else check_domain
        
        url = f'https://crt.sh/?q=%25.{base_domain}&output=json'
        headers = {"User-Agent": "ThreatIntelDashboard/1.0"}
        resp = None
        for attempt, wait in enumerate([0, 2, 4]):
            if wait:
                time.sleep(wait)
            try:
                resp = http_session.get(url, timeout=15, headers=headers)
                if resp.status_code != 503:
                    break
            except Exception:
                if attempt == 2:
                    raise
        if resp is None or resp.status_code == 503:
            return {'valid': False, 'error': 'crt.sh temporarily unavailable, try again shortly', 'raw': {}}
        if resp.status_code == 429:
            return {'valid': False, 'status': 'rate-limited', 'raw': {}}
        _check_response(resp)
        data = resp.json()
        
        # Extract unique subdomains
        subdomains = set()
        for cert in data:
            name_value = cert.get('name_value', '')
            for subdomain in name_value.split('\n'):
                subdomain = subdomain.strip().lower()
                if subdomain:
                    subdomains.add(subdomain)
        
        sorted_subdomains = sorted(list(subdomains))
        
        return {
            'valid': True,
            'subdomain_count': len(sorted_subdomains),
            'subdomains': sorted_subdomains[:20],  # Return top 20
            'total_found': len(sorted_subdomains),
            'raw': data,
        }
    except Exception as e:
        return {'valid': False, 'error': str(e), 'raw': {}}


def query_ipinfo(ip_or_domain: str) -> dict:
    """Query IPinfo.io for IP intelligence and geolocation"""
    try:
        check_ip = ip_or_domain
        # Resolve domain/URL to IP if needed
        if not re.match(IP_REGEX, ip_or_domain) and not re.match(IPV6_REGEX, ip_or_domain):
            domain = ip_or_domain
            if ip_or_domain.startswith('http://') or ip_or_domain.startswith('https://'):
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(ip_or_domain).netloc
                except Exception:
                    domain = ip_or_domain
            try:
                check_ip = socket.gethostbyname(domain)
            except socket.gaierror:
                return {'valid': True, 'found': False, 'raw': {}}

        token_param = f'?token={IPINFO_TOKEN}' if IPINFO_TOKEN else ''
        url = f'https://ipinfo.io/{check_ip}/json{token_param}'
        # Use plain requests — IPinfo is fast and retries are not needed
        resp = requests.get(url, timeout=5)

        if resp.status_code == 429:
            return {'valid': False, 'status': 'rate-limited', 'raw': {}}

        _check_response(resp)
        data = resp.json()

        result = {
            'valid': True,
            'found': True,
            'ip': data.get('ip', check_ip),
            'hostname': data.get('hostname', 'N/A'),
            'country': data.get('country', 'N/A'),
            'city': data.get('city', 'N/A'),
            'org': data.get('org', 'N/A'),
            'raw': data,
        }

        # Privacy flags (paid tier only — present on paid plans)
        privacy = data.get('privacy') or {}
        if privacy:
            result['vpn'] = privacy.get('vpn', False)
            result['proxy'] = privacy.get('proxy', False)
            result['hosting'] = privacy.get('hosting', False)

        return result
    except Exception as e:
        return {'valid': False, 'error': str(e), 'raw': {}}


def query_secheaders(domain: str) -> dict:
    """Query SecurityHeaders.com (check HTTP security headers)"""
    try:
        # Extract domain from URL if necessary
        check_domain = domain
        if domain.startswith('http://') or domain.startswith('https://'):
            try:
                from urllib.parse import urlparse
                check_domain = urlparse(domain).netloc
            except:
                check_domain = domain
        
        # Skip security headers check for IP addresses
        if re.match(IP_REGEX, check_domain) or re.match(IPV6_REGEX, check_domain):
            return {'valid': True, 'is_ip': True, 'raw': {}}
        
        url = f'https://{check_domain}'
        resp = http_session.get(url, timeout=5, allow_redirects=True)
        
        if resp.status_code == 429:
            return {'valid': False, 'status': 'rate-limited', 'raw': {}}
        
        headers = resp.headers
        
        # Security headers to check
        required_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'X-Frame-Options',
            'X-Content-Type-Options': 'X-Content-Type-Options',
            'Referrer-Policy': 'Referrer-Policy',
            'Permissions-Policy': 'Permissions-Policy'
        }
        
        present = []
        missing = []
        
        for header_name, header_label in required_headers.items():
            if header_name in headers or header_name.lower() in [k.lower() for k in headers.keys()]:
                present.append(header_label)
            else:
                missing.append(header_label)
        
        # Score: A=6, B=5, C=4, D=3, F=2
        score_map = {6: 'A', 5: 'B', 4: 'C', 3: 'D', 2: 'F'}
        grade = score_map.get(len(present), 'F')
        
        return {
            'valid': True,
            'grade': grade,
            'score': len(present),
            'present_headers': present,
            'missing_headers': missing,
            'max_headers': 6,
            'raw': dict(headers),
        }
    except Exception as e:
        return {'valid': False, 'error': str(e), 'raw': {}}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/lookup', methods=['POST'])
@limiter.limit("30/hour")
def lookup():
    payload = request.get_json(force=True)
    query = payload.get('query', '').strip()

    if not is_valid_query(query):
        logger.warning(f'Invalid query format: {query}')
        return jsonify({'error': 'Invalid IP address, domain, or URL'}), 400

    # Sanitize input - reject dangerous shell characters
    sanitized, error_msg = sanitize_input(query)
    if not sanitized:
        logger.warning(f'Sanitization failed for query: {error_msg}')
        return jsonify({'error': f'Input validation failed: {error_msg}'}), 400

    # Route and validate input before querying
    routing = route_input(query)
    if not routing['valid']:
        logger.warning(f'Routing validation failed: {routing["error"]}')
        return jsonify({'error': routing['error']}), 400
    
    query_type = get_query_type(query)
    query_hash = hashlib.sha256(query.lower().encode()).hexdigest()
    
    logger.info(f'Processing lookup for {query_type}: {query}')
    
    # Check cache
    cached = get_cached_result(query_hash)
    if cached:
        logger.info(f'Cache hit for {query} ({query_type})')
        # Stored object is the full response_data dict; return it consistently
        try:
            cached['from_cache'] = True
        except Exception:
            # In case cached is not a dict, wrap it
            cached = {'results': cached, 'from_cache': True}
        return jsonify(cached)

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
        tasks['ipinfo'] = lambda: query_ipinfo(resolved_ip)
        if query_type == 'ip':
            tasks['greynoise'] = lambda: query_greynoise(resolved_ip)
            tasks['crowdsec'] = lambda: query_crowdsec(resolved_ip)
        if query_type == 'domain':
            tasks['whois'] = lambda: query_whois(query)
            tasks['dns'] = lambda: query_dns(query)
            tasks['ssl'] = lambda: query_ssl(query)
            tasks['crtsh'] = lambda: query_crtsh(query)
            tasks['secheaders'] = lambda: query_secheaders(query)
    elif query_type == 'url':
        tasks['virustotal'] = lambda: query_virustotal(query)
        tasks['urlhaus'] = lambda: query_urlhaus(query)
        # Domain-level APIs for URLs (extract domain first)
        try:
            from urllib.parse import urlparse
            url_domain = urlparse(query).netloc
            tasks['ipinfo'] = lambda: query_ipinfo(url_domain)
            tasks['whois'] = lambda: query_whois(url_domain)
            tasks['dns'] = lambda: query_dns(url_domain)
            tasks['ssl'] = lambda: query_ssl(url_domain)
            tasks['crtsh'] = lambda: query_crtsh(url_domain)
            tasks['secheaders'] = lambda: query_secheaders(url_domain)
        except:
            pass

    results = {}
    errors = {}

    # Choose a sensible number of workers based on tasks
    num_workers = min(10, max(1, len(tasks)))
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_source = {executor.submit(_timed_query, fn): source for source, fn in tasks.items()}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                # Guard individual future result retrieval with a timeout
                result = future.result(timeout=30)
                results[source] = result
                
                # Handle 429 rate-limited responses specially
                if result.get('status') == 'rate-limited':
                    logger.warning(f'{source}: Rate limited (429) for {query}')
            except FutureTimeoutError:
                errors[source] = 'Timeout while querying source'
                logger.error(f'{source}: Timeout while querying source for {query}')
            except Exception as ex:
                err_msg = str(ex)
                errors[source] = err_msg
                results[source] = {'valid': False, 'error': err_msg}
                logger.error(f'{source}: {err_msg} for query {query}')

    # Calculate threat score
    threat_score = calculate_threat_score(results)
    
    # Log successful sources
    successful_sources = [s for s in results.keys() if results[s].get('valid')]
    logger.info(f'Lookup completed: {query} ({query_type}) - Threat Score: {threat_score:.1f} - Sources: {len(successful_sources)}/{len(tasks)}')
    
    # Cache results
    response_data = {
        'results': results,
        'threat_score': threat_score,
        'query': query,
        'query_type': query_type,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'errors': errors if errors else None
    }
    cache_result(query, query_type, threat_score, response_data)
    
    return jsonify(response_data)


@app.route('/api/lookup/stream', methods=['POST'])
@limiter.limit("30/hour")
def lookup_stream():
    payload = request.get_json(force=True)
    query = payload.get('query', '').strip()

    if not is_valid_query(query):
        logger.warning(f'Invalid query format: {query}')
        return jsonify({'error': 'Invalid IP address, domain, or URL'}), 400

    sanitized, error_msg = sanitize_input(query)
    if not sanitized:
        logger.warning(f'Sanitization failed for query: {error_msg}')
        return jsonify({'error': f'Input validation failed: {error_msg}'}), 400

    routing = route_input(query)
    if not routing['valid']:
        logger.warning(f'Routing validation failed: {routing["error"]}')
        return jsonify({'error': routing['error']}), 400

    query_type = get_query_type(query)
    query_hash = hashlib.sha256(query.lower().encode()).hexdigest()
    logger.info(f'Processing SSE lookup for {query_type}: {query}')

    cached = get_cached_result(query_hash)
    if cached:
        logger.info(f'Cache hit for {query} ({query_type})')
        def generate_cached():
            for source, data in (cached.get('results') or {}).items():
                yield 'data: ' + json.dumps(make_json_safe({'source': source, 'data': data})) + '\n\n'
            yield ('event: __complete__\ndata: ' + json.dumps(make_json_safe({
                'query': cached.get('query', query),
                'query_type': cached.get('query_type', query_type),
                'threat_score': cached.get('threat_score', 0),
                'timestamp': cached.get('timestamp', ''),
                'from_cache': True,
            })) + '\n\n')
        resp = Response(stream_with_context(generate_cached()), content_type='text/event-stream')
        resp.headers['Cache-Control'] = 'no-cache'
        resp.headers['X-Accel-Buffering'] = 'no'
        return resp

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
        tasks['ipinfo'] = lambda: query_ipinfo(resolved_ip)
        if query_type == 'ip':
            tasks['greynoise'] = lambda: query_greynoise(resolved_ip)
            tasks['crowdsec'] = lambda: query_crowdsec(resolved_ip)
        if query_type == 'domain':
            tasks['whois'] = lambda: query_whois(query)
            tasks['dns'] = lambda: query_dns(query)
            tasks['ssl'] = lambda: query_ssl(query)
            tasks['crtsh'] = lambda: query_crtsh(query)
            tasks['secheaders'] = lambda: query_secheaders(query)
    elif query_type == 'url':
        tasks['virustotal'] = lambda: query_virustotal(query)
        tasks['urlhaus'] = lambda: query_urlhaus(query)
        try:
            from urllib.parse import urlparse
            url_domain = urlparse(query).netloc
            tasks['ipinfo'] = lambda: query_ipinfo(url_domain)
            tasks['whois'] = lambda: query_whois(url_domain)
            tasks['dns'] = lambda: query_dns(url_domain)
            tasks['ssl'] = lambda: query_ssl(url_domain)
            tasks['crtsh'] = lambda: query_crtsh(url_domain)
            tasks['secheaders'] = lambda: query_secheaders(url_domain)
        except Exception:
            pass

    q = Queue()
    all_results = {}

    def run_task(src, fn):
        try:
            result = _timed_query(fn)
            all_results[src] = result
            q.put((src, result))
        except Exception as ex:
            err = {'valid': False, 'error': str(ex)}
            all_results[src] = err
            q.put((src, err))

    def generate():
        num_workers = min(10, max(1, len(tasks)))
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            for src, fn in tasks.items():
                executor.submit(run_task, src, fn)
            completed = 0
            while completed < len(tasks):
                try:
                    src, result = q.get(timeout=31)
                    completed += 1
                    yield 'data: ' + json.dumps(make_json_safe({'source': src, 'data': result})) + '\n\n'
                except Exception:
                    break

        threat_score = calculate_threat_score(all_results)
        successful = [s for s in all_results if all_results[s].get('valid')]
        logger.info(
            f'SSE lookup done: {query} ({query_type}) - Score: {threat_score:.1f}'
            f' - Sources: {len(successful)}/{len(tasks)}'
        )
        response_data = {
            'results': all_results,
            'threat_score': threat_score,
            'query': query,
            'query_type': query_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        cache_result(query, query_type, threat_score, response_data)
        yield ('event: __complete__\ndata: ' + json.dumps(make_json_safe({
            'query': query,
            'query_type': query_type,
            'threat_score': threat_score,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })) + '\n\n')

    resp = Response(stream_with_context(generate()), content_type='text/event-stream')
    resp.headers['Cache-Control'] = 'no-cache'
    resp.headers['X-Accel-Buffering'] = 'no'
    return resp


@app.route('/api/history', methods=['GET'])
def get_history():
    """Get scan history"""
    limit = request.args.get('limit', 50, type=int)
    with get_db_session() as session:
        results = session.query(ScanResult).order_by(
            ScanResult.created_at.desc()
        ).limit(limit).all()
        
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
    with get_db_session() as session:
        total_scans = session.query(ScanResult).count()
        avg_threat_score = session.query(func.avg(ScanResult.threat_score)).scalar() or 0
        
        query_type_counts = session.query(
            ScanResult.query_type,
            func.count(ScanResult.id)
        ).group_by(ScanResult.query_type).all()
    
    return jsonify({
        'total_scans': total_scans,
        'average_threat_score': round(avg_threat_score, 2),
        'query_types': dict(query_type_counts)
    })


@app.route('/api/clear-history', methods=['DELETE'])
def clear_history():
    """Delete all scan results from the database"""
    try:
        with get_db_session() as session:
            session.query(ScanResult).delete()
        return jsonify({
            'success': True,
            'message': 'All scan history cleared'
        }), 200
    except Exception as e:
        return jsonify({
            'error': f'Failed to clear history: {str(e)}'
        }), 500


@app.route('/api/export', methods=['POST'])
def export_results():
    """Export scan results as JSON"""
    payload = request.get_json(force=True)
    data = payload.get('data')
    
    if not data:
        return jsonify({'error': 'No data to export'}), 400
    
    filename = f"threat_intel_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    
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


@app.route('/api/health-check', methods=['GET'])
def health_check():
    """Ping each configured API source and return up/slow/down/unconfigured per source."""

    def _probe(label, fn):
        if fn is None:
            return label, {'status': 'unconfigured', 'duration_ms': 0}
        start = time.perf_counter()
        try:
            fn()
            ms = round((time.perf_counter() - start) * 1000)
            return label, {'status': 'slow' if ms > 2000 else 'up', 'duration_ms': ms}
        except Exception as exc:
            ms = round((time.perf_counter() - start) * 1000)
            return label, {'status': 'down', 'duration_ms': ms, 'error': str(exc)}

    def _probe_ssl():
        sock = socket.create_connection(('google.com', 443), timeout=3)
        sock.close()

    def _probe_whois():
        sock = socket.create_connection(('whois.iana.org', 43), timeout=3)
        sock.close()

    # Build probes dict — None means unconfigured (no API key)
    probes = {
        'virustotal': (lambda: requests.get(
            'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8',
            headers={'x-apikey': VT_API_KEY}, timeout=5
        ).raise_for_status()) if VT_API_KEY else None,

        'abuseipdb': (lambda: requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY},
            params={'ipAddress': '8.8.8.8', 'maxAgeInDays': 1}, timeout=5
        ).raise_for_status()) if ABUSEIPDB_API_KEY else None,

        'greynoise': (lambda: requests.get(
            'https://api.greynoise.io/v3/community/8.8.8.8',
            headers={'key': GREYNOISE_API_KEY}, timeout=5
        )) if GREYNOISE_API_KEY else None,

        'crowdsec': (lambda: requests.get(
            'https://cti.api.crowdsec.net/v2/smoke/8.8.8.8',
            headers={'x-api-key': CROWDSEC_API_KEY}, timeout=5
        )) if CROWDSEC_API_KEY else None,

        'ipinfo': (lambda: requests.get(
            f'https://ipinfo.io/8.8.8.8/json?token={IPINFO_TOKEN}', timeout=5
        ).raise_for_status()) if IPINFO_TOKEN else None,

        'urlhaus': lambda: requests.get('https://urlhaus-api.abuse.ch/', timeout=5),
        'crtsh': lambda: requests.get('https://crt.sh/', timeout=5).raise_for_status(),
        'secheaders': lambda: requests.get(
            'https://www.google.com', timeout=5, allow_redirects=True
        ),
        'dns': lambda: socket.gethostbyname('google.com'),
        'whois': _probe_whois,
        'ssl': _probe_ssl,
    }

    statuses = {}
    with ThreadPoolExecutor(max_workers=len(probes)) as executor:
        futures = {executor.submit(_probe, label, fn): label for label, fn in probes.items()}
        for future in as_completed(futures):
            try:
                label, result = future.result(timeout=10)
                statuses[label] = result
            except Exception as exc:
                label = futures[future]
                statuses[label] = {'status': 'down', 'duration_ms': 0, 'error': str(exc)}

    up_count = sum(1 for v in statuses.values() if isinstance(v, dict) and v.get('status') == 'up')
    logger.info(f'Health check: {up_count}/{len(probes)} sources up')
    return jsonify(statuses)


@app.errorhandler(Exception)
def handle_any_exception(e):
    """Global catch-all: always return JSON, never HTML error pages."""
    if isinstance(e, HTTPException):
        return jsonify({'error': e.description}), e.code
    logger.exception(f'Unhandled exception in request: {e}')
    return jsonify({'error': 'Internal server error', 'detail': str(e)}), 500


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({'error': 'Rate limit exceeded. Max 30 requests/hour per IP.'}), 429


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
