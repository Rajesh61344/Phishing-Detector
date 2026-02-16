#!/usr/bin/env python3
"""
Advanced Phishing Detector - Fixed & Production Ready
Strictly for authorized pentesting
"""

import sys
import re
import socket
import ssl
import urllib.parse
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import argparse
import json
import subprocess
import platform

# Try importing optional dependencies with fallbacks
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠️  'requests' not found - content analysis limited")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("⚠️  'dnspython' not found - DNS checks limited")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️  'python-whois' not found - WHOIS checks limited")

class PhishingDetector:
    def __init__(self):
        self.results = {}
        
    def check_url_syntax(self, url: str) -> Dict[str, any]:
        """Check URL for suspicious syntax patterns"""
        try:
            parsed = urllib.parse.urlparse(url)
        except:
            return {'syntax_error': True}
            
        checks = {
            'suspicious_protocol': parsed.scheme not in ['http', 'https'],
            'suspicious_subdomains': len(parsed.hostname.split('.')) > 4 if parsed.hostname else False,
            'suspicious_path': False,
            'suspicious_query': False,
            'excessive_length': len(url) > 2000,
            'double_slash': '//' in url[8:] if url.startswith(('http://', 'https://')) else False,
            'encoded_chars': False
        }
        
        # Suspicious path patterns
        suspicious_paths = [r'\.\.', r'%2e%2e', r'\\', r'\%5c']
        for pattern in suspicious_paths:
            if re.search(pattern, url, re.IGNORECASE):
                checks['suspicious_path'] = True
                break
                
        # Encoded suspicious chars
        encoded_suspicious = re.findall(r'%[0-9a-f]{2}', url.lower())
        suspicious_encodings = ['%00', '%0a', '%0d', '%2e', '%2f', '%5c']
        checks['encoded_chars'] = any(enc in encoded_suspicious for enc in suspicious_encodings)
        
        return checks

    def check_domain_reputation(self, hostname: str) -> Dict[str, any]:
        """Check domain reputation with fallback methods"""
        checks = {
            'newly_registered': False,
            'suspicious_whois': False,
            'no_mx_records': False,
            'domain_age_days': 999
        }
        
        # WHOIS lookup (optional)
        if WHOIS_AVAILABLE:
            try:
                w = whois.whois(hostname)
                if w.creation_date:
                    creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    age_days = (datetime.now() - creation_date).days
                    checks['domain_age_days'] = age_days
                    if age_days < 90:
                        checks['newly_registered'] = True
            except:
                checks['suspicious_whois'] = True
        
        # MX records check (optional)
        if DNS_AVAILABLE:
            try:
                dns.resolver.resolve(hostname, 'MX')
            except:
                checks['no_mx_records'] = True
                
        return checks

    def check_ssl_certificate(self, hostname: str) -> Dict[str, any]:
        """Analyze SSL certificate with error handling"""
        checks = {
            'self_signed': False,
            'expired': False,
            'mismatched_cn': False,
            'ssl_error': False
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check common name
                    subject = dict(x[0] for x in cert['subject'])
                    cn = subject.get('commonName', '')
                    checks['mismatched_cn'] = hostname not in cn
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    checks['expired'] = not_after < datetime.now()
                        
        except ssl.SSLError:
            checks['self_signed'] = True
        except Exception:
            checks['ssl_error'] = True
            
        return checks

    def check_similar_domains(self, hostname: str) -> Dict[str, any]:
        """Homograph and typosquatting detection"""
        checks = {
            'homograph_attack': False,
            'typosquatting': False
        }
        
        # Basic homograph detection
        try:
            punycode = hostname.encode('punycode').decode('ascii', errors='ignore')
            if punycode != hostname.lower():
                checks['homograph_attack'] = True
        except:
            pass
            
        # Typosquatting patterns
        hostname_lower = hostname.lower()
        common_brands = ['google', 'microsoft', 'paypal', 'amazon']
        for brand in common_brands:
            if brand in hostname_lower:
                typo_patterns = [f'{brand[:-1]}x', f'{brand}0']
                for pattern in typo_patterns:
                    if pattern in hostname_lower:
                        checks['typosquatting'] = True
                        break
                        
        return checks

    def check_page_content(self, url: str) -> Dict[str, any]:
        """Analyze page content (optional dependency)"""
        checks = {
            'phishing_form': False,
            'fake_login': False,
            'content_error': False
        }
        
        if not REQUESTS_AVAILABLE:
            checks['content_error'] = True
            return checks
            
        try:
            response = requests.get(url, timeout=10, verify=True)
            content = response.text.lower()
            
            # Phishing patterns
            phishing_patterns = [
                r'username.*?password|password.*?username',
                r'card.*?number|cvv.*?number',
                r'banking.*?login'
            ]
            
            for pattern in phishing_patterns:
                if re.search(pattern, content):
                    checks['phishing_form'] = True
                    break
                    
        except:
            checks['content_error'] = True
            
        return checks

    def analyze_url(self, url: str) -> Dict[str, any]:
        """Complete analysis pipeline"""
        print(f"[+] Analyzing: {url}")
        self.results[url] = {'timestamp': datetime.now().isoformat()}
        
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        
        # Run checks
        syntax = self.check_url_syntax(url)
        domain = self.check_domain_reputation(hostname)
        ssl = self.check_ssl_certificate(hostname)
        similar = self.check_similar_domains(hostname)
        content = self.check_page_content(url)
        
        all_results = {**syntax, **domain, **ssl, **similar, **content}
        risk_score = self.calculate_risk_score(all_results)
        
        all_results.update({
            'risk_score': risk_score,
            'risk_level': self.get_risk_level(risk_score)
        })
        
        self.results[url].update(all_results)
        return all_results

    def calculate_risk_score(self, results: Dict) -> int:
        """Risk scoring algorithm"""
        score = 0
        
        high_risk = ['homograph_attack', 'newly_registered', 'self_signed', 'phishing_form']
        for indicator in high_risk:
            score += 25 if results.get(indicator, False) else 0
            
        medium_risk = ['suspicious_protocol', 'no_mx_records', 'mismatched_cn', 'expired']
        for indicator in medium_risk:
            score += 15 if results.get(indicator, False) else 0
            
        low_risk = ['suspicious_subdomains', 'double_slash', 'encoded_chars', 'typosquatting']
        for indicator in low_risk:
            score += 10 if results.get(indicator, False) else 0
            
        if results.get('domain_age_days', 999) < 30:
            score += 20
            
        return min(score, 100)

    def get_risk_level(self, score: int) -> str:
        if score >= 80: return "CRITICAL"
        elif score >= 60: return "HIGH" 
        elif score >= 40: return "MEDIUM"
        elif score >= 20: return "LOW"
        return "CLEAN"

    def generate_report(self):
        """Generate pentest report"""
        print("\n" + "="*80)
        print("           PHISHING DETECTION REPORT")
        print("="*80)
        
        urls = list(self.results.keys())
        critical = sum(1 for url in urls if self.results[url]['risk_level'] == 'CRITICAL')
        
        print(f"Total URLs: {len(urls)} | CRITICAL: {critical}")
        print("-"*80)
        
        for url, data in self.results.items():
            level = data['risk_level']
            score = data['risk_score']
            print(f"\n🔍 {url}")
            print(f"   {level:<8} | Score: {score}/100")
            
            suspicious = [k for k,v in data.items() if v is True and k not in ['risk_score', 'risk_level', 'timestamp']]
            if suspicious:
                print(f"   Indicators: {', '.join(suspicious[:3])}" + ("..." if len(suspicious)>3 else ""))
        print("\n⚠️  Authorized pentest tool only\n")

def install_dependencies():
    """Auto-install missing packages"""
    packages = []
    if not REQUESTS_AVAILABLE: packages.append('requests')
    if not DNS_AVAILABLE: packages.append('dnspython')
    if not WHOIS_AVAILABLE: packages.append('python-whois')
    
    if packages:
        print("📦 Installing missing dependencies...")
        for pkg in packages:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg, '--quiet'])
        print("✅ Dependencies installed!")

def main():
    print("🚀 Advanced Phishing Detector v2.0 - Pentest Edition")
    
    # Auto-install dependencies
    install_dependencies()
    
    parser = argparse.ArgumentParser(description="Phishing Detector - Fixed Version")
    parser.add_argument('urls', nargs='+', help="URLs to analyze")
    parser.add_argument('-o', '--output', help="JSON report file")
    parser.add_argument('--no-install', action='store_true', help="Skip auto-install")
    
    args = parser.parse_args()
    
    if not args.no_install:
        install_dependencies()
    
    detector = PhishingDetector()
    
    for url in args.urls:
        try:
            detector.analyze_url(url)
        except KeyboardInterrupt:
            print("\n[!] Stopped by user")
            break
    
    detector.generate_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(detector.results, f, indent=2)
        print(f"📄 Report saved: {args.output}")

if __name__ == "__main__":
    main()