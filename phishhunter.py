#!/usr/bin/env python3
"""
PhishHunter - Advanced Phishing Website Detection Tool
Author: Ali AlEnezi
Email: site@hotmail.com
GitHub: https://github.com/SiteQ8/
Version: 1.0.0

A comprehensive Python tool for detecting phishing websites using multiple detection methods:
- URL structure analysis
- Domain reputation checking
- Certificate transparency monitoring
- WHOIS analysis
- Machine learning-based detection
- DNS analysis
"""

import re
import json
import time
import hashlib
import requests
import socket
import ssl
import whois
import dns.resolver
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import argparse
import logging
import concurrent.futures
from pathlib import Path
import csv

# Import optional ML libraries
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: Machine learning libraries not available. Install scikit-learn and numpy for ML features.")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phishhunter.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class DetectionResult:
    """Container for detection results"""
    url: str
    is_phishing: bool
    confidence_score: float
    detection_methods: List[str]
    risk_factors: List[str]
    timestamp: str
    details: Dict

class PhishHunter:
    """Advanced Phishing Detection System"""

    def __init__(self, config_file: Optional[str] = None):
        """Initialize PhishHunter with configuration"""
        self.config = self._load_config(config_file)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PhishHunter/1.0.0 (Security Research Tool)'
        })

        # Initialize detection modules
        self.url_analyzer = URLAnalyzer()
        self.domain_checker = DomainReputationChecker(self.config.get('api_keys', {}))
        self.cert_analyzer = CertificateAnalyzer()
        self.whois_analyzer = WHOISAnalyzer()
        self.dns_analyzer = DNSAnalyzer()

        if ML_AVAILABLE:
            self.ml_detector = MLPhishingDetector()

        logger.info("PhishHunter initialized successfully")

    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            'api_keys': {
                'virustotal': '',
                'urlscan': '',
                'domain_reputation': ''
            },
            'detection_settings': {
                'confidence_threshold': 0.7,
                'max_workers': 5,
                'timeout': 30
            },
            'phishing_keywords': [
                'login', 'secure', 'account', 'verify', 'update', 'suspended',
                'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
                'bank', 'credit', 'visa', 'mastercard', 'bitcoin'
            ]
        }

        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}")

        return default_config

    def analyze_url(self, url: str) -> DetectionResult:
        """Comprehensive analysis of a URL for phishing indicators"""
        logger.info(f"Analyzing URL: {url}")

        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        detection_methods = []
        risk_factors = []
        details = {}
        total_score = 0.0
        method_count = 0

        # URL Structure Analysis
        try:
            url_score, url_risks = self.url_analyzer.analyze(url)
            total_score += url_score
            method_count += 1
            detection_methods.append('url_analysis')
            risk_factors.extend(url_risks)
            details['url_analysis'] = {'score': url_score, 'risks': url_risks}
        except Exception as e:
            logger.warning(f"URL analysis failed: {e}")

        # Domain Reputation Check
        try:
            domain_score, domain_risks = self.domain_checker.check_domain(url)
            total_score += domain_score
            method_count += 1
            detection_methods.append('domain_reputation')
            risk_factors.extend(domain_risks)
            details['domain_reputation'] = {'score': domain_score, 'risks': domain_risks}
        except Exception as e:
            logger.warning(f"Domain reputation check failed: {e}")

        # Certificate Analysis
        try:
            cert_score, cert_risks = self.cert_analyzer.analyze_certificate(url)
            total_score += cert_score
            method_count += 1
            detection_methods.append('certificate_analysis')
            risk_factors.extend(cert_risks)
            details['certificate_analysis'] = {'score': cert_score, 'risks': cert_risks}
        except Exception as e:
            logger.warning(f"Certificate analysis failed: {e}")

        # WHOIS Analysis
        try:
            whois_score, whois_risks = self.whois_analyzer.analyze_domain(url)
            total_score += whois_score
            method_count += 1
            detection_methods.append('whois_analysis')
            risk_factors.extend(whois_risks)
            details['whois_analysis'] = {'score': whois_score, 'risks': whois_risks}
        except Exception as e:
            logger.warning(f"WHOIS analysis failed: {e}")

        # DNS Analysis
        try:
            dns_score, dns_risks = self.dns_analyzer.analyze_dns(url)
            total_score += dns_score
            method_count += 1
            detection_methods.append('dns_analysis')
            risk_factors.extend(dns_risks)
            details['dns_analysis'] = {'score': dns_score, 'risks': dns_risks}
        except Exception as e:
            logger.warning(f"DNS analysis failed: {e}")

        # Machine Learning Detection
        if ML_AVAILABLE:
            try:
                ml_score, ml_risks = self.ml_detector.predict(url)
                total_score += ml_score
                method_count += 1
                detection_methods.append('ml_detection')
                risk_factors.extend(ml_risks)
                details['ml_detection'] = {'score': ml_score, 'risks': ml_risks}
            except Exception as e:
                logger.warning(f"ML detection failed: {e}")

        # Calculate final confidence score
        confidence_score = total_score / method_count if method_count > 0 else 0.0
        is_phishing = confidence_score >= self.config['detection_settings']['confidence_threshold']

        result = DetectionResult(
            url=url,
            is_phishing=is_phishing,
            confidence_score=confidence_score,
            detection_methods=detection_methods,
            risk_factors=list(set(risk_factors)),  # Remove duplicates
            timestamp=datetime.now().isoformat(),
            details=details
        )

        logger.info(f"Analysis complete. Phishing probability: {confidence_score:.2%}")
        return result

    def batch_analyze(self, urls: List[str]) -> List[DetectionResult]:
        """Analyze multiple URLs concurrently"""
        logger.info(f"Starting batch analysis of {len(urls)} URLs")

        results = []
        max_workers = self.config['detection_settings']['max_workers']

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(self.analyze_url, url): url for url in urls}

            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error analyzing {url}: {e}")

        return results

    def save_results(self, results: List[DetectionResult], output_file: str):
        """Save detection results to file"""
        output_path = Path(output_file)

        if output_path.suffix.lower() == '.json':
            self._save_json(results, output_path)
        elif output_path.suffix.lower() == '.csv':
            self._save_csv(results, output_path)
        else:
            raise ValueError("Unsupported output format. Use .json or .csv")

        logger.info(f"Results saved to {output_file}")

    def _save_json(self, results: List[DetectionResult], output_path: Path):
        """Save results as JSON"""
        with open(output_path, 'w') as f:
            json.dump([asdict(result) for result in results], f, indent=2)

    def _save_csv(self, results: List[DetectionResult], output_path: Path):
        """Save results as CSV"""
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Is_Phishing', 'Confidence_Score', 'Detection_Methods', 'Risk_Factors', 'Timestamp'])

            for result in results:
                writer.writerow([
                    result.url,
                    result.is_phishing,
                    f"{result.confidence_score:.3f}",
                    ';'.join(result.detection_methods),
                    ';'.join(result.risk_factors),
                    result.timestamp
                ])

class URLAnalyzer:
    """URL structure analysis for phishing indicators"""

    def __init__(self):
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.site',
            '.top', '.win', '.bid', '.loan', '.date', '.review'
        ]

        self.phishing_keywords = [
            'secure', 'account', 'verify', 'login', 'update', 'suspended',
            'confirm', 'validation', 'security', 'alert', 'warning'
        ]

    def analyze(self, url: str) -> Tuple[float, List[str]]:
        """Analyze URL structure for phishing indicators"""
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()

        risk_score = 0.0
        risk_factors = []

        # Check domain length
        if len(domain) > 50:
            risk_score += 0.3
            risk_factors.append('long_domain_name')

        # Check for suspicious TLDs
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                risk_score += 0.4
                risk_factors.append(f'suspicious_tld_{tld}')
                break

        # Check for multiple subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            risk_score += 0.2
            risk_factors.append('excessive_subdomains')

        # Check for phishing keywords
        full_url = f"{domain} {path} {query}"
        for keyword in self.phishing_keywords:
            if keyword in full_url:
                risk_score += 0.1
                risk_factors.append(f'phishing_keyword_{keyword}')

        # Check for IP address instead of domain
        if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
            risk_score += 0.8
            risk_factors.append('ip_address_domain')

        # Check for URL shortening services
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
        if any(shortener in domain for shortener in shorteners):
            risk_score += 0.3
            risk_factors.append('url_shortener')

        # Check for suspicious characters
        suspicious_chars = ['-', '_']
        for char in suspicious_chars:
            if domain.count(char) > 3:
                risk_score += 0.1
                risk_factors.append(f'excessive_{char}_characters')

        # Check for homograph attacks (basic)
        if any(ord(c) > 127 for c in domain):
            risk_score += 0.5
            risk_factors.append('unicode_homograph_attack')

        return min(risk_score, 1.0), risk_factors

class DomainReputationChecker:
    """Check domain reputation using various APIs"""

    def __init__(self, api_keys: Dict[str, str]):
        self.api_keys = api_keys

    def check_domain(self, url: str) -> Tuple[float, List[str]]:
        """Check domain reputation using multiple sources"""
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc

        risk_score = 0.0
        risk_factors = []

        # Check with VirusTotal if API key available
        if self.api_keys.get('virustotal'):
            try:
                vt_score, vt_risks = self._check_virustotal(domain)
                risk_score += vt_score * 0.5
                risk_factors.extend(vt_risks)
            except Exception as e:
                logger.warning(f"VirusTotal check failed: {e}")

        # Check domain age and registration details
        try:
            age_score, age_risks = self._check_domain_age(domain)
            risk_score += age_score * 0.3
            risk_factors.extend(age_risks)
        except Exception as e:
            logger.warning(f"Domain age check failed: {e}")

        # Check for known phishing domains (basic blacklist)
        if self._is_known_phishing_domain(domain):
            risk_score += 1.0
            risk_factors.append('known_phishing_domain')

        return min(risk_score, 1.0), risk_factors

    def _check_virustotal(self, domain: str) -> Tuple[float, List[str]]:
        """Check domain with VirusTotal API"""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return 0.0, []

        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'apikey': api_key, 'domain': domain}

        response = requests.get(url, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json()
            if data.get('response_code') == 1:
                positives = data.get('positives', 0)
                total = data.get('total', 1)

                if positives > 0:
                    score = positives / total
                    return score, [f'virustotal_detection_{positives}_{total}']

        return 0.0, []

    def _check_domain_age(self, domain: str) -> Tuple[float, List[str]]:
        """Check if domain is newly registered (suspicious)"""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                days_old = (datetime.now() - creation_date).days

                if days_old < 30:
                    return 0.8, ['newly_registered_domain']
                elif days_old < 90:
                    return 0.4, ['recently_registered_domain']
                elif days_old < 365:
                    return 0.2, ['young_domain']

        except Exception:
            return 0.3, ['whois_lookup_failed']

        return 0.0, []

    def _is_known_phishing_domain(self, domain: str) -> bool:
        """Check against known phishing domain patterns"""
        # Basic check - you could expand this with actual blacklists
        phishing_patterns = [
            r'.*paypal.*secure.*',
            r'.*amazon.*login.*',
            r'.*microsoft.*verify.*',
            r'.*apple.*id.*',
            r'.*facebook.*security.*'
        ]

        for pattern in phishing_patterns:
            if re.match(pattern, domain, re.IGNORECASE):
                return True

        return False

class CertificateAnalyzer:
    """Analyze SSL certificates for phishing indicators"""

    def analyze_certificate(self, url: str) -> Tuple[float, List[str]]:
        """Analyze SSL certificate for suspicious patterns"""
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        port = 443

        risk_score = 0.0
        risk_factors = []

        try:
            # Get certificate information
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

            # Check certificate validity period
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')

            validity_days = (not_after - not_before).days

            # Short validity periods can be suspicious
            if validity_days < 90:
                risk_score += 0.3
                risk_factors.append('short_certificate_validity')

            # Check if certificate is very new
            days_since_issued = (datetime.now() - not_before).days
            if days_since_issued < 7:
                risk_score += 0.4
                risk_factors.append('newly_issued_certificate')

            # Check issuer
            issuer = cert.get('issuer', [])
            issuer_name = ''
            for item in issuer:
                if item[0][0] == 'organizationName':
                    issuer_name = item[0][1].lower()
                    break

            # Free certificate authorities might be used by phishers
            free_cas = ['let\'s encrypt', 'cloudflare']
            if any(ca in issuer_name for ca in free_cas):
                risk_score += 0.1
                risk_factors.append('free_certificate_authority')

            # Check subject alternative names
            san_list = []
            for ext in cert.get('subjectAltName', []):
                if ext[0] == 'DNS':
                    san_list.append(ext[1])

            # Multiple SANs with different domains can be suspicious
            if len(san_list) > 5:
                risk_score += 0.2
                risk_factors.append('excessive_san_entries')

        except Exception as e:
            # No HTTPS or certificate issues
            risk_score += 0.5
            risk_factors.append('certificate_error')
            logger.warning(f"Certificate analysis failed for {domain}: {e}")

        return min(risk_score, 1.0), risk_factors

class WHOISAnalyzer:
    """Analyze WHOIS information for suspicious patterns"""

    def analyze_domain(self, url: str) -> Tuple[float, List[str]]:
        """Analyze WHOIS data for phishing indicators"""
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc

        risk_score = 0.0
        risk_factors = []

        try:
            w = whois.whois(domain)

            # Check registration details
            if w.registrar:
                registrar = w.registrar.lower()
                # Some registrars are commonly used for suspicious domains
                suspicious_registrars = ['namecheap', 'godaddy', 'pdr']
                if any(reg in registrar for reg in suspicious_registrars):
                    risk_score += 0.1
                    risk_factors.append('suspicious_registrar')

            # Check privacy protection
            if w.registrant_name and 'privacy' in w.registrant_name.lower():
                risk_score += 0.2
                risk_factors.append('privacy_protected_whois')

            # Check registrant country
            if hasattr(w, 'registrant_country') and w.registrant_country:
                high_risk_countries = ['CN', 'RU', 'UA', 'BD']
                if w.registrant_country.upper() in high_risk_countries:
                    risk_score += 0.3
                    risk_factors.append('high_risk_country_registration')

        except Exception as e:
            risk_score += 0.1
            risk_factors.append('whois_lookup_failed')
            logger.warning(f"WHOIS analysis failed for {domain}: {e}")

        return min(risk_score, 1.0), risk_factors

class DNSAnalyzer:
    """Analyze DNS records for suspicious patterns"""

    def analyze_dns(self, url: str) -> Tuple[float, List[str]]:
        """Analyze DNS records for phishing indicators"""
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc

        risk_score = 0.0
        risk_factors = []

        try:
            # Check A records
            answers = dns.resolver.resolve(domain, 'A')
            ip_addresses = [str(rdata) for rdata in answers]

            # Check for suspicious IP ranges
            for ip in ip_addresses:
                if self._is_suspicious_ip(ip):
                    risk_score += 0.3
                    risk_factors.append(f'suspicious_ip_{ip}')

            # Check MX records
            try:
                mx_answers = dns.resolver.resolve(domain, 'MX')
                if not mx_answers:
                    risk_score += 0.1
                    risk_factors.append('no_mx_records')
            except dns.resolver.NXDOMAIN:
                risk_score += 0.2
                risk_factors.append('no_mx_records')

        except dns.resolver.NXDOMAIN:
            risk_score += 0.8
            risk_factors.append('domain_not_found')
        except Exception as e:
            risk_score += 0.1
            risk_factors.append('dns_lookup_failed')
            logger.warning(f"DNS analysis failed for {domain}: {e}")

        return min(risk_score, 1.0), risk_factors

    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is in suspicious ranges"""
        # Basic check for some known suspicious ranges
        suspicious_ranges = [
            '185.', '194.', '91.', '5.'  # Common hosting providers used by phishers
        ]

        return any(ip.startswith(range_prefix) for range_prefix in suspicious_ranges)

if ML_AVAILABLE:
    class MLPhishingDetector:
        """Machine Learning based phishing detection"""

        def __init__(self):
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.vectorizer = TfidfVectorizer(max_features=1000)
            self.is_trained = False
            self._train_model()

        def _train_model(self):
            """Train the ML model with sample data"""
            # Sample training data - in a real implementation, use a larger dataset
            training_urls = [
                # Legitimate URLs
                'https://www.google.com',
                'https://www.facebook.com',
                'https://www.amazon.com',
                'https://www.microsoft.com',
                'https://www.apple.com',
                'https://github.com',
                'https://stackoverflow.com',

                # Phishing-like URLs
                'https://secure-paypal-login.tk',
                'https://amazon-verify-account.ml',
                'https://microsoft-security-alert.ga',
                'https://apple-id-locked.cf',
                'https://facebook-security-check.site'
            ]

            labels = [0, 0, 0, 0, 0, 0, 0,  # Legitimate
                     1, 1, 1, 1, 1]         # Phishing

            features = self.vectorizer.fit_transform(training_urls)
            self.model.fit(features, labels)
            self.is_trained = True

        def predict(self, url: str) -> Tuple[float, List[str]]:
            """Predict if URL is phishing using ML"""
            if not self.is_trained:
                return 0.0, ['ml_model_not_trained']

            try:
                features = self.vectorizer.transform([url])
                probability = self.model.predict_proba(features)[0][1]  # Probability of phishing

                risk_factors = []
                if probability > 0.7:
                    risk_factors.append('high_ml_phishing_probability')
                elif probability > 0.5:
                    risk_factors.append('medium_ml_phishing_probability')

                return probability, risk_factors

            except Exception as e:
                logger.warning(f"ML prediction failed: {e}")
                return 0.0, ['ml_prediction_failed']

def main():
    """Main function for CLI usage"""
    parser = argparse.ArgumentParser(description='PhishHunter - Advanced Phishing Detection Tool')
    parser.add_argument('urls', nargs='*', help='URLs to analyze')
    parser.add_argument('-f', '--file', help='File containing URLs to analyze (one per line)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON or CSV)')
    parser.add_argument('-c', '--config', help='Configuration file path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--threshold', type=float, default=0.7, help='Phishing detection threshold')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize PhishHunter
    hunter = PhishHunter(args.config)

    # Collect URLs to analyze
    urls_to_analyze = []

    if args.urls:
        urls_to_analyze.extend(args.urls)

    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_urls = [line.strip() for line in f if line.strip()]
                urls_to_analyze.extend(file_urls)
        except FileNotFoundError:
            logger.error(f"File not found: {args.file}")
            sys.exit(1)

    if not urls_to_analyze:
        logger.error("No URLs provided for analysis")
        parser.print_help()
        sys.exit(1)

    # Update confidence threshold if specified
    hunter.config['detection_settings']['confidence_threshold'] = args.threshold

    # Analyze URLs
    if len(urls_to_analyze) == 1:
        result = hunter.analyze_url(urls_to_analyze[0])
        results = [result]
    else:
        results = hunter.batch_analyze(urls_to_analyze)

    # Display results
    print("\n" + "="*80)
    print("PHISHHUNTER DETECTION RESULTS")
    print("="*80)

    for result in results:
        status = "🚨 PHISHING DETECTED" if result.is_phishing else "✅ LIKELY SAFE"
        print(f"\n{status}")
        print(f"URL: {result.url}")
        print(f"Confidence: {result.confidence_score:.1%}")
        print(f"Detection Methods: {', '.join(result.detection_methods)}")

        if result.risk_factors:
            print(f"Risk Factors: {', '.join(result.risk_factors)}")

    # Save results if output file specified
    if args.output:
        hunter.save_results(results, args.output)
        print(f"\nResults saved to: {args.output}")

    # Summary
    phishing_count = sum(1 for r in results if r.is_phishing)
    print(f"\nSummary: {phishing_count}/{len(results)} URLs flagged as potential phishing")

if __name__ == '__main__':
    main()
