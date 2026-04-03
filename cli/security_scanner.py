#!/usr/bin/env python3
"""
Advanced Security Scanner - Educational & Production Ready
Combines local analysis with external API verification

This tool demonstrates how security scanners actually work:
1. Static analysis (patterns, signatures, entropy)
2. Behavioral indicators (file structure, headers)
3. External threat intelligence (APIs)
"""

import os
import re
# import sys
import json
# import time
import hashlib
# from unittest import result
import requests
from pathlib import Path
from urllib.parse import urlparse, unquote
from typing import Dict, List, Optional
import argparse
from dataclasses import dataclass, field
import math
from collections import Counter
from openai import OpenAI
import json
# ============================================
# CONFIGURATION
# ============================================

@dataclass
class ScannerConfig:
    """Configuration for the scanner"""
    google_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    cache_results: bool = True
    verbose: bool = False
    
    @classmethod
    def from_env(cls):
        """Load config from environment variables"""
        return cls(
            google_api_key=os.getenv('GOOGLE_SAFE_BROWSING_API_KEY'),
            virustotal_api_key=os.getenv('VIRUSTOTAL_API_KEY'),
            openai_api_key=os.getenv('OPENAI_API_KEY')
        )


@dataclass
class ThreatResult:
    """Result of a security scan"""
    is_safe: bool
    confidence: float  # 0.0 to 1.0
    threats: List[Dict] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    
    def add_threat(self, severity: str, category: str, description: str, details: Dict = None):
        """Add a threat to the result"""
        self.threats.append({
            'severity': severity,  # low, medium, high, critical
            'category': category,
            'description': description,
            'details': details or {}
        })
        self.is_safe = False


# ============================================
# URL SCANNER - DEEP ANALYSIS
# ============================================

class URLScanner:
    """
    Analyzes URLs for malicious indicators
    
    Detection techniques:
    1. Domain analysis (typosquatting, suspicious TLDs)
    2. Path traversal attempts
    3. Encoded payloads (base64, hex, URL encoding)
    4. JavaScript execution patterns
    5. Redirect chains
    6. IP-based hosts
    7. Punycode/IDN homograph attacks
    """
    
    # Known malicious patterns
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.club', '.work', '.click']
    
    # Popular domains often targeted for typosquatting
    POPULAR_DOMAINS = {
        'paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple',
        'netflix', 'instagram', 'twitter', 'linkedin', 'ebay', 'walmart',
        'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'usbank'
    }
    
    # Suspicious keywords that appear in phishing URLs
    PHISHING_KEYWORDS = [
        'verify', 'secure', 'account', 'login', 'banking', 'payment',
        'suspended', 'locked', 'urgent', 'confirm', 'update', 'credential',
        'validate', 'restore', 'limited', 'unusual', 'activity'
    ]
    
    def __init__(self, config: ScannerConfig):
        self.config = config
    
    def scan(self, url: str) -> ThreatResult:
        """Perform comprehensive URL analysis"""
        result = ThreatResult(is_safe=True, confidence=0.8)
        
        try:
            parsed = urlparse(url)
            result.metadata['parsed_url'] = {
                'scheme': parsed.scheme,
                'hostname': parsed.hostname,
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment
            }
        except Exception as e:
            result.add_threat('high', 'malformed_url', 
                            f'Cannot parse URL: {str(e)}')
            return result
        
        # Run all analysis checks
        self._check_ip_address(parsed, result)
        self._check_suspicious_tld(parsed, result)
        self._check_typosquatting(parsed, result)
        self._check_path_traversal(parsed, result)
        self._check_encoded_payloads(parsed, result)
        self._check_javascript_execution(parsed, result)
        self._check_phishing_keywords(url, result)
        self._check_punycode(parsed, result)
        self._check_suspicious_port(parsed, result)
        self._analyze_url_entropy(url, result)
        
        # If local analysis passed, verify with Google Safe Browsing
        if self.config.google_api_key and len(result.threats) > 0:
            print("Local analysis found potential threats, verifying with Google Safe Browsing...")
            self._check_google_safe_browsing(url, result)
        
        return result
    
    def _check_ip_address(self, parsed, result: ThreatResult):
        """
        Check if URL uses IP address instead of domain name.
        Legitimate sites use domain names; IP addresses often indicate:
        - Temporary/throwaway hosting
        - Avoiding domain blacklists
        - Testing/development servers used for attacks
        """
        hostname = parsed.hostname or ''
        
        # Check for IPv4 (e.g., 192.168.1.1)
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ipv4_pattern, hostname):
            result.add_threat('high', 'ip_address',
                            'URL uses IP address instead of domain name',
                            {'ip': hostname, 'reason': 'Common in phishing to avoid DNS blacklists'})
        
        # Check for IPv6 (e.g., [2001:db8::1])
        if hostname.startswith('[') and hostname.endswith(']'):
            result.add_threat('medium', 'ip_address',
                            'URL uses IPv6 address',
                            {'ip': hostname})
    
    def _check_suspicious_tld(self, parsed, result: ThreatResult):
        """
        Check for TLDs commonly abused by scammers.
        Some TLDs are free or very cheap, making them popular for:
        - Disposable phishing sites
        - Spam campaigns
        - Malware distribution
        """
        hostname = (parsed.hostname or '').lower()
        
        for tld in self.SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                result.add_threat('medium', 'suspicious_tld',
                                f'Domain uses high-risk TLD: {tld}',
                                {'tld': tld, 'reason': 'Commonly abused for phishing/spam'})
                break
    
    def _check_typosquatting(self, parsed, result: ThreatResult):
        """
        Detect typosquatting attempts.
        
        Typosquatting techniques:
        1. Character substitution (0 for o, 1 for l)
        2. Adding hyphens (pay-pal.com)
        3. Adding prefixes/suffixes (secure-paypal.com)
        4. Homoglyphs (using similar-looking characters)
        """
        hostname = (parsed.hostname or '').lower()
        
        for brand in self.POPULAR_DOMAINS:
            if brand in hostname:
                # Check if it's the exact legitimate domain
                if hostname == f'{brand}.com' or hostname == f'www.{brand}.com':
                    continue
                
                # Check for common typosquatting patterns
                suspicious_patterns = [
                    brand.replace('o', '0'),  # paypa1
                    brand.replace('l', '1'),  # paypa1
                    brand.replace('i', '1'),  # microsft
                    f'{brand}-secure',
                    f'{brand}-verify',
                    f'{brand}-account',
                    f'secure-{brand}',
                    f'verify-{brand}',
                    f'{brand}online',
                ]
                
                for pattern in suspicious_patterns:
                    if pattern in hostname:
                        result.add_threat('critical', 'typosquatting',
                                        f'Possible {brand.upper()} impersonation',
                                        {
                                            'target_brand': brand,
                                            'pattern': pattern,
                                            'actual_hostname': hostname
                                        })
                        break
    
    def _check_path_traversal(self, parsed, result: ThreatResult):
        """
        Detect path traversal attempts.
        
        Path traversal (../) allows accessing files outside web root:
        - ../../../../etc/passwd (Linux)
        - ..\..\..\..\windows\system32 (Windows)
        - URL-encoded variants (%2e%2e%2f)
        """
        path = unquote(parsed.path + parsed.query)
        
        # Check for directory traversal sequences
        traversal_patterns = [
            '../',
            '..\\',
            '%2e%2e%2f',
            '%2e%2e/',
            '..%2f',
            '%2e%2e%5c',
        ]
        
        for pattern in traversal_patterns:
            if pattern in path.lower():
                result.add_threat('high', 'path_traversal',
                                'Path traversal attempt detected',
                                {
                                    'pattern': pattern,
                                    'path': path,
                                    'danger': 'Can access unauthorized files/directories'
                                })
        
        # Check for absolute paths (reverse path traversal)
        if re.search(r'[/\\](etc|windows|system32|boot|dev)[/\\]', path, re.IGNORECASE):
            result.add_threat('critical', 'path_traversal',
                            'Absolute system path detected in URL',
                            {
                                'path': path,
                                'danger': 'Attempting to access system files'
                            })
    
    def _check_encoded_payloads(self, parsed, result: ThreatResult):
        """
        Detect encoded malicious payloads.
        
        Attackers encode payloads to:
        1. Bypass filters/WAFs
        2. Hide malicious scripts
        3. Obfuscate SQL injection
        
        Encoding types:
        - URL encoding (%20, %3C, etc.)
        - Base64 (dG9vIGJhZCB5b3UgZGVjb2RlZCB0aGlz)
        - Hex encoding (\x3C\x73\x63\x72\x69\x70\x74\x3E)
        """
        full_url = parsed.geturl()
        
        # Check for excessive URL encoding (multiple layers)
        url_encoded_count = full_url.count('%')
        if url_encoded_count > 10:
            result.add_threat('medium', 'encoded_payload',
                            'Excessive URL encoding detected',
                            {
                                'count': url_encoded_count,
                                'reason': 'May hide malicious payload'
                            })
        
        # Check for Base64 in URL
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = re.findall(base64_pattern, full_url)
        if base64_matches:
            for match in base64_matches[:3]:  # Limit to first 3
                try:
                    import base64
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    if '<script' in decoded.lower() or 'eval(' in decoded.lower():
                        result.add_threat('critical', 'encoded_payload',
                                        'Base64-encoded script detected',
                                        {
                                            'encoded': match[:50] + '...',
                                            'decoded': decoded[:100]
                                        })
                except:
                    pass
        
        # Check for hex encoding
        if '\\x' in full_url or '%u' in full_url:
            result.add_threat('high', 'encoded_payload',
                            'Hex encoding detected in URL',
                            {'reason': 'Often used to hide XSS/injection attacks'})
    
    def _check_javascript_execution(self, parsed, result: ThreatResult):
        """
        Detect JavaScript execution attempts in URL.
        
        Dangerous JavaScript patterns:
        - javascript: protocol (javascript:alert(1))
        - data: URI with script (data:text/html,<script>...)
        - eval() calls
        - document.cookie access
        """
        full_url = parsed.geturl().lower()
        
        # Check for javascript: protocol
        if full_url.startswith('javascript:'):
            result.add_threat('critical', 'javascript_execution',
                            'JavaScript protocol handler detected',
                            {
                                'url': full_url[:100],
                                'danger': 'Executes arbitrary JavaScript'
                            })
        
        # Check for data: URI with scripts
        if full_url.startswith('data:') and '<script' in full_url:
            result.add_threat('critical', 'javascript_execution',
                            'Data URI with embedded script',
                            {'danger': 'Can execute malicious code'})
        
        # Check for dangerous JavaScript functions in URL
        dangerous_js = ['eval(', 'document.cookie', 'window.location', 
                       'document.write', 'innerHTML', 'exec(']
        for js_func in dangerous_js:
            if js_func in full_url:
                result.add_threat('high', 'javascript_execution',
                                f'Dangerous JavaScript function: {js_func}',
                                {'function': js_func})
    
    def _check_phishing_keywords(self, url: str, result: ThreatResult):
        """
        Check for keywords commonly used in phishing URLs.
        
        Phishing URLs often contain urgency/security keywords to:
        - Create panic ("account suspended")
        - Appear legitimate ("secure-login")
        - Pressure users ("verify now")
        """
        url_lower = url.lower()
        found_keywords = [kw for kw in self.PHISHING_KEYWORDS if kw in url_lower]
        
        if len(found_keywords) >= 2:
            result.add_threat('medium', 'phishing_keywords',
                            'Multiple phishing keywords detected',
                            {
                                'keywords': found_keywords,
                                'count': len(found_keywords),
                                'reason': 'Common in phishing campaigns'
                            })
    
    def _check_punycode(self, parsed, result: ThreatResult):
        """
        Detect Punycode/IDN homograph attacks.
        
        Punycode allows Unicode in domain names:
        - xn--pple-43d.com looks like "аpple.com" (Cyrillic 'а')
        - Attackers use lookalike characters to fool users
        
        Example: аррӏе.com (all Cyrillic) vs apple.com (Latin)
        """
        hostname = parsed.hostname or ''
        
        # Check if domain uses Punycode (starts with xn--)
        if hostname.startswith('xn--'):
            try:
                decoded = hostname.encode('ascii').decode('idna')
                result.add_threat('critical', 'punycode_attack',
                                'Punycode domain detected (homograph attack)',
                                {
                                    'punycode': hostname,
                                    'decoded': decoded,
                                    'danger': 'Uses lookalike Unicode characters to impersonate brands'
                                })
            except:
                pass
    
    def _check_suspicious_port(self, parsed, result: ThreatResult):
        """
        Check for non-standard ports.
        
        Standard ports:
        - 80 (HTTP), 443 (HTTPS), 8080 (HTTP alt), 8443 (HTTPS alt)
        
        Suspicious ports may indicate:
        - Proxy/tunnel
        - Malware C2 server
        - Testing/development server repurposed for attacks
        """
        if parsed.port and str(parsed.port) not in ['80', '443', '8080', '8443']:
            result.add_threat('medium', 'suspicious_port',
                            f'Non-standard port: {parsed.port}',
                            {
                                'port': parsed.port,
                                'reason': 'Legitimate sites use standard ports'
                            })
            
    def _analyze_url_entropy(self, url: str, result: ThreatResult):
        """
        Calculate URL entropy to detect randomness.
        
        High entropy indicates:
        - Randomly generated domains (DGA - Domain Generation Algorithm)
        - Encrypted/encoded data
        - Token-based tracking URLs (often legitimate)
        
        Shannon entropy formula: H = -Σ(p(x) * log2(p(x)))
        """
        if not url:
            return

        counter = Counter(url)
        length = len(url)

        entropy = -sum((c/length) * math.log2(c/length) for c in counter.values())

        if entropy > 4.5:
            result.add_threat(
                'medium',
                'high_entropy',
                f'URL looks randomly generated (entropy={round(entropy,2)})'
            )
    
    def _check_google_safe_browsing(self, url: str, result: ThreatResult):
        """
        Verify URL against Google Safe Browsing API.
        
        Google maintains a database of:
        - Phishing sites
        - Malware distribution
        - Unwanted software
        - Social engineering
        """
        if not self.config.google_api_key:
            return
        
        try:
            api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.config.google_api_key}'
            
            payload = {
                "client": {
                    "clientId": "security-scanner",# ?, maybe we need real client info
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('matches'):
                    for match in data['matches']:
                        threat_type = match.get('threatType', 'UNKNOWN')
                        result.add_threat('critical', 'google_safe_browsing',
                                        f'Flagged by Google Safe Browsing: {threat_type}',
                                        {
                                            'threat_type': threat_type,
                                            'platform': match.get('platformType'),
                                            'source': 'Google Safe Browsing API'
                                        })
                    result.metadata['google_safe_browsing'] = 'UNSAFE'
                else:
                    result.metadata['google_safe_browsing'] = 'SAFE'
            else:
                result.metadata['google_safe_browsing'] = f'ERROR: {response.status_code}'
                
        except Exception as e:
            result.metadata['google_safe_browsing'] = f'ERROR: {str(e)}'
            if self.config.verbose:
                print(f"⚠️  Google Safe Browsing API error: {e}")


# ============================================
# FILE SCANNER - DEEP ANALYSIS
# ============================================

class FileScanner:
    """
    Analyzes files for malicious indicators.
    
    Detection techniques:
    1. File header analysis (magic bytes)
    2. Extension verification (double extensions, mismatches)
    3. Entropy analysis (packed/encrypted content)
    4. String extraction (suspicious commands, URLs)
    5. PE/ELF structure analysis
    6. Embedded scripts
    7. Macro detection (Office docs)
    8. Hash-based detection
    """
    
    # Magic bytes for common file types
    MAGIC_BYTES = {
        'pdf': b'%PDF',
        'zip': b'PK\x03\x04',
        'rar': b'Rar!\x1a\x07',
        'exe': b'MZ',
        'elf': b'\x7fELF',
        'png': b'\x89PNG',
        'jpg': b'\xff\xd8\xff',
        'gif': b'GIF8',
        'docx': b'PK\x03\x04',  # DOCX is ZIP-based
        'xlsx': b'PK\x03\x04',
    }
    
    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = {
        'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js',
        'jar', 'msi', 'dll', 'sys', 'ps1', 'sh', 'app', 'deb', 
        'rpm', 'pkg', 'dmg', 'hta', 'cpl', 'gadget', 'wsf'
    }
    
    # Suspicious strings to look for
    SUSPICIOUS_STRINGS = [
        b'eval(',
        b'exec(',
        b'system(',
        b'shell_exec',
        b'passthru',
        b'base64_decode',
        b'gzinflate',
        b'str_rot13',
        b'powershell',
        b'cmd.exe',
        b'/bin/bash',
        b'/bin/sh',
        b'wget ',
        b'curl ',
        b'chmod +x',
        b'nc -e',
        b'netcat',
    ]
    
    def __init__(self, config: ScannerConfig):
        self.config = config
    
    def scan(self, file_path: str) -> ThreatResult:
        result = ThreatResult(is_safe=True, confidence=0.7)

        if not os.path.exists(file_path):
            result.add_threat('high', 'file_not_found', f'File does not exist: {file_path}')
            return result

        file_path = Path(file_path)
        result.metadata['filename'] = file_path.name
        result.metadata['size'] = os.path.getsize(file_path)
        result.metadata['extension'] = file_path.suffix.lower()

        # Run all analysis checks
        self._check_extension(file_path, result)
        self._check_magic_bytes(file_path, result)
        self._analyze_entropy(file_path, result)
        self._extract_strings(file_path, result)
        self._check_pe_structure(file_path, result)
        self._calculate_hash(file_path, result)

        print(f"""
            Completed local analysis for {file_path.name}.
            Found {len(result.threats)} potential threats.
            """)

        # VirusTotal (only if needed)
        if self.config.virustotal_api_key and len(result.threats) > 0:
            print("Local analysis found potential threats, verifying with VirusTotal...")
            self._check_virustotal(file_path, result)

        # Final heuristic correlation
        self._final_risk_adjustment(file_path, result)

        # ✅ NOW compute final confidence + safety
        threat_count = len(result.threats)

        if threat_count == 0:
            result.confidence = 0.9
            result.is_safe = True
        elif threat_count == 1:
            result.confidence = 0.6
            result.is_safe = True
        else:
            result.confidence = 0.3
            result.is_safe = False

        return result
    
    def _check_extension(self, file_path: Path, result: ThreatResult):
        """
        Analyze file extension for malicious indicators.
        
        Checks:
        1. Dangerous extensions (.exe, .bat, .vbs, etc.)
        2. Double extensions (document.pdf.exe)
        3. Extension spoofing (spaces, unicode)
        4. Reverse path traversal in filename
        """
        filename = file_path.name
        parts = filename.split('.')
        
        # Check for double/triple extensions
        if len(parts) > 2:
            for i, part in enumerate(parts[:-1]):
                if part.lower() in self.DANGEROUS_EXTENSIONS:
                    result.add_threat('critical', 'double_extension',
                                    'Double extension detected (common malware trick)',
                                    {
                                        'filename': filename,
                                        'hidden_extension': part,
                                        'visible_extension': parts[-1],
                                        'danger': 'File may execute as executable despite appearing safe'
                                    })
        
        # Check if final extension is dangerous
        ext = file_path.suffix[1:].lower() if file_path.suffix else ''
        if ext in self.DANGEROUS_EXTENSIONS:
            result.add_threat('high', 'dangerous_extension',
                            f'Executable file type: .{ext}',
                            {
                                'extension': ext,
                                'danger': 'Can execute code on system'
                            })
        
        # Check for spaces in extension (obfuscation)
        if '. ' in filename or ' .' in filename:
            result.add_threat('high', 'extension_obfuscation',
                            'Suspicious spacing in filename (extension hiding)',
                            {
                                'filename': filename,
                                'danger': 'Attempts to hide real extension'
                            })
        
        # Check for reverse path traversal in filename
        # This is important! Filenames with ../ can escape directories
        if '../' in filename or '..\\'in filename:
            result.add_threat('critical', 'path_traversal_filename',
                            'Path traversal sequence in filename',
                            {
                                'filename': filename,
                                'danger': 'When extracted, file may escape intended directory'
                            })
        
        # Check for absolute paths in filename
        if filename.startswith('/') or re.match(r'^[A-Za-z]:\\', filename):
            result.add_threat('critical', 'absolute_path_filename',
                            'Absolute path in filename',
                            {
                                'filename': filename,
                                'danger': 'May overwrite system files when extracted'
                            })
        
        # Check for null bytes (can truncate filename in some systems)
        if '\x00' in filename:
            result.add_threat('critical', 'null_byte_filename',
                            'Null byte in filename (parser confusion)',
                            {
                                'filename': repr(filename),
                                'danger': 'Can bypass file type checks'
                            })
    
    def _check_magic_bytes(self, file_path: Path, result: ThreatResult):
        """
        Verify file type using magic bytes (file header).
        
        Magic bytes are the first few bytes that identify file type:
        - PDF files start with %PDF
        - ZIP files start with PK
        - EXE files start with MZ
        
        Attackers may rename .exe to .pdf to fool users.
        """
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
            
            # Determine actual file type from magic bytes
            actual_type = None
            for file_type, magic in self.MAGIC_BYTES.items():
                if header.startswith(magic):
                    actual_type = file_type
                    break
            
            result.metadata['magic_bytes'] = header.hex()
            result.metadata['detected_type'] = actual_type or 'unknown'
            
            # Check for extension mismatch
            claimed_ext = file_path.suffix[1:].lower() if file_path.suffix else ''
            
            if actual_type and claimed_ext:
                # Special case: Office docs are ZIP-based
                office_exts = {'docx', 'xlsx', 'pptx'}
                if claimed_ext in office_exts and actual_type == 'zip':
                    actual_type = claimed_ext
                
                if actual_type != claimed_ext and claimed_ext not in office_exts:
                    severity = 'critical' if actual_type == 'exe' else 'high'
                    result.add_threat(severity, 'extension_mismatch',
                                    f'Extension mismatch: claims .{claimed_ext} but is actually {actual_type}',
                                    {
                                        'claimed_extension': claimed_ext,
                                        'actual_type': actual_type,
                                        'magic_bytes': header.hex(),
                                        'danger': 'File type deception attempt'
                                    })
        
        except Exception as e:
            result.metadata['magic_bytes_error'] = str(e)
    
    def _analyze_entropy(self, file_path: Path, result: ThreatResult):
        """
        Calculate file entropy to detect packed/encrypted content.
        
        Entropy measures randomness:
        - Low entropy (< 3.0): Plain text, normal files
        - Medium entropy (3.0-5.0): Compressed files
        - High entropy (> 7.0): Encrypted or packed malware
        
        Malware often uses packers to:
        - Evade signature detection
        - Hide malicious code
        - Compress payload
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read(min(1024 * 1024, os.path.getsize(file_path)))  # Read max 1MB
            
            if not data:
                return
            
            # Calculate Shannon entropy
            counter = Counter(data)
            length = len(data)
            entropy = -sum((count/length) * math.log2(count/length) 
                          for count in counter.values())
            
            result.metadata['entropy'] = round(entropy, 2)
            
            # High entropy in executable files is very suspicious
            if entropy > 7.0:
                ext = file_path.suffix[1:].lower() if file_path.suffix else ''
                if ext in self.DANGEROUS_EXTENSIONS:
                    result.add_threat('high', 'high_entropy',
                                    f'Very high entropy: {entropy:.2f} (likely packed/encrypted)',
                                    {
                                        'entropy': round(entropy, 2),
                                        'threshold': 7.0,
                                        'danger': 'Packed executables often hide malware'
                                    })
                elif ext in ['zip', 'rar', '7z', 'gz']:
                    # High entropy is normal for compressed files
                    pass
                else:
                    result.add_threat('medium', 'high_entropy',
                                    f'High entropy: {entropy:.2f} (may be encrypted/obfuscated)',
                                    {'entropy': round(entropy, 2)})
            
        except Exception as e:
            result.metadata['entropy_error'] = str(e)
    
    def _extract_strings(self, file_path: Path, result: ThreatResult):
        """
        Extract and analyze strings from file.
        
        Looking for:
        - Shell commands (system, exec, powershell)
        - Network activity (URLs, IPs)
        - Obfuscation (base64, eval)
        - Suspicious function calls
        
        This is how AV software finds malware behavior indicators.
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read(min(1024 * 1024 * 5, os.path.getsize(file_path)))  # Read max 5MB
            
            found_suspicious = []
            
            # Check for suspicious strings
            for sus_string in self.SUSPICIOUS_STRINGS:
                if sus_string in data:
                    found_suspicious.append(sus_string.decode('utf-8', errors='ignore'))
            
            if found_suspicious:
                result.add_threat('high', 'suspicious_strings',
                                f'Found {len(found_suspicious)} suspicious command(s)',
                                {
                                    'strings': found_suspicious[:10],  # Limit to 10
                                    'danger': 'File contains code execution indicators'
                                })
            
            # Extract URLs
            url_pattern = rb'https?://[^\s<>"{}|\\^`\[\]]{4,}'
            urls = re.findall(url_pattern, data)
            if urls:
                decoded_urls = [url.decode('utf-8', errors='ignore') for url in urls[:10]]
                result.metadata['embedded_urls'] = decoded_urls
                
                # Check if any URLs are suspicious
                if len(urls) > 5:
                    result.add_threat('medium', 'multiple_urls',
                                    f'File contains {len(urls)} URLs',
                                    {
                                        'count': len(urls),
                                        'sample_urls': decoded_urls[:5]
                                    })
            
            # Check for PowerShell encoded commands
            if b'powershell' in data.lower() and b'-encodedcommand' in data.lower():
                result.add_threat('critical', 'powershell_encoded',
                                'PowerShell encoded command detected',
                                {
                                    'danger': 'Common malware delivery technique'
                                })
            
        except Exception as e:
            result.metadata['strings_error'] = str(e)
    
    def _check_pe_structure(self, file_path: Path, result: ThreatResult):
        """
        Analyze PE (Windows executable) structure.
        
        PE analysis can reveal:
        - Suspicious section names (.code, .rsrc)
        - Unusual imports (VirtualAlloc, CreateRemoteThread)
        - Timestamp anomalies
        - Packer signatures
        
        Note: This is a simplified check. Real AV uses full PE parsing.
        """
        ext = file_path.suffix[1:].lower() if file_path.suffix else ''
        if ext not in ['exe', 'dll', 'sys']:
            return
        
        try:
            with open(file_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if not dos_header.startswith(b'MZ'):
                    return
                
                # Get PE header offset
                pe_offset = int.from_bytes(dos_header[60:64], 'little')
                f.seek(pe_offset)
                
                # Read PE signature
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    result.add_threat('medium', 'invalid_pe',
                                    'Invalid PE structure (possibly corrupted or tampered)',
                                    {})
                    return
                
                result.metadata['pe_detected'] = True
                
                # Check for suspicious imports (simplified - would need full PE parsing)
                f.seek(0)
                data = f.read(min(1024 * 100, os.path.getsize(file_path)))
                
                suspicious_imports = [
                    b'VirtualAlloc',      # Memory allocation (shellcode execution)
                    b'CreateRemoteThread', # Code injection
                    b'WriteProcessMemory', # Process injection
                    b'SetWindowsHookEx',   # Keylogging
                    b'URLDownloadToFile',  # Download files
                ]
                
                found_imports = []
                for imp in suspicious_imports:
                    if imp in data:
                        found_imports.append(imp.decode())
                
                if found_imports:
                    result.add_threat('high', 'suspicious_imports',
                                    'Suspicious Windows API calls detected',
                                    {
                                        'imports': found_imports,
                                        'danger': 'Common in malware for code injection/evasion'
                                    })
                
        except Exception as e:
            result.metadata['pe_analysis_error'] = str(e)
    
    def _calculate_hash(self, file_path: Path, result: ThreatResult):
        """
        Calculate file hash for reputation lookup.
        
        Hashes are used to:
        - Identify known malware (hash databases)
        - Track file variants
        - Verify file integrity
        
        Common hash algorithms:
        - MD5 (fast, collisions possible)
        - SHA1 (deprecated but still used)
        - SHA256 (current standard)
        """
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            
            result.metadata['hashes'] = {
                'md5': md5.hexdigest(),
                'sha1': sha1.hexdigest(),
                'sha256': sha256.hexdigest()
            }
            
        except Exception as e:
            result.metadata['hash_error'] = str(e)
    
    def _check_virustotal(self, file_path: Path, result: ThreatResult):
        """
        Verify file against VirusTotal.
        
        VirusTotal aggregates 70+ AV engines:
        - Scans file with multiple antivirus products
        - Provides detection rates
        - Shows behavioral analysis
        
        Free tier: 4 requests/minute, 500/day
        """
        if not self.config.virustotal_api_key:
            return
        
        try:
            # First, check if file hash exists in VT database
            if 'hashes' not in result.metadata:
                self._calculate_hash(file_path, result)
            
            sha256 = result.metadata['hashes']['sha256']
            
            # Check hash first (doesn't count against quota)
            url = f'https://www.virustotal.com/api/v3/files/{sha256}'
            headers = {'x-apikey': self.config.virustotal_api_key}
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                print("File found in VirusTotal database, analyzing results...")
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                result.metadata['virustotal'] = {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'total_engines': total,
                    'detection_rate': f'{malicious}/{total}'
                }
                
                if malicious > 0:
                    severity = 'critical' if malicious > 3 else 'high'
                    result.add_threat(severity, 'virustotal_detection',
                                    f'Detected by {malicious}/{total} antivirus engines',
                                    {
                                        'malicious': malicious,
                                        'suspicious': suspicious,
                                        'total': total,
                                        'source': 'VirusTotal'
                                    })
                elif suspicious > 0:
                    result.add_threat('medium', 'virustotal_suspicious',
                                    f'Flagged as suspicious by {suspicious} engines',
                                    {'suspicious': suspicious})
                print(f"VirusTotal detection rate: {malicious}/{total} engines flagged this file.")
            
            elif response.status_code == 404:
                # File not in database - upload it (costs 1 request)
                if self.config.verbose:
                    print("  File not in VirusTotal database, uploading...")
                
                with open(file_path, 'rb') as f:
                    files = {'file': f}
                    upload_url = 'https://www.virustotal.com/api/v3/files'
                    upload_response = requests.post(upload_url, headers=headers, 
                                                   files=files, timeout=30)
                    
                    if upload_response.status_code == 200:
                        result.metadata['virustotal'] = 'UPLOADED - Check back in 1 minute'
                    else:
                        result.metadata['virustotal'] = f'Upload failed: {upload_response.status_code}'
                
                print("File not found in VirusTotal. Uploaded for analysis. Check back in a few minutes for results.")
            
            else:
                result.metadata['virustotal'] = f'ERROR: {response.status_code}'
                
        except Exception as e:
            result.metadata['virustotal'] = f'ERROR: {str(e)}'
            if self.config.verbose:
                print(f"  VirusTotal API error: {e}")

    
    def _final_risk_adjustment(self, file_path: Path, result: ThreatResult):
        ext = file_path.suffix[1:].lower()

        entropy = result.metadata.get('entropy', 0)
        threats = result.threats

        has_suspicious_strings = any(t['category'] == 'suspicious_strings' for t in threats)

        # 🔴 Strong heuristic: script + entropy + commands
        if ext in ['py', 'sh', 'js'] and entropy > 5.5 and has_suspicious_strings:
            result.add_threat(
                'high',
                'obfuscated_script',
                'Script file with obfuscation + execution indicators',
                {
                    'entropy': entropy,
                    'extension': ext,
                    'danger': 'Likely obfuscated or staged payload'
                }
            )


class TextScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config

    def analyze_text_for_scams(self, text: str) -> ThreatResult:
        result = ThreatResult(is_safe=True, confidence=0.7)
        lower_text = text.lower()

        # --- Extract URLs ---
        urls = re.findall(r'(https?://[^\s]+)', text)

        # --- Urgency ---
        urgency_phrases = [
            'act now', 'urgent', 'immediate action', 'within 24 hours',
            'account will be closed', 'suspended', 'expire', 'limited time',
            'verify immediately', 'confirm now', 'update required',
            'unusual activity', 'suspicious activity', 'unauthorized'
        ]

        for phrase in urgency_phrases:
            if phrase in lower_text:
                result.add_threat('high', 'urgency', f'Urgency tactic: "{phrase}"')

        # --- Sensitive info ---
        sensitive_requests = [
            'password', 'pin code', 'credit card', 'bank account',
            'verify your identity', 'confirm your details', 'update payment'
        ]

        for req in sensitive_requests:
            if req in lower_text:
                result.add_threat('high', 'sensitive_info', f'Requests sensitive info: "{req}"')

        # --- Generic greetings ---
        sender_patterns = [
            'dear customer', 'dear user', 'valued customer', 'account holder'
        ]

        for pattern in sender_patterns:
            if pattern in lower_text:
                result.add_threat('medium', 'generic_greeting', f'Generic greeting: "{pattern}"')

        # --- Threat language ---
        threat_phrases = [
            'legal action', 'penalty', 'arrest', 'warrant'
        ]

        for phrase in threat_phrases:
            if phrase in lower_text:
                result.add_threat('high', 'threat_language', f'Threatening language: "{phrase}"')

        # --- Rewards ---
        reward_phrases = [
            'you won', 'winner', 'claim your', 'free gift'
        ]

        for phrase in reward_phrases:
            if phrase in lower_text:
                result.add_threat('medium', 'reward', f'Suspicious reward: "{phrase}"')

        # --- URLs ---
        if urls:
            result.metadata['urls'] = urls
            if len(urls) > 2:
                result.add_threat('medium', 'multiple_urls', f'{len(urls)} URLs found')

        # --- Grammar ---
        grammar_issues = ['kindly', 'do the needful']
        for issue in grammar_issues:
            if issue in lower_text:
                result.add_threat('low', 'grammar', f'Unusual phrasing: "{issue}"')

        # --- Final scoring ---
        self._finalize(result)

        return result


    def analyze_text_with_ai(self, text: str) -> Dict:
        """
        Use OpenAI to analyze text for scam/phishing risk.
        Returns structured result.
        """

        if not self.config.openai_api_key:
            return {"ai_used": False}

        try:
            client = OpenAI(api_key=self.config.openai_api_key)

            response = client.chat.completions.create(
                model="gpt-4o-mini",  # cheap + good enough
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity assistant. "
                            "Analyze text for scam/phishing indicators.\n\n"
                            "Return ONLY valid JSON in this format:\n"
                            "{"
                            '"risk": "low|medium|high",'
                            '"reasons": ["reason1", "reason2"],'
                            '"summary": "short explanation"'
                            "}"
                        )
                    },
                    {
                        "role": "user",
                        "content": text
                    }
                ],
                temperature=0.2
            )

            content = response.choices[0].message.content

            # Try to parse JSON safely
            try:
                parsed = json.loads(content)
            except Exception:
                parsed = {
                    "risk": "unknown",
                    "reasons": [],
                    "summary": content[:200]
                }

            return {"ai_used": True, "result": parsed}
                
        except Exception as e:
            if self.config.verbose:
                print(f"AI analysis failed: {e}")
            return {"ai_used": False, "error": str(e)}

    def analyze_text_with_ai(self, text: str) -> Dict:
        """
        Use OpenAI to analyze text for scam/phishing risk.
        Returns structured result.
        """

        if not self.config.openai_api_key:
            return {"ai_used": False}

        try:
            client = OpenAI(api_key=self.config.openai_api_key)

            response = client.chat.completions.create(
                model="gpt-4o-mini",  # cheap + good enough
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity assistant. "
                            "Analyze text for scam/phishing indicators.\n\n"
                            "Return ONLY valid JSON in this format:\n"
                            "{"
                            '"risk": "low|medium|high",'
                            '"reasons": ["reason1", "reason2"],'
                            '"summary": "short explanation"'
                            "}"
                        )
                    },
                    {
                        "role": "user",
                        "content": text
                    }
                ],
                temperature=0.2
            )

            content = response.choices[0].message.content

            # Try to parse JSON safely
            try:
                parsed = json.loads(content)
            except Exception:
                parsed = {
                    "risk": "unknown",
                    "reasons": [],
                    "summary": content[:200]
                }

            return {"ai_used": True, "result": parsed}
                
        except Exception as e:
            if self.config.verbose:
                print(f"AI analysis failed: {e}")
            return {"ai_used": False, "error": str(e)}

    def _finalize(self, result: ThreatResult):
        n = len(result.threats)

        if n == 0:
            result.confidence = 0.9
        elif n == 1:
            result.confidence = 0.6
        else:
            result.confidence = 0.3
            result.is_safe = False

    def scan(self, text: str) -> ThreatResult:
        """Main entry point for text scanning (CLI + API)"""

        result = self.analyze_text_for_scams(text)

        # Decide if escalation is needed
        high_count = sum(1 for t in result.threats if t['severity'] in ('high', 'critical'))

        if high_count >= 1 and self.config.openai_api_key:
            print("High-risk indicators found in text, performing AI analysis...")
            ai_result = self.analyze_text_with_ai(text)
            result.metadata['ai'] = ai_result

            # Optional: adjust confidence slightly
            if ai_result.get("ai_used") and ai_result.get("result", {}).get("risk") == "high":
                result.is_safe = False
                result.confidence = min(result.confidence, 0.3)

        return result
    
# ============================================
# MAIN CLI INTERFACE
# ============================================

def print_result(result: ThreatResult, verbose: bool = False):
    """Pretty print scan result"""
    
    # Status header
    if result.is_safe:
        print("\n SAFE - No threats detected")
    else:
        severity_counts = Counter(t['severity'] for t in result.threats)
        print(f"\n THREATS DETECTED - {len(result.threats)} issue(s) found")
        print(f"   Critical: {severity_counts.get('critical', 0)}, "
              f"High: {severity_counts.get('high', 0)}, "
              f"Medium: {severity_counts.get('medium', 0)}, "
              f"Low: {severity_counts.get('low', 0)}")
    
    print(f"   Confidence: {result.confidence * 100:.0f}%")
    
    # Print threats
    if result.threats:
        print("\n Detected Threats:")
        for i, threat in enumerate(result.threats, 1):
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(threat['severity'], '⚪')
            
            print(f"\n  {i}. {severity_emoji} [{threat['severity'].upper()}] {threat['description']}")
            print(f"     Category: {threat['category']}")
            
            if verbose and threat['details']:
                print(f"     Details:")
                for key, value in threat['details'].items():
                    if isinstance(value, (list, dict)):
                        print(f"       {key}: {json.dumps(value, indent=10)}")
                    else:
                        print(f"       {key}: {value}")
    
    # Print metadata
    if verbose and result.metadata:
        print("\n Metadata:")
        for key, value in result.metadata.items():
            if isinstance(value, dict):
                print(f"   {key}:")
                for k, v in value.items():
                    print(f"     {k}: {v}")
            else:
                print(f"   {key}: {value}")


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Security Scanner - Educational & Production Ready',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan a URL
  python security_scanner.py -u https://example.com
  
  # Scan a file
  python security_scanner.py -f suspicious.exe
  
  # Scan with API verification
  export GOOGLE_SAFE_BROWSING_API_KEY="your-key"
  export VIRUSTOTAL_API_KEY="your-key"
  python security_scanner.py -u https://example.com -v
  
  # Scan multiple items
  python security_scanner.py -u https://site1.com -u https://site2.com -f file1.exe -f file2.pdf
        '''
    )
    
    parser.add_argument('-u', '--url', action='append', help='URL to scan (can specify multiple)')
    parser.add_argument('-f', '--file', action='append', help='File to scan (can specify multiple)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--text', action='append', help='Text to scan (can specify multiple)')
    parser.add_argument('--no-api', action='store_true', help='Skip API verification even if keys are set')
    
    args = parser.parse_args()
    
    if not args.url and not args.file and not args.text:
        parser.print_help()
        return
    
    # Load configuration
    config = ScannerConfig.from_env()
    config.verbose = args.verbose
    
    if args.no_api:
        config.google_api_key = None
        config.virustotal_api_key = None
    
    # Print configuration status
    print("  Security Scanner v1.0")
    print("=" * 60)
    print(f"Google Safe Browsing: {'✓ Enabled' if config.google_api_key else '✗ Disabled (set GOOGLE_SAFE_BROWSING_API_KEY)'}")
    print(f"VirusTotal: {'✓ Enabled' if config.virustotal_api_key else '✗ Disabled (set VIRUSTOTAL_API_KEY)'}")
    print(f"AI Analysis: {'✓ Enabled' if getattr(config, 'openai_api_key', None) else '✗ Disabled (set OPENAI_API_KEY)'}")
    print("=" * 60)
    
    # Scan URLs
    if args.url:
        scanner = URLScanner(config)
        for url in args.url:
            print(f"\n Scanning URL: {url}")
            print("-" * 60)
            result = scanner.scan(url)
            print_result(result, args.verbose)
    
    # Scan files
    if args.file:
        scanner = FileScanner(config)
        for file_path in args.file:
            print(f"\n Scanning File: {file_path}")
            print("-" * 60)
            result = scanner.scan(file_path)
            print_result(result, args.verbose)
    # Scan text
    if args.text:
        scanner = TextScanner(config)

        for text in args.text:
            print(f"\n Scanning Text:")
            print("-" * 60)
            print(f"   \"{text[:80]}{'...' if len(text) > 80 else ''}\"")

            result = scanner.scan(text)

            print_result(result, args.verbose)
if __name__ == '__main__':
    main()