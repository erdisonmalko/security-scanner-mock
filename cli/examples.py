#!/usr/bin/env python3
"""
Example: Using the Security Scanner Programmatically

This shows how to integrate the scanner into your own Python applications.
"""

import sys
import os
from dotenv import load_dotenv
load_dotenv()
# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security_scanner import URLScanner, FileScanner, ScannerConfig
from create_example_files import TEST_DIR

def example_url_scanning():
    """Example: Scan URLs with custom configuration"""
    print("=" * 60)
    print("Example 1: URL Scanning")
    print("=" * 60)
    
    # Configure scanner
    config = ScannerConfig(
        google_api_key=os.getenv('GOOGLE_SAFE_BROWSING_API_KEY'),
        verbose=True
    )
    
    scanner = URLScanner(config)
    
    # Test URLs
    test_urls = [
        "https://google.com",                          # Safe
        "http://192.168.1.1/admin",                   # IP address
        "https://paypa1-secure.com/verify",           # Typosquatting
        "javascript:alert(document.cookie)",          # JS execution
        "https://example.com/../../../etc/passwd",    # Path traversal
        "https://xn--googl-5ve.com/login",            # Punycode phishing
        "https://bit.ly/3abcXYZ",                     # URL shortener
        "http://example.com/login?user=admin&pw=123", # Suspicious query
        ]
    
    for url in test_urls:
        print(f"\nScanning: {url}")
        result = scanner.scan(url)
        
        if result.is_safe:
            print("   SAFE")
        else:
            print(f"   {len(result.threats)} threat(s) found:")
            for threat in result.threats[:2]:  # Show first 2
                print(f"      - {threat['description']}")

def example_file_scanning():
    """Example: Scan files and handle results"""
    print("\n" + "=" * 60)
    print("Example 2: File Scanning")
    print("=" * 60)
    
    config = ScannerConfig(
        virustotal_api_key=os.getenv('VIRUSTOTAL_API_KEY'),
        verbose=False
    )
    
    scanner = FileScanner(config)
    
    # Test files
    test_files = [
        f"{TEST_DIR}/safe_document.txt",
        f"{TEST_DIR}/invoice.pdf.exe",
        f"{TEST_DIR}/suspicious_script.py",
        f"{TEST_DIR}/unknown.bin",
        f"{TEST_DIR}/payload.scr",
    ]
    
    for file_path in test_files:
        if not os.path.exists(file_path):
            print(f"\n  File not found: {file_path}")
            continue
        
        print(f"\n Scanning: {file_path}")
        result = scanner.scan(file_path)
        
        print(f"   Status: {' SAFE' if result.is_safe else 'THREATS'}")
        print(f"   Size: {result.metadata.get('size', 0)} bytes")
        print(f"   Entropy: {result.metadata.get('entropy', 'N/A')}")
        
        if not result.is_safe:
            print(f"   Threats: {len(result.threats)}")
            for threat in result.threats[:2]:
                print(f"      - [{threat['severity']}] {threat['category']}")

def example_custom_analysis():
    """Example: Build custom analysis logic"""
    print("\n" + "=" * 60)
    print("Example 3: Custom Analysis")
    print("=" * 60)
    
    config = ScannerConfig()
    url_scanner = URLScanner(config)
    file_scanner = FileScanner(config)
    
    # Scan multiple items and aggregate
    items = [
        ("url", "https://suspicious-site.com/login"),
        ("file", f"{TEST_DIR}/safe_document.txt"),
    ]
    
    critical_threats = []
    high_threats = []
    
    for item_type, item in items:
        if item_type == "url":
            result = url_scanner.scan(item)
        else:
            if not os.path.exists(item):
                continue
            result = file_scanner.scan(item)
        
        # Categorize by severity
        for threat in result.threats:
            if threat['severity'] == 'critical':
                critical_threats.append((item, threat))
            elif threat['severity'] == 'high':
                high_threats.append((item, threat))
    
    # Report
    print(f"\n Analysis Summary:")
    print(f"   Critical threats: {len(critical_threats)}")
    print(f"   High threats: {len(high_threats)}")
    
    if critical_threats:
        print("\n CRITICAL THREATS:")
        for item, threat in critical_threats:
            print(f"   {item}")
            print(f"      → {threat['description']}")

def example_building_report():
    """Example: Generate detailed security report"""
    print("\n" + "=" * 60)
    print("Example 4: Security Report Generation")
    print("=" * 60)
    
    config = ScannerConfig(verbose=False)
    scanner = FileScanner(config)
    
    # Scan a file
    file_path = "test_files/suspicious_script.py"
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return
    
    result = scanner.scan(file_path)
    
    # Generate report
    print(f"\n{'='*60}")
    print(f"SECURITY SCAN REPORT")
    print(f"{'='*60}")
    print(f"File: {file_path}")
    print(f"Size: {result.metadata.get('size', 'Unknown')} bytes")
    print(f"Type: {result.metadata.get('extension', 'Unknown')}")
    print(f"Entropy: {result.metadata.get('entropy', 'N/A')}")
    
    if 'hashes' in result.metadata:
        print(f"\nHashes:")
        for hash_type, hash_value in result.metadata['hashes'].items():
            print(f"  {hash_type.upper()}: {hash_value}")
    
    print(f"\nRISK ASSESSMENT: {' SAFE' if result.is_safe else '🚨 THREATS DETECTED'}")
    print(f"Confidence: {result.confidence * 100:.0f}%")
    
    if result.threats:
        print(f"\nDetailed Findings ({len(result.threats)} issues):")
        for i, threat in enumerate(result.threats, 1):
            print(f"\n  {i}. [{threat['severity'].upper()}] {threat['description']}")
            print(f"     Category: {threat['category']}")
            if threat['details']:
                for key, value in threat['details'].items():
                    if key != 'reason':
                        print(f"     {key}: {value}")

def main():
    """Run all examples"""
    print("\n  Security Scanner - Usage Examples\n")
    
    # Check if API keys are set
    has_google = bool(os.getenv('GOOGLE_SAFE_BROWSING_API_KEY'))
    has_vt = bool(os.getenv('VIRUSTOTAL_API_KEY'))
    
    print("Configuration:")
    print(f"  Google Safe Browsing: {'✓ Enabled' if has_google else '✗ Not configured'}")
    print(f"  VirusTotal: {'✓ Enabled' if has_vt else '✗ Not configured'}")
    
    if not has_google and not has_vt:
        print("\n  No API keys configured. Set environment variables:")
        print("     export GOOGLE_SAFE_BROWSING_API_KEY='your-key'")
        print("     export VIRUSTOTAL_API_KEY='your-key'\n")
    
    # Run examples
    try:
        example_url_scanning()
        example_file_scanning()
        example_custom_analysis()
        example_building_report()
        
        print("\n" + "=" * 60)
        print(" All examples completed!")
        print("=" * 60)
        
    except KeyboardInterrupt:
        print("\n\n  Examples interrupted by user")
    except Exception as e:
        print(f"\n\n  Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()