#!/usr/bin/env python3
"""
Enhanced Text Analyzer with Sentiment Analysis
Detects phishing/scams using emotional manipulation patterns
"""

import os
import re
import json
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass, field

# ============================================
# SENTIMENT ANALYSIS INTEGRATION
# ============================================
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

        
class SentimentAnalyzer:
    """
    Analyzes text sentiment to detect emotional manipulation.
    
    Phishing/scams often use:
    - Fear/urgency (NEGATIVE sentiment with urgent words)
    - Fake rewards (POSITIVE sentiment with prize claims)
    - Authority pressure (NEGATIVE + threatening language)
    """
    
    def __init__(self, api_key: Optional[str] = None, provider: str = 'huggingface'):
        self.api_key = api_key or os.getenv('HUGGINGFACE_API_KEY')
        self.provider = provider
        
    def analyze_huggingface(self, text: str) -> Dict:
        """
        Use Hugging Face's sentiment analysis models.
        
        Models available:
        - distilbert-base-uncased-finetuned-sst-2-english (general)
        - twitter-roberta-base-sentiment (social media)
        - finiteautomata/bertweet-base-sentiment-analysis (tweets)
        """
        if not self.api_key:
            return {'error': 'No Hugging Face API key'}
        
        # Fixed URL (removed 'lish' from the end)
        API_URL = "https://router.huggingface.co/hf-inference/models/distilbert/distilbert-base-uncased-finetuned-sst-2-english"
        headers = {"Authorization": f"Bearer {self.api_key}"}

        try:
            response = requests.post(
                    API_URL,
                    headers=headers,
                    json={"inputs": text, "options": {"wait_for_model": True}},
                    timeout=20
                )
            
            if response.status_code == 200:
                result = response.json()
                
                # This specific model returns: [[{'label': 'LABEL_0', 'score': 0.99}, ...]]
                if isinstance(result, list) and len(result) > 0:
                    data = result[0] if isinstance(result[0], list) else result
                    
                    # The model sorts by highest score, so index 0 is your result
                    sentiment = data[0]['label']
                    confidence = data[0]['score']
                    
                    return {
                        'sentiment': sentiment,
                        'confidence': confidence,
                        'provider': 'huggingface'
                    }
            else:
                return {'error': f'HTTP {response.status_code}', 'msg': response.text}

                
        except Exception as e:
            return {'error': str(e)}
        
        return {'error': 'Unknown error'}
    
    def analyze_google(self, text: str) -> Dict:
        """
        Use Google Cloud Natural Language API.
        
        Provides:
        - Sentiment score (-1.0 to 1.0)
        - Magnitude (strength of emotion)
        - Entity analysis
        """
        if not self.api_key:
            return {'error': 'No Google API key'}
        
        url = f"https://language.googleapis.com/v1/documents:analyzeSentiment?key={self.api_key}"
        
        payload = {
            "document": {
                "type": "PLAIN_TEXT",
                "content": text
            },
            "encodingType": "UTF8"
        }
        
        try:
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                sentiment = data['documentSentiment']
                
                # Convert score to label
                score = sentiment['score']
                if score > 0.25:
                    label = 'POSITIVE'
                elif score < -0.25:
                    label = 'NEGATIVE'
                else:
                    label = 'NEUTRAL'
                
                return {
                    'sentiment': label,
                    'score': score,
                    'magnitude': sentiment['magnitude'],
                    'confidence': abs(score),
                    'provider': 'google'
                }
            else:
                return {'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def analyze(self, text: str) -> Dict:
        """Main analysis method - routes to appropriate provider"""
        if self.provider == 'huggingface':
            return self.analyze_huggingface(text)
        elif self.provider == 'google':
            return self.analyze_google(text)
        else:
            return {'error': f'Unknown provider: {self.provider}'}


# ============================================
# ENHANCED TEXT SCANNER
# ============================================

@dataclass
class TextThreat:
    """Individual threat found in text"""
    category: str
    severity: str  # low, medium, high, critical
    description: str
    evidence: List[str] = field(default_factory=list)
    sentiment_data: Dict = field(default_factory=dict)


@dataclass
class TextScanResult:
    """Result of text analysis"""
    is_scam: bool
    risk_score: float  # 0.0 to 1.0
    threats: List[TextThreat] = field(default_factory=list)
    sentiment: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)


class EnhancedTextScanner:
    """
    Advanced text scanner combining:
    1. Pattern matching (existing techniques)
    2. Sentiment analysis (emotional manipulation)
    3. Linguistic analysis (grammar, urgency)
    """
    
    # Phishing/scam indicators
    URGENCY_PHRASES = [
        'act now', 'urgent', 'immediate action', 'within 24 hours',
        'expires today', 'last chance', 'limited time', 'hurry',
        'don\'t miss out', 'final notice', 'immediately', 'asap'
    ]
    
    FEAR_PHRASES = [
        'account suspended', 'account closed', 'locked', 'frozen',
        'unauthorized', 'suspicious activity', 'security alert',
        'unusual activity', 'compromised', 'hacked', 'breach'
    ]
    
    THREAT_PHRASES = [
        'legal action', 'arrest', 'warrant', 'penalty', 'fine',
        'consequences', 'lose access', 'terminated', 'lawsuit'
    ]
    
    REWARD_PHRASES = [
        'you won', 'winner', 'prize', 'claim your', 'free gift',
        'congratulations', 'selected', 'lucky', 'refund', 'cashback'
    ]
    
    SENSITIVE_REQUESTS = [
        'password', 'pin', 'ssn', 'social security', 'credit card',
        'cvv', 'account number', 'routing number', 'verify identity',
        'confirm details', 'date of birth', 'mother\'s maiden'
    ]
    
    def __init__(self, sentiment_api_key: Optional[str] = None, 
                 sentiment_provider: str = 'huggingface'):
        self.sentiment_analyzer = SentimentAnalyzer(sentiment_api_key, sentiment_provider)
    
    def scan(self, text: str, use_sentiment: bool = True) -> TextScanResult:
        """Comprehensive text analysis"""
        result = TextScanResult(is_scam=False, risk_score=0.0)
        text_lower = text.lower()
        
        # 1. Pattern-based analysis
        self._check_urgency(text_lower, result)
        self._check_fear_tactics(text_lower, result)
        self._check_threats(text_lower, result)
        self._check_rewards(text_lower, result)
        self._check_sensitive_info(text_lower, result)
        self._check_generic_greetings(text_lower, result)
        self._extract_urls(text, result)
        
        # 2. Sentiment analysis (if enabled)
        if use_sentiment:
            sentiment = self.sentiment_analyzer.analyze(text)
            result.sentiment = sentiment
            
            if 'error' not in sentiment:
                self._analyze_sentiment_context(text_lower, sentiment, result)
        
        # 3. Calculate risk score
        self._calculate_risk_score(result)
        
        return result
    
    def _check_urgency(self, text: str, result: TextScanResult):
        """Detect urgency tactics"""
        found = [phrase for phrase in self.URGENCY_PHRASES if phrase in text]
        
        if found:
            severity = 'high' if len(found) >= 2 else 'medium'
            result.threats.append(TextThreat(
                category='urgency',
                severity=severity,
                description=f'Urgency tactics detected ({len(found)} phrases)',
                evidence=found
            ))
    
    def _check_fear_tactics(self, text: str, result: TextScanResult):
        """Detect fear-inducing language"""
        found = [phrase for phrase in self.FEAR_PHRASES if phrase in text]
        
        if found:
            result.threats.append(TextThreat(
                category='fear',
                severity='high',
                description='Fear tactics detected',
                evidence=found
            ))
    
    def _check_threats(self, text: str, result: TextScanResult):
        """Detect threatening language"""
        found = [phrase for phrase in self.THREAT_PHRASES if phrase in text]
        
        if found:
            result.threats.append(TextThreat(
                category='threats',
                severity='critical',
                description='Threatening language detected',
                evidence=found
            ))
    
    def _check_rewards(self, text: str, result: TextScanResult):
        """Detect fake reward claims"""
        found = [phrase for phrase in self.REWARD_PHRASES if phrase in text]
        
        if found:
            severity = 'high' if len(found) >= 2 else 'medium'
            result.threats.append(TextThreat(
                category='reward_scam',
                severity=severity,
                description='Unsolicited reward claim detected',
                evidence=found
            ))
    
    def _check_sensitive_info(self, text: str, result: TextScanResult):
        """Detect requests for sensitive information"""
        found = [phrase for phrase in self.SENSITIVE_REQUESTS if phrase in text]
        
        if found:
            result.threats.append(TextThreat(
                category='data_theft',
                severity='critical',
                description='Requests sensitive personal information',
                evidence=found
            ))
    
    def _check_generic_greetings(self, text: str, result: TextScanResult):
        """Detect generic greetings (legitimate companies use names)"""
        generic = ['dear customer', 'dear user', 'dear member', 'valued customer']
        found = [g for g in generic if g in text]
        
        if found:
            result.threats.append(TextThreat(
                category='generic_greeting',
                severity='medium',
                description='Generic greeting (legitimate companies use your name)',
                evidence=found
            ))
    
    def _extract_urls(self, text: str, result: TextScanResult):
        """Extract and count URLs"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        
        result.metadata['url_count'] = len(urls)
        result.metadata['urls'] = urls[:5]  # Store first 5
        
        if len(urls) > 3:
            result.threats.append(TextThreat(
                category='multiple_urls',
                severity='medium',
                description=f'Contains {len(urls)} URLs (suspicious for legitimate messages)',
                evidence=urls[:3]
            ))
    
    def _analyze_sentiment_context(self, text: str, sentiment: Dict, result: TextScanResult):
        """
        Combine sentiment with context to detect manipulation.
        
        Patterns:
        - NEGATIVE sentiment + urgency = FEAR-based scam
        - POSITIVE sentiment + rewards = GREED-based scam
        - Mixed sentiment + threats = AUTHORITY scam
        """
        if 'sentiment' not in sentiment:
            return
        
        sent_label = sentiment['sentiment']
        confidence = sentiment.get('confidence', 0.5)
        
        # Pattern 1: Negative sentiment + urgency/fear
        has_urgency = any(t.category in ['urgency', 'fear'] for t in result.threats)
        if sent_label == 'NEGATIVE' and has_urgency and confidence > 0.7:
            result.threats.append(TextThreat(
                category='emotional_manipulation',
                severity='critical',
                description='Fear-based manipulation detected (negative sentiment + urgency)',
                sentiment_data={
                    'pattern': 'fear_urgency',
                    'sentiment': sent_label,
                    'confidence': confidence
                }
            ))
        
        # Pattern 2: Positive sentiment + reward claims
        has_reward = any(t.category == 'reward_scam' for t in result.threats)
        if sent_label == 'POSITIVE' and has_reward and confidence > 0.7:
            result.threats.append(TextThreat(
                category='emotional_manipulation',
                severity='high',
                description='Greed-based manipulation detected (positive sentiment + fake rewards)',
                sentiment_data={
                    'pattern': 'greed_reward',
                    'sentiment': sent_label,
                    'confidence': confidence
                }
            ))
        
        # Pattern 3: Negative sentiment + threats
        has_threats = any(t.category == 'threats' for t in result.threats)
        if sent_label == 'NEGATIVE' and has_threats:
            result.threats.append(TextThreat(
                category='emotional_manipulation',
                severity='critical',
                description='Authority-based manipulation (threats + negative sentiment)',
                sentiment_data={
                    'pattern': 'authority_threat',
                    'sentiment': sent_label,
                    'confidence': confidence
                }
            ))
    
    def _calculate_risk_score(self, result: TextScanResult):
        """Calculate overall risk score"""
        if not result.threats:
            result.risk_score = 0.0
            result.is_scam = False
            return
        
        # Weight by severity
        weights = {'critical': 0.4, 'high': 0.25, 'medium': 0.15, 'low': 0.05}
        
        score = 0.0
        for threat in result.threats:
            score += weights.get(threat.severity, 0.1)
        
        # Cap at 1.0
        result.risk_score = min(score, 1.0)
        
        # Threshold for scam classification
        result.is_scam = result.risk_score >= 0.5


# ============================================
# CLI INTERFACE
# ============================================

def print_text_result(result: TextScanResult, verbose: bool = False):
    """Pretty print text analysis result"""
    
    # Header
    risk_emoji = '🚨' if result.is_scam else '⚠️' if result.risk_score > 0.3 else '✅'
    risk_label = 'HIGH RISK SCAM' if result.is_scam else 'SUSPICIOUS' if result.risk_score > 0.3 else 'SAFE'
    
    print(f"\n{risk_emoji} {risk_label}")
    print(f"Risk Score: {result.risk_score * 100:.0f}%")
    
    # Sentiment
    if result.sentiment and 'error' not in result.sentiment:
        sent = result.sentiment['sentiment']
        conf = result.sentiment.get('confidence', 0) * 100
        emoji = '😊' if sent == 'POSITIVE' else '😟' if sent == 'NEGATIVE' else '😐'
        print(f"Sentiment: {emoji} {sent} ({conf:.0f}% confidence)")
    
    # Threats
    if result.threats:
        print(f"\n📋 Detected Issues ({len(result.threats)}):")
        
        for i, threat in enumerate(result.threats, 1):
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(threat.severity, '⚪')
            
            print(f"\n  {i}. {severity_emoji} [{threat.severity.upper()}] {threat.description}")
            
            if verbose and threat.evidence:
                print(f"     Evidence: {', '.join(threat.evidence[:5])}")
            
            if verbose and threat.sentiment_data:
                print(f"     Sentiment Analysis: {threat.sentiment_data}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enhanced Text Analyzer with Sentiment Analysis',
        epilog='''
Examples:
  # Analyze text from command line
  python text_analyzer.py -t "Your account has been suspended! Click here now!"
  
  # Analyze text from file
  python text_analyzer.py -f phishing_email.txt
  
  # Use Google API instead of Hugging Face
  python text_analyzer.py -t "Win a free iPhone!" --provider google
  
  # Skip sentiment analysis (faster, local only)
  python text_analyzer.py -t "Some text" --no-sentiment
        '''
    )
    
    parser.add_argument('-t', '--text', help='Text to analyze')
    parser.add_argument('-f', '--file', help='File containing text to analyze')
    parser.add_argument('--provider', choices=['huggingface', 'google'], 
                       default='huggingface', help='Sentiment API provider')
    parser.add_argument('--no-sentiment', action='store_true', 
                       help='Skip sentiment analysis (local patterns only)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Get text
    if args.text:
        text = args.text
    elif args.file:
        with open(args.file, 'r') as f:
            text = f.read()
    else:
        parser.print_help()
        return
    
    # Get API key
    if not args.no_sentiment:
        if args.provider == 'huggingface':
            api_key = os.getenv('HUGGINGFACE_API_KEY')
            if not api_key:
                print("⚠️  HUGGINGFACE_API_KEY not set")
                print("   Get your key at: https://huggingface.co/settings/tokens")
                print("   Or use --no-sentiment for local analysis only\n")
        elif args.provider == 'google':
            api_key = os.getenv('GOOGLE_CLOUD_API_KEY')
            if not api_key:
                print("⚠️  GOOGLE_CLOUD_API_KEY not set")
                print("   Or use --no-sentiment for local analysis only\n")
    else:
        api_key = None
    
    # Analyze
    print("\n🔍 Analyzing Text...")
    print("=" * 60)
    
    scanner = EnhancedTextScanner(api_key, args.provider)
    result = scanner.scan(text, use_sentiment=not args.no_sentiment)
    
    print_text_result(result, args.verbose)
    
    if args.verbose:
        print("\n📊 Metadata:")
        for key, value in result.metadata.items():
            print(f"   {key}: {value}")
    
    print("\n" + "=" * 60)


if __name__ == '__main__':
    main()