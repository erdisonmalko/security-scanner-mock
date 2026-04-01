from security_scanner import ScannerConfig, TextScanner
# --- Set up config with API key ---
config = ScannerConfig.from_env()
config.verbose = True 

# --- Create the TextScanner ---
scanner = TextScanner(config)

# --- Test text ---
test_text = """
Urgent! Your account has been compromised. 
You must verify your password immediately or you will lose access. 
Click the link below to update your information:
http://fakebank-login.example.com
"""

# --- Call AI analysis directly ---
ai_result = scanner.analyze_text_with_ai(test_text)

print("AI Analysis Result:")
print(ai_result)