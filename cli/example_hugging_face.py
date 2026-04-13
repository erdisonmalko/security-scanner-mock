from text_analyzer_hugging_face import SentimentAnalyzer

def serialize_sentiment_result(result: dict):
    return {
        "sentiment": result.get("sentiment"),
        "confidence": result.get("confidence"),
        "provider": result.get("provider", "huggingface")
    }

text = """
Urgent! Your account has been compromised. 
You must verify your password immediately or you will lose access. 
Click the link below to update your information:
http://fakebank-login.example.com
"""
scanner = SentimentAnalyzer(provider="huggingface")
result = scanner.analyze(text)  # returns dict

if 'error' in result.keys():
    print(f"Error: {result['error']}")
else:
    serialize_sentiment = serialize_sentiment_result(result)
    print(f"Sentiment Analysis Result: {serialize_sentiment}")