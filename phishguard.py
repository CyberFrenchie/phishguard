import re
import sys

def is_suspicious_url(url):
    """Basic URL phishing checks"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url  # Assume https if missing
    
    # Common phishing patterns
    suspicious_patterns = [
        r'paypal.*\.com.*login', r'bank.*\.com.*verify', r'crypto.*wallet', 
        r'urgent.*action', r'account.*suspended', r'login.*now',
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP instead of domain
        r'http://',  # Plain HTTP = red flag
        r'@',        # User@domain in URL (rare legit)
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True, f"Matched suspicious pattern: {pattern}"
    
    # Typosquatting rough check (e.g., g00gle.com)
    common_legit = ['google', 'paypal', 'amazon', 'microsoft', 'apple']
    domain = re.sub(r'^https?://(www\.)?', '', url).split('/')[0].lower()
    for legit in common_legit:
        if legit in domain and domain != legit + '.com':
            return True, f"Possible typosquatting near '{legit}'"
    
    return False, "No obvious URL red flags"

def is_suspicious_text(text):
    """Simple text-based phishing indicators"""
    red_flags = [
        r'(urgent|important|immediately|verify now|account suspended|update payment)',
        r'(bitcoin|crypto|wallet|send money|wire transfer)',
        r'(click here|login to confirm|secure your account)',
        r'(password|credential|login details)',
    ]
    
    score = 0
    reasons = []
    for flag in red_flags:
        if re.search(flag, text, re.IGNORECASE):
            score += 1
            reasons.append(flag)
    
    if score >= 2:
        return True, f"High risk text ({score}/4 flags): {', '.join(reasons)}"
    elif score >= 1:
        return True, f"Medium risk text ({score}/4 flags): {', '.join(reasons)}"
    return False, "Text seems clean"

def main():
    print("PhishGuard - Simple Phishing Detector CLI")
    print("Enter a URL or text snippet (or 'quit' to exit)\n")
    
    while True:
        user_input = input("> ").strip()
        if user_input.lower() in ['quit', 'exit', 'q']:
            break
        if not user_input:
            continue
        
        # Treat as URL if it looks like one
        if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$|^https?://', user_input):
            is_phish_url, reason_url = is_suspicious_url(user_input)
            print(f"URL Check: {'⚠️ Suspicious' if is_phish_url else '✅ Seems safe'}")
            print(f"  Reason: {reason_url}\n")
        else:
            # Treat as text
            is_phish_text, reason_text = is_suspicious_text(user_input)
            print(f"Text Check: {'⚠️ Suspicious' if is_phish_text else '✅ Seems safe'}")
            print(f"  Reason: {reason_text}\n")

if __name__ == "__main__":
    main()
