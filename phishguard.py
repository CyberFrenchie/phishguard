import re
import sys

def levenshtein_distance(s1, s2):
    """Simple Levenshtein distance for typosquatting check"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

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
    
    # Typosquatting check
    common_legit = ['google', 'paypal', 'amazon', 'microsoft', 'apple', 'facebook', 'netflix', 'bankofamerica', 'chase']
    # Extract base domain (e.g., 'paypa1.com' → 'paypa1')
    domain = re.sub(r'^https?://(www\.)?', '', url).split('/')[0].lower()
    domain_clean = domain.split('.')[0]  # Strip TLD
    for legit in common_legit:
        dist = levenshtein_distance(domain_clean, legit)
        if 1 <= dist <= 2 and len(domain_clean) >= len(legit) - 2:  # Allow small edits/inserts
            return True, f"Possible typosquatting: '{domain_clean}' close to '{legit}' (distance {dist})"
    
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
