import re
from datetime import datetime
import time

rate_limit_data = {}
REQUEST_LIMIT = 20
TIME_WINDOW = 60  # seconds

failed_attempts = {}
MAX_ATTEMPTS = 5

blocked_ips = set()
request_logs = []

# Patterns for attacks
sql_injection_patterns = [
    r"(\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b)",
]

xss_patterns = [
    r"<script.*?>.*?</script>",
]

def is_malicious(data):
    for pattern in sql_injection_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return "SQL Injection"

    for pattern in xss_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return "XSS Attack"

    return None

def log_request(ip, endpoint, status, threat=None):
    request_logs.append({
        "ip": ip,
        "endpoint": endpoint,
        "status": status,
        "threat": threat,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

def track_failed_login(ip):
    if ip not in failed_attempts:
        failed_attempts[ip] = 1
    else:
        failed_attempts[ip] += 1

    if failed_attempts[ip] >= MAX_ATTEMPTS:
        blocked_ips.add(ip)
        return True
    return False

def reset_attempts(ip):
    if ip in failed_attempts:
        failed_attempts[ip] = 0

def check_rate_limit(ip):
    current_time = time.time()

    if ip not in rate_limit_data:
        rate_limit_data[ip] = []

    # Keep only recent requests
    rate_limit_data[ip] = [
        timestamp for timestamp in rate_limit_data[ip]
        if current_time - timestamp < TIME_WINDOW
    ]

    rate_limit_data[ip].append(current_time)

    if len(rate_limit_data[ip]) > REQUEST_LIMIT:
        return True
    return False

