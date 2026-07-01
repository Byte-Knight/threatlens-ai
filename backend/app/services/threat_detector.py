import re


def detect_threats(parsed_log: dict):
    log_text = parsed_log["log_text"]

    detected_attacks = []

    sql_injection_patterns = [
        r"(?i)or\s+'1'\s*=\s*'1",
        r"(?i)union\s+select",
        r"(?i)drop\s+table",
    ]

    xss_patterns = [
        r"(?i)<script>",
        r"(?i)javascript:",
        r"(?i)onerror=",
    ]

    directory_traversal_patterns = [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
    ]

    if parsed_log["failed_logins"] >= 3:
        detected_attacks.append("SSH Brute Force")

    if parsed_log["port_scan_attempts"] >= 5:
        detected_attacks.append("Port Scan")

    if parsed_log["request_count"] >= 10:
        detected_attacks.append("DDoS / Request Flooding")

    if any(re.search(pattern, log_text) for pattern in sql_injection_patterns):
        detected_attacks.append("SQL Injection")

    if any(re.search(pattern, log_text) for pattern in xss_patterns):
        detected_attacks.append("Cross-Site Scripting (XSS)")

    if any(re.search(pattern, log_text) for pattern in directory_traversal_patterns):
        detected_attacks.append("Directory Traversal")

    threat_level = "HIGH" if detected_attacks else "LOW"
    attack_type = ", ".join(detected_attacks) if detected_attacks else "Unknown"

    recommendations = []

    if "SSH Brute Force" in detected_attacks:
        recommendations.extend([
            "Block suspicious IP",
            "Reset affected credentials",
            "Review authentication logs",
            "Enable multi-factor authentication",
        ])

    if "Port Scan" in detected_attacks:
        recommendations.extend([
            "Review firewall rules",
            "Block scanning source IPs",
            "Check for exposed services",
        ])

    if "DDoS / Request Flooding" in detected_attacks:
        recommendations.extend([
            "Rate-limit repeated requests",
            "Block abusive source IPs",
            "Enable DDoS protection through a CDN or firewall",
            "Review web server traffic spikes",
        ])

    if "SQL Injection" in detected_attacks:
        recommendations.extend([
            "Use parameterized SQL queries",
            "Validate and sanitize user input",
            "Review web application logs",
        ])

    if "Cross-Site Scripting (XSS)" in detected_attacks:
        recommendations.extend([
            "Sanitize user-generated content",
            "Apply Content Security Policy headers",
            "Encode output before rendering HTML",
        ])

    if "Directory Traversal" in detected_attacks:
        recommendations.extend([
            "Restrict file path access",
            "Validate requested file paths",
            "Disable direct access to sensitive system files",
        ])

    recommendations = list(dict.fromkeys(recommendations))

    return {
        "threat_level": threat_level,
        "attack_type": attack_type,
        "detected_attacks": detected_attacks,
        "recommendations": recommendations,
    }