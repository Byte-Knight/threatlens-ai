import re


def analyze_ssh_log(log_text: str):
    failed_logins = len(re.findall(r"Failed password", log_text))
    successful_logins = len(re.findall(r"Accepted password", log_text))

    ips = re.findall(r"from (\d+\.\d+\.\d+\.\d+)", log_text)
    unique_ips = list(set(ips))

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

    port_scan_attempts = len(re.findall(r"Connection attempt", log_text))

    detected_attacks = []

    if failed_logins >= 3:
        detected_attacks.append("SSH Brute Force")

    if port_scan_attempts >= 5:
        detected_attacks.append("Port Scan")

    if any(re.search(pattern, log_text) for pattern in sql_injection_patterns):
        detected_attacks.append("SQL Injection")

    if any(re.search(pattern, log_text) for pattern in xss_patterns):
        detected_attacks.append("Cross-Site Scripting (XSS)")

    if any(re.search(pattern, log_text) for pattern in directory_traversal_patterns):
        detected_attacks.append("Directory Traversal")

    if detected_attacks:
        threat_level = "HIGH"
        attack_type = ", ".join(detected_attacks)
    else:
        threat_level = "LOW"
        attack_type = "Unknown"

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

    incident_report = {
        "title": f"{attack_type} Detected",
        "summary": (
            f"ThreatLens detected the following attack pattern(s): {attack_type}. "
            f"Failed logins: {failed_logins}. "
            f"Successful logins: {successful_logins}. "
            f"Suspicious source IPs: {', '.join(unique_ips) if unique_ips else 'None detected'}."
        ),
        "severity": threat_level,
        "evidence": [
            f"Detected attacks: {attack_type}",
            f"{failed_logins} failed login attempts",
            f"{successful_logins} successful login attempts",
            f"{port_scan_attempts} connection attempts",
            f"Suspicious IPs: {', '.join(unique_ips) if unique_ips else 'None detected'}",
        ],
        "recommended_actions": recommendations,
    }

    return {
        "threat_level": threat_level,
        "attack_type": attack_type,
        "detected_attacks": detected_attacks,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "port_scan_attempts": port_scan_attempts,
        "suspicious_ips": unique_ips,
        "recommendations": recommendations,
        "incident_report": incident_report,
    }