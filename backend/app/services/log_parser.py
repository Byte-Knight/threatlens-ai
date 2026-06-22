import re


def analyze_ssh_log(log_text: str):
    failed_logins = len(re.findall(r"Failed password", log_text))
    successful_logins = len(re.findall(r"Accepted password", log_text))

    ips = re.findall(r"from (\d+\.\d+\.\d+\.\d+)", log_text)
    unique_ips = list(set(ips))

    threat_level = "LOW"
    attack_type = "Unknown"

    if failed_logins >= 3:
        threat_level = "HIGH"
        attack_type = "SSH Brute Force"

    recommendations = []

    if threat_level == "HIGH":
        recommendations = [
            "Block suspicious IP",
            "Reset affected credentials",
            "Review authentication logs",
            "Enable multi-factor authentication",
        ]

    incident_report = {
        "title": f"{attack_type} Detected",
        "summary": (
            f"{failed_logins} failed SSH login attempts were detected. "
            f"{successful_logins} successful login attempt was also found. "
            f"Suspicious source IPs: {', '.join(unique_ips)}."
        ),
        "severity": threat_level,
        "evidence": [
            f"{failed_logins} failed login attempts",
            f"{successful_logins} successful login attempts",
            f"Suspicious IPs: {', '.join(unique_ips)}",
        ],
        "recommended_actions": recommendations,
    }

    return {
        "threat_level": threat_level,
        "attack_type": attack_type,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "suspicious_ips": unique_ips,
        "recommendations": recommendations,
        "incident_report": incident_report,
    }