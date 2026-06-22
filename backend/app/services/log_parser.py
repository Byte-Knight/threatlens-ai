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

    return {
        "threat_level": threat_level,
        "attack_type": attack_type,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "suspicious_ips": unique_ips,
        "recommendations": recommendations,
    }