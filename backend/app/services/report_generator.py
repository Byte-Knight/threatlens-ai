def generate_incident_report(parsed_log: dict, threat_result: dict):
    suspicious_ips = parsed_log["suspicious_ips"]
    detected_attacks = threat_result["detected_attacks"]

    return {
        "title": f"{threat_result['attack_type']} Detected",
        "summary": (
            f"ThreatLens detected the following attack pattern(s): "
            f"{threat_result['attack_type']}. "
            f"Failed logins: {parsed_log['failed_logins']}. "
            f"Successful logins: {parsed_log['successful_logins']}. "
            f"Suspicious source IPs: {', '.join(suspicious_ips) if suspicious_ips else 'None detected'}."
        ),
        "severity": threat_result["threat_level"],
        "evidence": [
            f"Detected attacks: {', '.join(detected_attacks) if detected_attacks else 'None'}",
            f"{parsed_log['failed_logins']} failed login attempts",
            f"{parsed_log['successful_logins']} successful login attempts",
            f"{parsed_log['port_scan_attempts']} connection attempts",
            f"Suspicious IPs: {', '.join(suspicious_ips) if suspicious_ips else 'None detected'}",
        ],
        "recommended_actions": threat_result["recommendations"],
    }