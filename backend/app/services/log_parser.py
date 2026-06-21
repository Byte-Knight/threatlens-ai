import re

def analyze_ssh_log(log_text: str):
    failed_logins = len(
        re.findall(r"Failed password", log_text)
    )

    successful_logins = len(
        re.findall(r"Accepted password", log_text)
    )

    ips = re.findall(
        r"from (\d+\.\d+\.\d+\.\d+)",
        log_text
    )

    unique_ips = list(set(ips))

    return {
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "suspicious_ips": unique_ips,
    }