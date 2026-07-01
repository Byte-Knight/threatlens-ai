import re


def parse_log(log_text: str):
    failed_logins = len(re.findall(r"Failed password", log_text))
    successful_logins = len(re.findall(r"Accepted password", log_text))

    ips = re.findall(r"from (\d+\.\d+\.\d+\.\d+)", log_text)

    connection_ips = re.findall(
        r"Connection attempt from (\d+\.\d+\.\d+\.\d+)",
        log_text
    )

    request_ips = re.findall(
        r"Connection request from (\d+\.\d+\.\d+\.\d+)",
        log_text
    )

    unique_ips = list(set(ips + connection_ips + request_ips))

    port_scan_attempts = len(
        re.findall(r"Connection attempt", log_text)
    )

    request_count = len(
        re.findall(r"Connection request", log_text)
    )

    return {
        "log_text": log_text,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "port_scan_attempts": port_scan_attempts,
        "request_count": request_count,
        "suspicious_ips": unique_ips,
    }