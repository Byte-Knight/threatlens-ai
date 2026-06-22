from fastapi import FastAPI, UploadFile, File

from app.services.log_parser import parse_log
from app.services.threat_detector import detect_threats
from app.services.report_generator import generate_incident_report


app = FastAPI(
    title="ThreatLens AI API",
    description="Backend API for analyzing cybersecurity logs.",
    version="0.1.0",
)


def analyze_log(log_text: str):
    parsed_log = parse_log(log_text)
    threat_result = detect_threats(parsed_log)
    incident_report = generate_incident_report(parsed_log, threat_result)

    return {
        **threat_result,
        "failed_logins": parsed_log["failed_logins"],
        "successful_logins": parsed_log["successful_logins"],
        "port_scan_attempts": parsed_log["port_scan_attempts"],
        "suspicious_ips": parsed_log["suspicious_ips"],
        "incident_report": incident_report,
    }


@app.get("/")
def root():
    return {"message": "ThreatLens AI backend is running"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/test-analysis")
def test_analysis():
    sample_log = """
    Failed password for root from 192.168.1.10
    Failed password for root from 192.168.1.10
    Failed password for root from 192.168.1.10
    Accepted password for root from 192.168.1.10
    """

    return analyze_log(sample_log)


@app.post("/upload-log")
async def upload_log(file: UploadFile = File(...)):
    contents = await file.read()
    log_text = contents.decode("utf-8")

    analysis = analyze_log(log_text)

    return {
        "filename": file.filename,
        "analysis": analysis,
    }