from io import BytesIO

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app.services.log_parser import parse_log
from app.services.threat_detector import detect_threats
from app.services.report_generator import generate_incident_report

from app.database import Base, engine, SessionLocal
from app.models.report import Report


app = FastAPI(
    title="ThreatLens AI API",
    description="Backend API for analyzing cybersecurity logs.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)


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

    db = SessionLocal()

    report = Report(
        filename=file.filename,
        threat_level=analysis["threat_level"],
        attack_type=analysis["attack_type"],
        summary=analysis["incident_report"]["summary"],
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    report_id = report.id

    db.close()

    return {
        "filename": file.filename,
        "report_id": report_id,
        "analysis": analysis,
    }


@app.get("/reports")
def get_reports():
    db = SessionLocal()

    reports = (
        db.query(Report)
        .order_by(Report.created_at.desc())
        .all()
    )

    db.close()

    return reports


@app.get("/reports/{report_id}")
def get_report(report_id: int):
    db = SessionLocal()

    report = (
        db.query(Report)
        .filter(Report.id == report_id)
        .first()
    )

    db.close()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return report


@app.get("/reports/{report_id}/pdf")
def download_report_pdf(report_id: int):
    db = SessionLocal()

    report = (
        db.query(Report)
        .filter(Report.id == report_id)
        .first()
    )

    db.close()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)

    width, height = letter
    y = height - 60

    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(50, y, "ThreatLens AI")
    y -= 30

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "Cybersecurity Incident Report")
    y -= 40

    pdf.setFont("Helvetica", 11)
    pdf.drawString(50, y, f"Report ID: #{report.id}")
    y -= 22

    pdf.drawString(50, y, f"Filename: {report.filename}")
    y -= 22

    pdf.drawString(50, y, f"Threat Level: {report.threat_level}")
    y -= 22

    pdf.drawString(50, y, f"Created At: {report.created_at}")
    y -= 35

    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(50, y, "Attack Type")
    y -= 20

    pdf.setFont("Helvetica", 11)
    text = pdf.beginText(50, y)
    text.setLeading(16)

    for line in report.attack_type.split(", "):
        text.textLine(f"- {line}")

    pdf.drawText(text)
    y -= 100

    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(50, y, "Summary")
    y -= 20

    pdf.setFont("Helvetica", 11)
    text = pdf.beginText(50, y)
    text.setLeading(16)

    words = report.summary.split()
    line = ""

    for word in words:
        if len(line + word) < 85:
            line += word + " "
        else:
            text.textLine(line)
            line = word + " "

    if line:
        text.textLine(line)

    pdf.drawText(text)

    pdf.showPage()
    pdf.save()

    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=threatlens_report_{report.id}.pdf"
        },
    )


@app.delete("/reports/{report_id}")
def delete_report(report_id: int):
    db = SessionLocal()

    report = (
        db.query(Report)
        .filter(Report.id == report_id)
        .first()
    )

    if not report:
        db.close()
        raise HTTPException(status_code=404, detail="Report not found")

    db.delete(report)
    db.commit()
    db.close()

    return {"message": "Report deleted successfully"}