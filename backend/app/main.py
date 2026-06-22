from fastapi import FastAPI, UploadFile, File
from app.services.log_parser import analyze_ssh_log

app = FastAPI(
    title="ThreatLens AI API",
    description="Backend API for analyzing cybersecurity logs.",
    version="0.1.0"
)

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

    return analyze_ssh_log(sample_log)

@app.post("/upload-log")
async def upload_log(file: UploadFile = File(...)):
    contents = await file.read()
    log_text = contents.decode("utf-8")

    analysis = analyze_ssh_log(log_text)

    return {
        "filename": file.filename,
        "analysis": analysis
    }