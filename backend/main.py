from fastapi import FastAPI
from pydantic import BaseModel

from backend.scanner.url_analyzer import analyze_url
from backend.scanner.scoring import calculate_risk
from backend.scanner.dns_analyzer import analyze_dns

app = FastAPI(title="LinkTrust API")

class URLRequest(BaseModel):
	url:str


@app.get("/")
def home():
	return {
		"message": "LinkTrust API is running"
	}

@app.post("/scan")
def scan_url(request: URLRequest):

	analysis  = analyze_url(request.url)

	dns = None

	if analysis["valid"] and not analysis["is_ip"]:
		dns = analyze_dns(analysis["domain"])

	risk = calculate_risk(analysis)

	return  {
		"analysis": analysis,
		"dns": dns,
		"risk": risk
	}


