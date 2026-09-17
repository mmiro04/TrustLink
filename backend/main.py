from fastapi import FastAPI
from pydantic import BaseModel

from backend.scanner.url_analyzer import analyze_url
from backend.scanner.scoring import calculate_risk
from backend.scanner.dns_analyzer import analyze_dns
from backend.scanner.ssl_analyzer import analyze_ssl
from backend.scanner.redirect_analyzer import analyze_redirects

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
	ssl_info = None
	redirects = None

	if analysis["valid"] and not analysis["is_ip"]:
		dns = analyze_dns(analysis["domain"])

		redirects = analyze_redirects(request.url)

		if analysis["https"]:
			ssl_info = analyze_ssl(
				analysis["domain"],
				analysis["port"] or 443
			)

	risk = calculate_risk(
		analysis,
		dns,
		ssl_info,
		redirects
	)

	return  {
		"analysis": analysis,
		"dns": dns,
		"ssl": ssl_info,
		"redirects": redirects,
		"risk": risk

	}


