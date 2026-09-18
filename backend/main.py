from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.scanner.url_analyzer import analyze_url
from backend.scanner.scoring import calculate_risk
from backend.scanner.dns_analyzer import analyze_dns
from backend.scanner.ssl_analyzer import analyze_ssl
from backend.scanner.redirect_analyzer import analyze_redirects
from backend.scanner.threat_intel import check_virustotal
from backend.scanner.url_security import validate_url_for_request

app = FastAPI(title="LinkTrust API")

app.add_middleware(
	CORSMiddleware,
	allow_origins=[
		"http://localhost:5500",
		"http://127.0.0.1:5500",
		"https://mmiro04.github.io"
	],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)

class URLRequest(BaseModel):
	url:str


@app.get("/")
def home():
	return {
		"message": "LinkTrust API is running"
	}

@app.post("/scan")
def scan_url(request: URLRequest):

    analysis = analyze_url(request.url)

    dns = None
    ssl_info = None
    redirects = None
    threat_intel = None

    if analysis["valid"]:

        allowed, reason = validate_url_for_request(
            request.url
        )

        if not allowed:

            redirects = {
                "url": request.url,
                "final_url": None,
                "redirect_count": 0,
                "redirect_chain": [],
                "error": f"Request blocked: {reason}"
            }

        elif not analysis["is_ip"]:

            dns = analyze_dns(
                analysis["domain"]
            )

            redirects = analyze_redirects(
                request.url
            )

            threat_intel = check_virustotal(
                request.url
            )

            if analysis["https"]:

                ssl_info = analyze_ssl(
                    analysis["domain"],
                    analysis["port"] or 443
                )

    risk = calculate_risk(
        analysis,
        dns,
        ssl_info,
        redirects,
        threat_intel
    )

    return {
        "analysis": analysis,
        "dns": dns,
        "ssl": ssl_info,
        "redirects": redirects,
        "threat_intel": threat_intel,
        "risk": risk
    }
