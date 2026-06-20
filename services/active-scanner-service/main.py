import requests
import time
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import warnings

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

app = FastAPI(title="WatchTower Active Scanner")

class ScanRequest(BaseModel):
    url: str

class Finding(BaseModel):
    title: str
    description: str
    severity: str
    passed: bool

class ScanReport(BaseModel):
    target_url: str
    scan_duration_ms: int
    security_score: int
    findings: list[Finding]

def check_headers(url: str) -> list[Finding]:
    findings = []
    try:
        response = requests.head(url, timeout=5, verify=False)
        headers = {k.lower(): v for k, v in response.headers.items()}

        # 1. Strict-Transport-Security
        if 'strict-transport-security' not in headers:
            findings.append(Finding(
                title="Missing HSTS Header",
                description="The site does not enforce HTTPS via Strict-Transport-Security.",
                severity="HIGH",
                passed=False
            ))
        else:
            findings.append(Finding(
                title="HSTS Header Present",
                description="Strict-Transport-Security is enforced.",
                severity="LOW",
                passed=True
            ))

        # 2. X-Frame-Options (Clickjacking)
        if 'x-frame-options' not in headers and 'content-security-policy' not in headers:
            findings.append(Finding(
                title="Missing Clickjacking Protection",
                description="Neither X-Frame-Options nor CSP frame-ancestors are present.",
                severity="MEDIUM",
                passed=False
            ))
        else:
            findings.append(Finding(
                title="Clickjacking Protection Present",
                description="X-Frame-Options or CSP is preventing clickjacking.",
                severity="LOW",
                passed=True
            ))

        # 3. Server Information Leak
        if 'server' in headers or 'x-powered-by' in headers:
            findings.append(Finding(
                title="Server Version Leak",
                description=f"Server header exposes backend tech: {headers.get('server', '')} {headers.get('x-powered-by', '')}",
                severity="LOW",
                passed=False
            ))
        else:
             findings.append(Finding(
                title="No Server Version Leak",
                description="Backend technology is hidden.",
                severity="LOW",
                passed=True
            ))

    except Exception as e:
        findings.append(Finding(
            title="Header Scan Failed",
            description=f"Could not connect to target: {str(e)}",
            severity="HIGH",
            passed=False
        ))
    return findings

def check_sensitive_files(url: str) -> list[Finding]:
    findings = []
    base_url = url.rstrip('/')
    
    sensitive_paths = [
        ('/.env', 'Environment Variables Exposure'),
        ('/.git/config', 'Git Repository Exposure'),
        ('/wp-login.php', 'WordPress Login Page Exposed')
    ]

    for path, desc in sensitive_paths:
        try:
            res = requests.get(base_url + path, timeout=3, verify=False, allow_redirects=False)
            if res.status_code == 200:
                findings.append(Finding(
                    title=desc,
                    description=f"Sensitive file found at {path}",
                    severity="CRITICAL",
                    passed=False
                ))
            else:
                findings.append(Finding(
                    title=f"No {desc}",
                    description=f"Path {path} is secure (Status {res.status_code}).",
                    severity="LOW",
                    passed=True
                ))
        except:
            pass

    return findings

@app.post("/api/v1/scanner/analyze", response_model=ScanReport)
def analyze_url(req: ScanRequest):
    target = req.url
    if not target.startswith("http"):
        target = "https://" + target

    parsed = urlparse(target)
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL format")

    start_time = time.time()
    
    all_findings = []
    all_findings.extend(check_headers(target))
    all_findings.extend(check_sensitive_files(target))

    duration_ms = int((time.time() - start_time) * 1000)

    # Calculate a simple 0-100 score
    score = 100
    for f in all_findings:
        if not f.passed:
            if f.severity == "CRITICAL": score -= 40
            elif f.severity == "HIGH": score -= 20
            elif f.severity == "MEDIUM": score -= 10
            elif f.severity == "LOW": score -= 5
    
    score = max(0, score)

    return ScanReport(
        target_url=target,
        scan_duration_ms=duration_ms,
        security_score=score,
        findings=all_findings
    )
