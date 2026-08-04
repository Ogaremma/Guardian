from urllib.parse import quote, urlparse
import re
import urllib.request

from fastapi import FastAPI, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from app.database import (
    create_user,
    email_exists,
    get_all_attacks,
    get_last_attack,
    get_recent_attacks_by_username,
    get_total_attacks,
    get_user_by_token,
    get_user_by_username,
    save_attack,
    username_exists,
    verify_user,
)
from app.detector import inspect_agent_report, inspect_request
from app.incident import handle_incident
from app.logger import log_attack

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
templates = Jinja2Templates(directory="templates")


def fetch_html_content(url: str) -> str | None:
    try:
        request_obj = urllib.request.Request(
            url,
            headers={"User-Agent": "GuardianScanner/1.0"}
        )
        with urllib.request.urlopen(request_obj, timeout=15) as response:
            content_type = response.info().get("Content-Type", "")
            body = response.read()

        if "text/html" not in content_type.lower():
            return ""

        return body.decode("utf-8", errors="ignore")
    except Exception:
        return None


@app.get("/", response_class=HTMLResponse)
def landing_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="landing.html"
    )

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, message: str | None = None, message_type: str = "info"):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "message": message,
            "message_type": message_type,
        }
    )

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, message: str | None = None, message_type: str = "info"):
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={
            "message": message,
            "message_type": message_type,
        }
    )

@app.get("/health")
def health():
    return {
        "status": "Healthy"
    }

@app.get("/about")
def about():
    return {
        "engineer": "Ogar Emma",
        "project": "Guardian",
        "purpose": "Detect suspicious activities on websites"
    }

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, message: str | None = None, message_type: str = "info"):
    username = request.cookies.get("guardian_user")
    if not username:
        return RedirectResponse(url=f"/login?message={quote('Please login first.')}&message_type=warning", status_code=303)

    user = get_user_by_username(username)
    if not user:
        return RedirectResponse(url=f"/login?message={quote('Please login first.')}&message_type=warning", status_code=303)

    total_attacks = get_total_attacks()
    last_attack = get_last_attack()
    website = user[2]
    recent_attacks = get_recent_attacks_by_username(username)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "threats_today": total_attacks,
            "last_attack": last_attack,
            "username": username,
            "website": website,
            "message": message,
            "message_type": message_type,
            "recent_attacks": recent_attacks,
        }
    )

@app.post("/scan")
def scan(request: Request, scan_url: str = Form(...)):
    username = request.cookies.get("guardian_user")
    if not username:
        return RedirectResponse(url=f"/login?message={quote('Please login first.')}&message_type=warning", status_code=303)

    user = get_user_by_username(username)
    if not user:
        return RedirectResponse(url=f"/login?message={quote('Please login first.')}&message_type=warning", status_code=303)

    if not scan_url:
        scan_url = user[2]

    if not scan_url.startswith(("http://", "https://")):
        scan_url = f"http://{scan_url}"

    html_content = fetch_html_content(scan_url)
    if html_content is None:
        message = quote("External scan failed: unable to retrieve the site.")
        return RedirectResponse(url=f"/dashboard?message={message}&message_type=danger", status_code=303)

    title_match = re.search(r"<title>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1).strip() if title_match else ""
    search = urlparse(scan_url).query

    result = inspect_agent_report(scan_url, title, search, request.client.host)
    if not result["safe"]:
        username_val, email, website, _, _ = user
        log_attack(username_val, result["reason"], request.client.host)
        save_attack(
            website=website,
            attack_type=result["reason"],
            severity=result["severity"],
            source_ip=request.client.host,
            username=username_val
        )
        message = quote(f"External scan found suspicious content: {result['reason']}")
        message_type = "danger"
    else:
        message = quote("External scan completed. No suspicious content found.")
        message_type = "success"

    return RedirectResponse(url=f"/dashboard?message={message}&message_type={message_type}", status_code=303)

@app.get("/logs", response_class=HTMLResponse)
def logs(request: Request):
    username = request.cookies.get("guardian_user")
    if not username:
        return RedirectResponse(url=f"/login?message={quote('Please login first.')}&message_type=warning", status_code=303)

    attacks = get_all_attacks()

    return templates.TemplateResponse(
        request=request,
        name="logs.html",
        context={
            "attacks": attacks
        }
    )

@app.get("/logout")
def logout(request: Request):
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("guardian_user")
    return response

@app.post("/register")
def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    website: str = Form(...),
    password: str = Form(...),
):
    client_ip = request.client.host
    print("Register attempt from", client_ip)

    if not username or not email or not website or not password:
        message = quote("Please fill in all registration fields.")
        return RedirectResponse(url=f"/register?message={message}&message_type=danger", status_code=303)

    if username_exists(username):
        message = quote("Username already exists.")
        return RedirectResponse(url=f"/register?message={message}&message_type=danger", status_code=303)

    if email_exists(email):
        message = quote("Email is already registered.")
        return RedirectResponse(url=f"/register?message={message}&message_type=danger", status_code=303)

    result = inspect_request(username, password, client_ip)
    if not result["safe"]:
        handle_incident(
            website=website,
            attack_type=result["reason"],
            severity=result["severity"],
            source_ip=client_ip,
            username=username,
            recipient_email=email,
        )
        message = quote("Registration appears suspicious and was blocked.")
        return RedirectResponse(url=f"/register?message={message}&message_type=danger", status_code=303)

    create_user(username, email, website, password)
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie("guardian_user", username, httponly=True)
    return response

@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    client_ip = request.client.host

    print("Client IP:", client_ip)
    print("Username:", username)

    result = inspect_request(
        username,
        password,
        client_ip,
    )

    if not result["safe"]:
        handle_incident(
            website="Local Guardian",
            attack_type=result["reason"],
            severity=result["severity"],
            source_ip=client_ip,
            username=username,
            recipient_email="emmawills725@gmail.com",
        )
        message = quote("Suspicious login attempt detected.")
        return RedirectResponse(url=f"/login?message={message}&message_type=danger", status_code=303)

    if not verify_user(username, password):
        message = quote("Invalid username or password.")
        return RedirectResponse(url=f"/login?message={message}&message_type=danger", status_code=303)

    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie("guardian_user", username, httponly=True)
    return response

@app.post("/agent/report")
async def agent_report(request: Request):
    payload = await request.json()
    site_token = payload.get("site_token")
    url = payload.get("url", "")
    title = payload.get("title", "")
    search = payload.get("search", "")
    client_ip = request.client.host

    user = get_user_by_token(site_token)
    if not user:
        return JSONResponse({"error": "Invalid site token."}, status_code=400)

    username, email, website, _, _ = user
    result = inspect_agent_report(url, title, search, client_ip)
    if not result["safe"]:
        log_attack(username, result["reason"], client_ip)
        save_attack(
            website=website,
            attack_type=result["reason"],
            severity=result["severity"],
            source_ip=client_ip,
            username=username
        )

    return JSONResponse({"safe": result["safe"], "reason": result["reason"]})

