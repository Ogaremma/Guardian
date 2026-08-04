from urllib.parse import quote

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from app.database import (
    create_user,
    email_exists,
    get_all_attacks,
    get_last_attack,
    get_total_attacks,
    username_exists,
    verify_user,
)
from app.detector import inspect_request
from app.incident import handle_incident

app = FastAPI()
templates = Jinja2Templates(directory="templates")

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
def dashboard(request: Request):
    username = request.cookies.get("guardian_user")
    if not username:
        return RedirectResponse(url=f"/login?message={quote('Please login first.')}&message_type=warning", status_code=303)

    total_attacks = get_total_attacks()
    last_attack = get_last_attack()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "threats_today": total_attacks,
            "last_attack": last_attack,
            "username": username,
        }
    )

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
    message = quote("Registration successful. Please login.")
    return RedirectResponse(url=f"/login?message={message}&message_type=success", status_code=303)

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

