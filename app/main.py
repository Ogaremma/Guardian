from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.detector import inspect_request
from app.incident import handle_incident
from fastapi.responses import RedirectResponse
from app.database import (
    get_total_attacks,
    get_last_attack,
    get_all_attacks
)

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse) 
def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html"
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

    total_attacks = get_total_attacks()
    last_attack = get_last_attack()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "threats_today": total_attacks,
            "last_attack": last_attack
        }
    )

@app.get("/logs", response_class=HTMLResponse)
def logs(request: Request):

    attacks = get_all_attacks()

    return templates.TemplateResponse(
        request=request,
        name="logs.html",
        context={
            "attacks": attacks
        }
    )

@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    client_ip = request.client.host

    print("Client IP:", client_ip)
    print("Username:", username)
    print("Password:", password)

    result = inspect_request(
        username, 
        password,
        client_ip
    )

    if not result["safe"]:
        handle_incident(
            website="Local Guardian",
            attack_type=result["reason"],
            severity=result["severity"],
            source_ip=client_ip,
            username=username,
            recipient_email="emmawills725@gmail.com"
        )

    return RedirectResponse(
    url="/dashboard",
    status_code=303
)

