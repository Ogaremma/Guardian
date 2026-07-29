from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.detector import inspect_request
from app.logger import log_attack

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

@app.post("/login")
def login(
    username: str = Form(...),
    password: str = Form(...)
):
    client_ip = request.client.host

    print("Client IP:", client_ip)
    print("Username:", username)
    print("Password:", password)

    result = inspect_request(username, password)

    if not result["safe"]:
        log_attack(username, result["reason"])

    return result

