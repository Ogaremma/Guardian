from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {
        "application": "Guardian",
        "version": "1.0",
        "status": "Running",
        "message": "Guardian Security Monitoring System"
    }

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

