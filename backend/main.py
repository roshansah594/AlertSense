
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.routes import router

app = FastAPI(
    title="AlertSense API",
    description="Alert Storm Correlation and Root Cause Analysis Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")

@app.get("/")
def home():
    return {
        "project": "AlertSense",
        "status": "Running",
        "message": "AlertSense Backend API is working"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}
