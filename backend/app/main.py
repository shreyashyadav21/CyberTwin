from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from backend.app.models.database import Base, engine, SessionLocal
from backend.app.services.network_service import seed_sample_networks_if_empty
from backend.app.api import (
    auth,
    networks,
    assessment,
    simulations,
    threats,
    incidents,
    controls,
    reports
)

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_sample_networks_if_empty(db)
    finally:
        db.close()
    yield

app = FastAPI(
    title="CyberTwin – Intelligent Cybersecurity Digital Twin & Attack Simulation Platform",
    description="Full-stack cybersecurity digital twin for network modeling, risk assessment, attack simulations, threat detection, and incident response.",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(networks.router)
app.include_router(assessment.router)
app.include_router(simulations.router)
app.include_router(threats.router)
app.include_router(incidents.router)
app.include_router(controls.router)
app.include_router(reports.router)

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "CyberTwin Digital Twin & Simulation Platform",
        "mode": "Simulated",
        "version": "1.0.0",
        "disclaimer": "All network nodes, simulated cyberattacks, and threat detection events execute solely in a virtual digital twin environment without sending packets to external physical hosts."
    }

@app.get("/")
def root():
    return {
        "message": "CyberTwin API Operational",
        "docs": "/docs",
        "health": "/api/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)

