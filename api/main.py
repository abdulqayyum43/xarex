"""Xarex Platform — unified FastAPI entry point for all three AI agents."""
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import scans, support, sdr, admin
from core.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Xarex AI Agents Platform",
    description=(
        "Three production-ready AI agents: autonomous penetration testing, "
        "customer support automation, and B2B sales outreach."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(support.router)
app.include_router(sdr.router)
app.include_router(admin.router)


@app.get("/health")
def health():
    return {"status": "ok", "agents": ["security", "support", "sdr"]}


@app.get("/")
def root():
    return {
        "product": "Xarex AI Agents Platform",
        "docs": "/docs",
        "agents": {
            "security": "Autonomous penetration testing and vulnerability assessment",
            "support": "Customer support automation with RAG knowledge base",
            "sdr": "B2B sales outreach sequence generation",
        },
    }
