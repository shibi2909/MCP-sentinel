"""FastAPI application entry point.

Start (from the backend folder):  uvicorn app.main:app --reload --port 8000
API docs:                          http://localhost:8000/docs
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import CORS_ORIGINS
from app.ml.model import get_classifier
from app.routers import auth, dashboard, demo, gateway, security_admin
from app.seed import init_database


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_database()
    get_classifier()  # load (or train on first start) the ML model before serving traffic
    yield


app = FastAPI(
    title="MCP-Sentinel",
    description="MCP: A Control-Theoretic Orchestration Framework - security gateway for Model Context Protocol tool calls",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

for router in (auth.router, gateway.router, dashboard.router, security_admin.router, demo.router):
    app.include_router(router)


@app.get("/api/health", tags=["health"])
def health():
    return {"status": "ok", "service": "mcp-sentinel"}
