import os, secrets, html
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import select, desc
from dotenv import load_dotenv
from database import init_db, SessionLocal
from models import SecurityEvent, License
load_dotenv()
TOKEN = os.getenv("DASHBOARD_TOKEN", "")
if len(TOKEN) < 32 or TOKEN.startswith("replace_"):
    raise RuntimeError("Set DASHBOARD_TOKEN to a random secret of at least 32 characters.")
app = FastAPI(title="AG Security Bot Admin")

def authorize(value):
    if not value or not secrets.compare_digest(value, TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.on_event("startup")
async def startup():
    await init_db()

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def home(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Send Authorization: Bearer <DASHBOARD_TOKEN>")
    authorize(authorization.removeprefix("Bearer ").strip())
    async with SessionLocal() as session:
        er = await session.execute(select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(25))
        events = er.scalars().all()
        lr = await session.execute(select(License).order_by(desc(License.created_at)).limit(25))
        licenses = lr.scalars().all()
    rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(v))}</td>" for v in
        [e.created_at.isoformat(), e.command, e.outcome, e.actor_id, e.guild_id, e.details[:160]]) + "</tr>" for e in events)
    license_rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(v))}</td>" for v in
        [l.id, l.label, "active" if l.active else "revoked", l.created_at.isoformat()]) + "</tr>" for l in licenses)
    return HTMLResponse("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
        "<title>AG Security Bot Admin</title><style>body{font:15px system-ui;max-width:1200px;margin:30px auto;padding:0 16px;background:#111827;color:#e5e7eb}"
        "table{width:100%;border-collapse:collapse;margin:14px 0 32px}td,th{border:1px solid #374151;padding:8px;text-align:left;overflow-wrap:anywhere}"
        "th{background:#1f2937}</style><h1>AG Security Bot Admin</h1><p>Latest 25 events and licenses; key secrets are never shown.</p>"
        "<h2>Security events</h2><table><tr><th>Time</th><th>Command</th><th>Outcome</th><th>Actor</th><th>Guild</th><th>Details</th></tr>"
        + rows + "</table><h2>Licenses</h2><table><tr><th>ID</th><th>Label</th><th>Status</th><th>Created</th></tr>"
        + license_rows + "</table>")

@app.get("/events")
async def events(authorization: str | None = Header(default=None), limit: int = 25):
    authorize(authorization.removeprefix("Bearer ").strip() if authorization else None)
    async with SessionLocal() as session:
        result = await session.execute(select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(max(1, min(limit, 100))))
        return [{"created_at": e.created_at.isoformat(), "command": e.command, "outcome": e.outcome,
                 "actor_id": e.actor_id, "guild_id": e.guild_id, "details": e.details} for e in result.scalars()]

@app.get("/licenses")
async def licenses(authorization: str | None = Header(default=None)):
    authorize(authorization.removeprefix("Bearer ").strip() if authorization else None)
    async with SessionLocal() as session:
        result = await session.execute(select(License).order_by(desc(License.created_at)))
        return [{"id": l.id, "label": l.label, "active": l.active, "created_at": l.created_at.isoformat()}
                for l in result.scalars()]
