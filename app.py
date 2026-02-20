"""FastAPI application for LinkedIn API Test Bench."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

from linkedin_client import (
    LinkedInApiClient,
    LinkedInConfig,
    LinkedInOAuthClient,
    StateStore,
    TokenStore,
    mask_token,
)

app = FastAPI(title="LinkedIn API Test Bench")

BASE_DIR = Path(__file__).parent
ENDPOINTS_PATH = BASE_DIR / "endpoints.json"
REPORTS_DIR = BASE_DIR / "reports"

config = LinkedInConfig.from_env()
oauth_client = LinkedInOAuthClient(config)
state_store = StateStore()
token_store = TokenStore(path=str(BASE_DIR / "token_store.json"))
api_client = LinkedInApiClient()


class RunRequest(BaseModel):
    names: list[str] | None = None
    all: bool = False


def load_endpoints() -> list[dict[str, Any]]:
    if not ENDPOINTS_PATH.exists():
        return []
    raw = json.loads(ENDPOINTS_PATH.read_text(encoding="utf-8"))
    return raw.get("endpoints", [])


def save_report(report: dict[str, Any]) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = REPORTS_DIR / f"report_{timestamp}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def get_latest_report_path() -> Path | None:
    if not REPORTS_DIR.exists():
        return None
    reports = sorted(REPORTS_DIR.glob("report_*.json"))
    return reports[-1] if reports else None


def token_status() -> dict[str, Any]:
    try:
        token_data = token_store.load()
    except RuntimeError as exc:
        return {"available": False, "error": str(exc)}

    if not token_data:
        return {"available": False, "error": "No token saved yet."}

    expires_in = token_data.get("expires_in")
    obtained_at = token_data.get("obtained_at")
    expires_at = (obtained_at + expires_in) if expires_in and obtained_at else None

    return {
        "available": True,
        "masked_access_token": mask_token(token_data.get("access_token")),
        "expires_in": expires_in,
        "obtained_at": obtained_at,
        "expires_at": expires_at,
        "is_expired": bool(expires_at and time.time() > expires_at),
        "has_refresh_token": "refresh_token" in token_data,
        "encrypted_storage": token_store.is_encrypted,
    }


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    status = token_status()
    endpoints = load_endpoints()
    latest_report = get_latest_report_path()
    latest_link = f"/reports/{latest_report.name}" if latest_report else ""

    endpoint_items = "".join(
        f"<li><code>{ep.get('name')}</code> - {ep.get('method')} {ep.get('url')}"
        f" (enabled={ep.get('enabled', True)})</li>"
        for ep in endpoints
    )

    return f"""
    <html>
      <head><title>LinkedIn API Test Bench</title></head>
      <body>
        <h1>LinkedIn API Test Bench</h1>
        <p><a href='/auth/login'><button>Login with LinkedIn</button></a></p>
        <h2>Token Status</h2>
        <pre>{json.dumps(status, indent=2, ensure_ascii=False)}</pre>
        <h2>Endpoints</h2>
        <ul>{endpoint_items}</ul>
        <h2>Run Tests</h2>
        <p>POST <code>/run</code> with <code>{{"all": true}}</code> or <code>{{"names": ["name"]}}</code>.</p>
        <h2>Latest Report</h2>
        <p>{f"<a href='{latest_link}'>{latest_report.name}</a>" if latest_report else "No report yet."}</p>
      </body>
    </html>
    """


@app.get("/auth/login")
def auth_login() -> RedirectResponse:
    if not config.is_valid:
        raise HTTPException(status_code=500, detail="Missing LinkedIn OAuth environment variables.")

    state = state_store.issue_state()
    authorization_url = oauth_client.build_authorization_url(state)
    return RedirectResponse(url=authorization_url, status_code=302)


@app.get("/auth/callback")
def auth_callback(code: str | None = None, state: str | None = None, error: str | None = None) -> JSONResponse:
    if error:
        return JSONResponse(status_code=400, content={"error": error})
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state.")
    if not state_store.validate_state(state):
        raise HTTPException(status_code=400, detail="Invalid or expired state.")

    try:
        token_data = oauth_client.exchange_code_for_token(code)
        token_store.save(token_data)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Token exchange failed: {exc}") from exc

    return JSONResponse(
        content={
            "message": "Token received and stored.",
            "token_info": {
                "access_token": mask_token(token_data.get("access_token")),
                "expires_in": token_data.get("expires_in"),
                "has_refresh_token": "refresh_token" in token_data,
            },
        }
    )


@app.get("/auth/status")
def auth_status() -> JSONResponse:
    return JSONResponse(content=token_status())


@app.post("/run")
def run_tests(payload: RunRequest) -> JSONResponse:
    token_data = token_store.load()
    if not token_data:
        raise HTTPException(status_code=401, detail="No token available. Authenticate first.")

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Stored token has no access_token.")

    endpoints = load_endpoints()
    enabled_endpoints = [ep for ep in endpoints if ep.get("enabled", True)]

    if payload.all:
        selected = enabled_endpoints
    elif payload.names:
        names = set(payload.names)
        selected = [ep for ep in enabled_endpoints if ep.get("name") in names]
    else:
        raise HTTPException(status_code=400, detail="Provide names or all=true.")

    if not selected:
        raise HTTPException(status_code=404, detail="No matching enabled endpoints found.")

    started_at = datetime.now(timezone.utc)
    results: list[dict[str, Any]] = []
    for endpoint in selected:
        result = api_client.request(
            method=endpoint.get("method", "GET"),
            url=endpoint.get("url"),
            access_token=access_token,
            headers=endpoint.get("headers"),
            params=endpoint.get("params"),
            json_body=endpoint.get("body_template"),
        )
        result.update(
            {
                "name": endpoint.get("name"),
                "method": endpoint.get("method"),
                "url": endpoint.get("url"),
                "required_scopes": endpoint.get("required_scopes", []),
                "executed_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        results.append(result)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(results),
            "ok": sum(1 for r in results if r.get("status_code") and int(r["status_code"]) < 400),
            "errors": sum(1 for r in results if not r.get("status_code") or int(r["status_code"]) >= 400),
        },
        "results": results,
    }

    report_path = save_report(report)
    return JSONResponse(content={"report_file": str(report_path.name), "report": report})


@app.get("/reports/{report_name}")
def get_report(report_name: str) -> JSONResponse:
    path = REPORTS_DIR / report_name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found.")
    return JSONResponse(content=json.loads(path.read_text(encoding="utf-8")))
