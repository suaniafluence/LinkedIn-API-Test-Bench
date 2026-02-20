"""LinkedIn OAuth2 and API helper client."""

from __future__ import annotations

import base64
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

load_dotenv()

AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
DEFAULT_TIMEOUT = 15.0
STATE_TTL_SECONDS = 600


@dataclass
class LinkedInConfig:
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: list[str]

    @classmethod
    def from_env(cls) -> "LinkedInConfig":
        scopes = os.getenv("LINKEDIN_SCOPES", "r_liteprofile r_emailaddress").split()
        return cls(
            client_id=os.getenv("LINKEDIN_CLIENT_ID", ""),
            client_secret=os.getenv("LINKEDIN_CLIENT_SECRET", ""),
            redirect_uri=os.getenv("LINKEDIN_REDIRECT_URI", "http://localhost:8000/auth/callback"),
            scopes=scopes,
        )

    @property
    def is_valid(self) -> bool:
        return bool(self.client_id and self.client_secret and self.redirect_uri)


class TokenStore:
    """Store token in local file; encrypted when TOKEN_ENCRYPTION_KEY is set."""

    def __init__(self, path: str = "token_store.json") -> None:
        self.path = Path(path)
        self.encryption_key = os.getenv("TOKEN_ENCRYPTION_KEY", "").strip()

    @property
    def is_encrypted(self) -> bool:
        return bool(self.encryption_key)

    def _get_fernet(self) -> Fernet:
        return Fernet(self.encryption_key.encode())

    def save(self, token_payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.is_encrypted:
            fernet = self._get_fernet()
            serialized = json.dumps(token_payload).encode("utf-8")
            encrypted = fernet.encrypt(serialized)
            wrapped = {
                "encrypted": True,
                "value": base64.urlsafe_b64encode(encrypted).decode("utf-8"),
            }
            self.path.write_text(json.dumps(wrapped, indent=2), encoding="utf-8")
            return

        wrapped = {
            "encrypted": False,
            "warning": "Token is stored in plaintext JSON. Set TOKEN_ENCRYPTION_KEY to encrypt.",
            "value": token_payload,
        }
        self.path.write_text(json.dumps(wrapped, indent=2), encoding="utf-8")

    def load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        wrapped = json.loads(self.path.read_text(encoding="utf-8"))
        if wrapped.get("encrypted"):
            if not self.is_encrypted:
                raise RuntimeError(
                    "Token file is encrypted but TOKEN_ENCRYPTION_KEY is missing."
                )
            try:
                encrypted = base64.urlsafe_b64decode(wrapped["value"].encode("utf-8"))
                decrypted = self._get_fernet().decrypt(encrypted)
                return json.loads(decrypted)
            except (InvalidToken, KeyError, json.JSONDecodeError) as exc:
                raise RuntimeError("Unable to decrypt token store.") from exc

        return wrapped.get("value")


class StateStore:
    def __init__(self) -> None:
        self._states: dict[str, float] = {}

    def issue_state(self) -> str:
        state = uuid.uuid4().hex
        self._states[state] = time.time()
        return state

    def validate_state(self, state: str) -> bool:
        issued_at = self._states.pop(state, None)
        if issued_at is None:
            return False
        return (time.time() - issued_at) <= STATE_TTL_SECONDS


class LinkedInOAuthClient:
    def __init__(self, config: LinkedInConfig) -> None:
        self.config = config

    def build_authorization_url(self, state: str) -> str:
        scope_str = "%20".join(self.config.scopes)
        return (
            f"{AUTH_URL}?response_type=code"
            f"&client_id={self.config.client_id}"
            f"&redirect_uri={self.config.redirect_uri}"
            f"&state={state}&scope={scope_str}"
        )

    def exchange_code_for_token(self, code: str) -> dict[str, Any]:
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "redirect_uri": self.config.redirect_uri,
        }
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            response = client.post(TOKEN_URL, data=payload)
            response.raise_for_status()
            token_data = response.json()

        token_data["obtained_at"] = int(time.time())
        return token_data


class LinkedInApiClient:
    def __init__(self, timeout: float = DEFAULT_TIMEOUT, retries: int = 2) -> None:
        self.timeout = timeout
        self.retries = retries

    def request(
        self,
        method: str,
        url: str,
        access_token: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        prepared_headers = {
            "Authorization": f"Bearer {access_token}",
            "X-Restli-Protocol-Version": "2.0.0",
            "Accept": "application/json",
        }
        if headers:
            prepared_headers.update(headers)

        attempts = 0
        last_error: str | None = None
        while attempts <= self.retries:
            attempts += 1
            started_at = time.perf_counter()
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.request(
                        method=method.upper(),
                        url=url,
                        headers=prepared_headers,
                        params=params,
                        json=json_body,
                    )
                elapsed_ms = round((time.perf_counter() - started_at) * 1000, 2)
                return self._build_response_payload(response, elapsed_ms)
            except httpx.TimeoutException:
                last_error = "timeout"
            except httpx.RequestError as exc:
                last_error = f"request_error: {exc}"

            if attempts <= self.retries:
                time.sleep(0.5 * attempts)

        return {
            "status_code": None,
            "error": last_error or "unknown_error",
            "latency_ms": None,
            "body": None,
            "response_size_bytes": None,
            "headers": {},
            "suggestion": "Check network connectivity and endpoint URL.",
        }

    def _build_response_payload(self, response: httpx.Response, elapsed_ms: float) -> dict[str, Any]:
        relevant_headers = {
            "x-li-request-id": response.headers.get("x-li-request-id"),
            "x-restli-id": response.headers.get("x-restli-id"),
            "x-ratelimit-limit": response.headers.get("x-ratelimit-limit"),
            "x-ratelimit-remaining": response.headers.get("x-ratelimit-remaining"),
            "retry-after": response.headers.get("retry-after"),
        }

        try:
            body: Any = response.json()
        except json.JSONDecodeError:
            body = response.text

        payload: dict[str, Any] = {
            "status_code": response.status_code,
            "latency_ms": elapsed_ms,
            "response_size_bytes": len(response.content),
            "headers": {k: v for k, v in relevant_headers.items() if v is not None},
            "body": body,
            "error": None,
            "suggestion": None,
        }

        if response.status_code == 401:
            payload["error"] = "unauthorized"
            payload["suggestion"] = "Access token is missing, expired, or invalid."
        elif response.status_code == 403:
            payload["error"] = "forbidden"
            payload["suggestion"] = "Scope manquant ou accès produit non approuvé."
        elif response.status_code == 404:
            payload["error"] = "not_found"
            payload["suggestion"] = "Endpoint URL may be incorrect or unavailable."
        elif response.status_code == 429:
            payload["error"] = "rate_limited"
            payload["suggestion"] = "Rate limit reached. Retry later and inspect retry-after."
        elif response.is_error:
            payload["error"] = "http_error"
            payload["suggestion"] = "Unexpected HTTP error. Inspect response body for details."

        return payload


def mask_token(token: str | None) -> str:
    if not token:
        return "<none>"
    if len(token) <= 8:
        return "***"
    return f"{token[:4]}...{token[-4:]}"
