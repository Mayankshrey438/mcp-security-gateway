from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import jwt
from fastapi import HTTPException, Request, status

from gateway.models import Principal
from gateway.settings import Settings


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


class IdentityVerifier:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def verify_http(self, request: Request) -> Principal:
        if self.settings.dev_identity:
            agent_id = request.headers.get("X-Agent-ID")
            if not agent_id:
                raise HTTPException(status_code=401, detail="X-Agent-ID is required in dev mode")
            scopes = frozenset(request.headers.get("X-Agent-Scopes", "").split())
            return Principal(id=agent_id, scopes=scopes)

        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Bearer token required")
        if not self.settings.jwt_public_key:
            raise HTTPException(status_code=503, detail="JWT verification is not configured")
        token = authorization.removeprefix("Bearer ").strip()
        try:
            claims = jwt.decode(
                token,
                self.settings.jwt_public_key,
                algorithms=[self.settings.jwt_algorithm],
                issuer=self.settings.jwt_issuer,
                audience=self.settings.jwt_audience,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail="Invalid access token") from exc
        raw_scopes = claims.get("scope", "")
        scopes = frozenset(raw_scopes.split() if isinstance(raw_scopes, str) else raw_scopes)
        return Principal(
            id=str(claims["sub"]),
            tenant_id=str(claims.get("tenant_id", "default")),
            scopes=scopes,
            claims=claims,
        )

    def require_admin(self, request: Request) -> Principal:
        principal = self.verify_http(request)
        if self.settings.admin_scope not in principal.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin scope required",
            )
        return principal


def secure_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())
