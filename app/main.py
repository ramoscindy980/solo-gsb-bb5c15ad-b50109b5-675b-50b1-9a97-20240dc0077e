"""FastAPI surface for the JSON redaction service."""

from __future__ import annotations

import os
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .redactor import ACTIONS, RuleError, redact

SALT_ENV_VAR = "REDACT_SALT"

app = FastAPI(title="JSON Redaction API", version="1.0.0")


class RuleIn(BaseModel):
    path: str = Field(
        ...,
        description="JSON Pointer (RFC 6901) with optional '*' (one level) and '**' (any depth) wildcards",
        examples=["/users/*/password"],
    )
    action: Literal["mask", "remove", "sha256"]


class RedactRequest(BaseModel):
    data: Any = Field(None, description="Arbitrary JSON document to redact")
    rules: list[RuleIn] = Field(default_factory=list)


class AuditEntry(BaseModel):
    pointer: str = Field(..., description="JSON Pointer of the matched node in the original document")
    rule: str = Field(..., description="Path of the rule that won for this node")
    rule_index: int = Field(..., description="Declaration index of the winning rule")
    action: str
    applied: bool = Field(
        ...,
        description="False when an ancestor node was already consumed by another rule",
    )


class RedactResponse(BaseModel):
    redacted: Any = Field(None, description="The redacted document")
    audit: list[AuditEntry]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/redact", response_model=RedactResponse)
def redact_endpoint(payload: RedactRequest) -> RedactResponse:
    salt = os.environ.get(SALT_ENV_VAR, "")
    try:
        redacted, audit = redact(
            payload.data,
            [rule.model_dump() for rule in payload.rules],
            salt=salt,
        )
    except RuleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return RedactResponse(redacted=redacted, audit=audit)
