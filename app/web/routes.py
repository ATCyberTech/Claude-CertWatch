"""Web UI routes — one placeholder page at M0, real screens owned by M6."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

router = APIRouter(tags=["web"])
_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/")
def index(request: Request) -> object:
    """M0 placeholder landing page — proves the Jinja2 pipeline, nothing more."""
    return _templates.TemplateResponse(request, "index.html", {})
