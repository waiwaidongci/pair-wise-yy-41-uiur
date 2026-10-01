from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, Tuple
from urllib.parse import urlparse

from .domain import (ConflictError, DomainError, NotFoundError, PermissionDenied,
                     ValidationError)
from .service import Service


def make_handler(service: Service, static_dir: str):
    root = Path(static_dir)

    class Handler(BaseHTTPRequestHandler):
        server_version = "BridgeRestrictionChain/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, path: Path) -> None:
            if not path.exists():
                self._json(404, {"error": "not_found"})
                return
            body = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _identity(self) -> Tuple[str, str]:
            return self.headers.get("X-Actor", ""), self.headers.get("X-Role", "")

        def _body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0:
                return {}
            if length > 2_000_000:
                raise ValidationError("请求体过大")
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError("请求体不是有效JSON") from exc
            if not isinstance(value, dict):
                raise ValidationError("请求体必须是JSON对象")
            return value

        def _send_error(self, exc: Exception) -> None:
            if isinstance(exc, ValidationError):
                status = 422
            elif isinstance(exc, NotFoundError):
                status = 404
            elif isinstance(exc, PermissionDenied):
                status = 403
            elif isinstance(exc, ConflictError):
                status = 409
            elif isinstance(exc, ValueError):
                status = 422
            elif isinstance(exc, DomainError):
                status = 400
            else:
                status = 500
            self._json(status, {"error": exc.__class__.__name__, "message": str(exc)})

        @staticmethod
        def _parts(path: str):
            return [p for p in path.split("/") if p]

        def do_GET(self) -> None:
            try:
                path = urlparse(self.path).path
                parts = self._parts(path)
                if path == "/health":
                    self._json(200, {"status": "ok"})
                elif path == "/":
                    self._html(root / "index.html")
                elif path == "/api/items":
                    actor, role = self._identity()
                    self._json(200, {"items": service.list_items(role)})
                elif len(parts) == 3 and parts[:2] == ["api", "items"]:
                    _, _, item_id = parts
                    actor, role = self._identity()
                    self._json(200, service.get_item(int(item_id), role))
                elif len(parts) == 4 and parts[:2] == ["api", "items"] \
                        and parts[3] == "records":
                    item_id = int(parts[2])
                    actor, role = self._identity()
                    self._json(200, {"records": service.list_records(item_id, role)})
                elif len(parts) == 4 and parts[:2] == ["api", "items"] \
                        and parts[3] == "recommendation":
                    item_id = int(parts[2])
                    actor, role = self._identity()
                    self._json(200, service.recommendation(item_id, role))
                elif path == "/api/recommendations":
                    actor, role = self._identity()
                    self._json(200, {"recommendations": service.list_recommendations(None, role)})
                elif path == "/api/conflicts":
                    actor, role = self._identity()
                    self._json(200, {"conflicts": service.list_conflicts(role)})
                elif path == "/api/drafts":
                    actor, role = self._identity()
                    self._json(200, {"drafts": service.list_drafts(role)})
                elif len(parts) == 3 and parts[:2] == ["api", "drafts"]:
                    actor, role = self._identity()
                    self._json(200, service.get_draft(parts[2], role))
                elif path == "/api/audit":
                    actor, role = self._identity()
                    self._json(200, {"events": service.audit(role)})
                else:
                    self._json(404, {"error": "not_found"})
            except Exception as exc:
                self._send_error(exc)

        def do_POST(self) -> None:
            try:
                path = urlparse(self.path).path
                parts = self._parts(path)
                actor, role = self._identity()
                body = self._body()
                if path == "/api/items":
                    self._json(201, service.create_item(body, actor, role))
                elif len(parts) == 4 and parts[:2] == ["api", "items"] \
                        and parts[3] == "records":
                    self._json(201, service.add_record(int(parts[2]), body, actor, role))
                elif len(parts) == 4 and parts[:2] == ["api", "items"] \
                        and parts[3] == "transition":
                    item_id = int(parts[2])
                    self._json(200, service.transition(
                        item_id, body.get("target"),
                        body.get("expected_version"), actor, role))
                elif len(parts) == 4 and parts[:2] == ["api", "items"] \
                        and parts[3] == "measurement":
                    self._json(200, service.update_measurement(
                        int(parts[2]), body, actor, role))
                elif len(parts) == 4 and parts[:2] == ["api", "items"] \
                        and parts[3] == "recommendation":
                    self._json(200, service.recommendation(int(parts[2]), role))
                elif path == "/api/cases":
                    self._json(201, service.register_case(body, actor, role))
                elif len(parts) == 4 and parts[:2] == ["api", "records"] \
                        and parts[3] == "reopen":
                    self._json(200, service.reopen_inspection(
                        int(parts[2]), body, actor, role))
                elif len(parts) == 4 and parts[:2] == ["api", "records"] \
                        and parts[3] == "expire":
                    self._json(200, service.expire_notice(
                        int(parts[2]), body, actor, role))
                elif path == "/api/drafts":
                    self._json(201, service.save_draft(body, actor, role))
                elif path == "/api/drafts/sync":
                    self._json(200, service.sync_drafts(role))
                elif len(parts) == 4 and parts[:2] == ["api", "drafts"] \
                        and parts[3] == "retry":
                    self._json(200, service.retry_draft(parts[2], role))
                elif len(parts) == 4 and parts[:2] == ["api", "conflicts"] \
                        and parts[3] == "resolve":
                    self._json(200, service.resolve_conflict(
                        int(parts[2]), body, actor, role))
                else:
                    self._json(404, {"error": "not_found"})
            except Exception as exc:
                self._send_error(exc)

    return Handler
