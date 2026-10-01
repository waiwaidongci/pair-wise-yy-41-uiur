from __future__ import annotations

import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .domain import ConflictError, NotFoundError


class LocalDraftStore:
    """断网时只落本地草稿；不修改中心数据。"""

    def __init__(self, path: Optional[str]):
        self.path = Path(path) if path else None
        self._lock = threading.RLock()
        self._memory: Dict[str, Dict[str, Any]] = {}
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not self.path.exists():
                self._write({'drafts': {}})

    def save(self, request_id: str, operation: str, payload: Dict[str, Any],
             actor: str, role: str) -> Dict[str, Any]:
        now = _now()
        with self._lock:
            data = self._read()
            existing = data['drafts'].get(request_id)
            if existing and existing['status'] == 'applied':
                raise ConflictError('请求编号已同步成功，不能覆盖；重试请使用原编号查询')
            draft = existing or {
                'request_id': request_id,
                'created_at': now,
                'attempts': 0,
            }
            draft.update({
                'operation': operation,
                'payload': payload,
                'actor': actor,
                'role': role,
                'status': 'pending',
                'updated_at': now,
                'last_error': None,
                'result': None,
            })
            data['drafts'][request_id] = draft
            self._write(data)
            return dict(draft)

    def get(self, request_id: str) -> Dict[str, Any]:
        with self._lock:
            draft = self._read()['drafts'].get(request_id)
        if draft is None:
            raise NotFoundError('本地草稿不存在')
        return dict(draft)

    def list_pending(self) -> List[Dict[str, Any]]:
        with self._lock:
            drafts = list(self._read()['drafts'].values())
        return [dict(d) for d in drafts
                if d.get('status') in ('pending', 'retrying', 'conflicted')]

    def mark(self, request_id: str, status: str, **changes: Any) -> Dict[str, Any]:
        with self._lock:
            data = self._read()
            draft = data['drafts'].get(request_id)
            if draft is None:
                raise NotFoundError('本地草稿不存在')
            draft['status'] = status
            draft['updated_at'] = _now()
            for key, value in changes.items():
                draft[key] = value
            data['drafts'][request_id] = draft
            self._write(data)
            return dict(draft)

    def _read(self) -> Dict[str, Any]:
        if self.path is None:
            return {'drafts': {k: dict(v) for k, v in self._memory.items()}}
        if not self.path.exists():
            return {'drafts': {}}
        with self.path.open('r', encoding='utf-8') as handle:
            data = json.load(handle)
        data.setdefault('drafts', {})
        return data

    def _write(self, data: Dict[str, Any]) -> None:
        if self.path is None:
            self._memory = {k: dict(v) for k, v in data['drafts'].items()}
            return
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.name + '.', suffix='.tmp', dir=self.path.parent
        )
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write('\n')
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
