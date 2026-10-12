"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
CLASSIFICATIONS = ("public", "internal", "restricted")


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))


def _parse_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def check(context: PolicyContext) -> tuple[bool, str]:
    """Mọi nhánh trả về đều có reason không rỗng. Thứ tự: dữ liệu -> egress ->
    danh tính -> tool/scope -> mục đích -> thời hạn; chỉ allow khi qua hết."""
    c = context
    if c.data_classification not in CLASSIFICATIONS:
        return False, f"deny: data_classification không hợp lệ ({c.data_classification!r})"

    if c.data_classification == "restricted" and c.egress_enabled:
        return False, "deny: dữ liệu restricted không được đi cùng egress (kể cả principal đủ quyền)"

    principal = _load_principals().get(c.principal_id)
    if principal is None:
        return False, f"deny: principal không xác định ({c.principal_id!r})"

    tool = c.requested_tool
    if not tool:
        return False, "deny: thiếu requested_tool"
    if tool not in principal["allowed_tools"]:
        return False, f"deny: principal {c.principal_id} không được dùng tool {tool}"
    if tool not in c.agent_scopes:
        return False, f"deny: tool {tool} nằm ngoài agent_scopes"
    if c.delegation_depth > 0 and tool not in c.parent_scopes:
        return False, f"deny: agent con vượt parent_scopes với tool {tool}"

    if c.request_purpose not in principal["purposes"]:
        return False, f"deny: mục đích {c.request_purpose!r} không được phép cho {c.principal_id}"

    expires = _parse_utc(c.expires_at)
    if expires is None:
        return False, "deny: expires_at thiếu hoặc sai định dạng"
    if expires <= datetime.now(timezone.utc):
        return False, f"deny: phiên đã hết hạn ({c.expires_at})"

    return True, (f"allow: {c.principal_id} dùng {tool} cho {c.request_purpose} "
                  f"(classification={c.data_classification}, depth={c.delegation_depth})")
