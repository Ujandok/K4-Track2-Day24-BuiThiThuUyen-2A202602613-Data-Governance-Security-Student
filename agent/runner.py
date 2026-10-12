"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
SESSION_TTL = timedelta(minutes=15)
_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)[a-z]?\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


class _Gate:
    """PEP: mọi lần xin gọi tool đi qua policy.check() rồi ledger.append()
    (allow lẫn deny). Tool thật chỉ chạy khi gate trả True."""

    def __init__(self, ledger_path: Path, principal_id: str, run_id: str, expires_at: str):
        self.ledger_path = ledger_path
        self.principal_id = principal_id
        self.run_id = run_id
        self.expires_at = expires_at

    def ask(self, *, tool: str, args: dict, classification: str, purpose: str,
            agent_id: str, scopes: tuple[str, ...], egress: bool,
            depth: int = 0, parent_scopes: tuple[str, ...] = ()) -> bool:
        context = policy.PolicyContext(
            data_classification=classification,
            request_purpose=purpose,
            agent_owner=agent_id,
            delegation_depth=depth,
            egress_enabled=egress,
            principal_id=self.principal_id,
            requested_tool=tool,
            agent_scopes=scopes,
            parent_scopes=parent_scopes,
            expires_at=self.expires_at,
        )
        allow, reason = policy.check(context)
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "on_behalf_of": self.principal_id,
            "agent_id": agent_id,
            "run_id": self.run_id,
            "expires_at": self.expires_at,
            "tool": tool,
            # Chỉ băm tham số: ledger không chứa hồ sơ hay PII thô.
            "args_hash": hashlib.sha256(
                json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(),
            "classification": classification,
            "egress": egress,
            "delegation_depth": depth,
            "decision": "allow" if allow else "deny",
            "reason": reason,
        }, self.ledger_path)
        return allow


def _ticket_ids(docs: list[dict]) -> list[int]:
    """Số ticket lấy từ TÊN FILE (ticket-007.md -> 7), không từ nội dung."""
    ids = []
    for doc in docs:
        m = _TICKET_FILE_RE.match(doc["id"])
        if m:
            ids.append(int(m.group(1)))
    return sorted(set(ids))


def _run_a(gate: _Gate, message: str, llm) -> tuple[list[int], list[dict], str | None]:
    """Run A — untrusted content. Chỉ search_docs; không read_customer/http_post.
    Chỉ đưa ra ngoài: list[int] ticket id, text đã che PII, và URL đích (chỉ
    dùng để ghi nhận lượt xin gửi bị chặn, không mang dữ liệu khách)."""
    if not gate.ask(tool="search_docs", args={"query": message}, classification="internal",
                    purpose="summarize-tickets", agent_id=f"{AGENT_ID}/run-a",
                    scopes=("search_docs",), egress=False):
        return [], [], None
    docs = tools.search_docs(message)
    injected = llm.find_injection("\n\n".join(d["text"] for d in docs))
    safe_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    # customer_id mà attacker nêu trong text bị bỏ qua có chủ đích.
    return _ticket_ids(docs), safe_docs, (injected.target_url if injected else None)


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Nguồn tin cậy: related_tickets trong data/customers.json."""
    wanted = set(ticket_ids)
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return [c["customer_id"] for c in customers if wanted & set(c.get("related_tickets", []))]


def _run_b(gate: _Gate, ticket_ids: list[int], egress_url: str | None) -> int:
    """Run B — private data. Chỉ nhận list[int]; không bao giờ thấy free text."""
    agent_id = f"{AGENT_ID}/run-b"
    read = 0
    for customer_id in _customers_for_tickets(ticket_ids):
        if gate.ask(tool="read_customer", args={"customer_id": customer_id},
                    classification="restricted", purpose="support-reply",
                    agent_id=agent_id, scopes=("read_customer",), egress=False):
            tools.read_customer(customer_id)
            read += 1
    if egress_url:
        # Lure đòi gửi dữ liệu ra ngoài: dữ liệu restricted + egress luôn bị
        # policy deny, nên http_post không bao giờ được gọi.
        gate.ask(tool="http_post", args={"url": egress_url}, classification="restricted",
                 purpose="support-reply", agent_id=agent_id,
                 scopes=("read_customer", "http_post"), egress=True)
    return read


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    gate = _Gate(
        ledger_path=ledger_path,
        principal_id=principal_id,
        run_id=f"run-{uuid.uuid4().hex[:12]}",
        expires_at=(datetime.now(timezone.utc) + SESSION_TTL).isoformat(),
    )
    ticket_ids, safe_docs, egress_url = _run_a(gate, message, llm)
    _run_b(gate, ticket_ids, egress_url)
    return llm.summarize(safe_docs)
