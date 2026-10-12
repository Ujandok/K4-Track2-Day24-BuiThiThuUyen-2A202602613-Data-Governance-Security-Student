"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
# SĐT: 0 + 9 chữ số, cho phép dấu cách/chấm/gạch ngang giữa các nhóm.
_PHONE_RE = re.compile(r"(?<![\d-])0\d{2,3}[ .-]?\d{3}[ .-]?\d{3,4}(?![\d-])")
_DIGITS_RE = re.compile(r"(?<![\d@.\w-])\d{8,16}(?![\d@\w-])")

# Ngữ cảnh ngay trước dãy số quyết định CCCD hay STK (cùng là dãy số dài).
_CCCD_CTX = re.compile(r"(cccd|cmnd|căn cước|can cuoc)\W{0,12}$", re.IGNORECASE)
_BANK_CTX = re.compile(r"(stk|tài khoản|tai khoan|tk|account)\W{0,12}$", re.IGNORECASE)
_PHONE_CTX = re.compile(r"(sđt|sdt|điện thoại|dien thoai|phone|hotline)\W{0,12}$", re.IGNORECASE)


def _overlaps(start: int, end: int, taken: list[tuple[int, int]]) -> bool:
    return any(start < e and s < end for s, e in taken)


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    taken: list[tuple[int, int]] = []

    def add(kind: str, start: int, end: int) -> None:
        entities.append({"type": kind, "start": start, "end": end})
        taken.append((start, end))

    for m in _EMAIL_RE.finditer(text):
        add("EMAIL", m.start(), m.end())

    for m in _DIGITS_RE.finditer(text):
        if _overlaps(m.start(), m.end(), taken):
            continue
        before = text[max(0, m.start() - 30) : m.start()]
        digits = m.group()
        if _CCCD_CTX.search(before):
            kind = "VN_CCCD"
        elif _BANK_CTX.search(before):
            kind = "VN_BANK_ACCOUNT"
        elif _PHONE_CTX.search(before) or (len(digits) == 10 and digits[0] == "0"):
            kind = "VN_PHONE"
        elif len(digits) == 12:
            kind = "VN_CCCD"
        else:
            kind = "VN_BANK_ACCOUNT"
        add(kind, m.start(), m.end())

    # SĐT có dấu phân cách (0912 345 678, 091-234-5678)
    for m in _PHONE_RE.finditer(text):
        if not _overlaps(m.start(), m.end(), taken):
            add("VN_PHONE", m.start(), m.end())

    return sorted(entities, key=lambda e: e["start"])


def redact(text: str) -> str:
    for e in sorted(detect(text), key=lambda e: e["start"], reverse=True):
        text = text[: e["start"]] + f"[REDACTED_{e['type']}]" + text[e["end"] :]
    return text
