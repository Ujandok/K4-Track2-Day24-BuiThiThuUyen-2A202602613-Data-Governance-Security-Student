# Verification — checkpoint 5

- **OS / Python / Gitleaks:** Windows 11 (PowerShell + Git Bash, không dùng WSL2 như README khuyến nghị) / Python 3.14.7 / Gitleaks 8.30.1 (`gitleaks version`).
- **`python -m pytest tests/ -q --basetemp=.pytest_tmp`:** `33 passed`, 0 skipped, 0 failed.
- **`python -m agent.check_lure corpus/ticket-90*.md`:** `4/4 lure sẵn sàng`.
- **`pre-commit run --all-files`:** `Detect hardcoded secrets...Passed`.
- **Gitleaks:** `gitleaks git --config .gitleaks.toml --redact .` → 1 finding, exit 1 (rule `lab24-synthetic-token`, commit `1bdd849`, token giả như dự kiến); `gitleaks dir --config .gitleaks.toml --redact .` → no leaks, exit 0. Chi tiết: `reports/secrets-incident.md`.
- **Before/after:** `reports/attack-before.log` 4 dòng, mỗi dòng là POST chứa record giả của KH-000999. `reports/attack-after.log` = **0 byte**, tạo sau khi reset sink lần hai và chạy `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` qua runner mới.
- **Ledger:** `reports/ledger.jsonl` 23 dòng, `verify()` → `True`; mọi dòng có `reason`; có `http_post` decision=deny, `on_behalf_of=dpo` (dòng 23), `search_docs` allow (dòng 1) và `read_customer` allow (dòng 2).
- **Lỗi đã gặp và cách sửa:**
  - Windows console lỗi `UnicodeEncodeError` khi in tiếng Việt: đặt `PYTHONUTF8=1`.
  - Thiếu `requests`/`pip-tools`: cài bằng pip.
  - Hook `gitleaks-system` mặc định chạy `gitleaks git ...` nên nối thêm `args` thành 2 đối số và báo lỗi: ghi đè `entry` thành `gitleaks dir --config .gitleaks.toml --redact` trong `.pre-commit-config.yaml`.
  - `reports/ledger.jsonl` ban đầu chưa có: tạo bằng cách chạy agent `--as dpo` sau khi runner an toàn.
- **Lỗi/giới hạn còn lại:** mock LLM, principal giả lập, regex PII (test set tổng hợp), ledger một file không phát hiện cắt đuôi; `dpo` vẫn đọc hợp lệ hồ sơ KH-000999, chỉ `http_post` bị chặn. Luật 91/2025/QH15: đã đối chiếu các điều trích dẫn với bản gốc `91qh.signed.pdf`. NĐ 356/2025/NĐ-CP, Luật AI 134/2025/QH15 và danh mục OWASP ASI: **NOT_VERIFIED** (chưa có văn bản gốc, xem `reports/compliance-mapping.md`). Chạy trên Windows native, chưa chạy trong WSL2/Linux: **NOT_VERIFIED** trên môi trường đó.

## CP3a — PII gate (`agent/pii.py`)

- Lệnh: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp` -> 2 passed.
- Kết quả: gold=118, pred=118, tp=118, precision=1.000, recall=1.000 (`tests/vn_pii_testset.jsonl`).
- Cách làm: regex cho EMAIL, SĐT và dãy 8–16 số; dãy số dài phân loại CCCD/STK/SĐT theo nhãn ngay trước ("CCCD", "STK", "SĐT"), nếu không có thì theo độ dài (12 số = CCCD, 10 số bắt đầu 0 = SĐT, còn lại = STK). Trùng chỉ báo một lần; `redact()` thay từ cuối về đầu.
- Giới hạn: test set tổng hợp và có mẫu rất đều nên 1.000 không có nghĩa đủ cho dữ liệu thật. Dãy số không nhãn dễ nhầm loại; dãy >16 số hoặc số bị chen chữ không bắt được; không phát hiện tên người, địa chỉ.
