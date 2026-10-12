# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify:
- Các lỗi còn lại:

## CP3a — PII gate (`agent/pii.py`)

- Lệnh: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp` -> 2 passed.
- Kết quả: gold=118, pred=118, tp=118, precision=1.000, recall=1.000 (`tests/vn_pii_testset.jsonl`).
- Cách làm: regex cho EMAIL, SĐT và dãy 8–16 số; dãy số dài phân loại CCCD/STK/SĐT theo nhãn ngay trước ("CCCD", "STK", "SĐT"), nếu không có thì theo độ dài (12 số = CCCD, 10 số bắt đầu 0 = SĐT, còn lại = STK). Trùng chỉ báo một lần; `redact()` thay từ cuối về đầu.
- Giới hạn: test set tổng hợp và có mẫu rất đều nên 1.000 không có nghĩa đủ cho dữ liệu thật. Dãy số không nhãn dễ nhầm loại; dãy >16 số hoặc số bị chen chữ không bắt được; không phát hiện tên người, địa chỉ.
