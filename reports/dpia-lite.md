# DPIA-lite — checkpoint 5

Bản mô tả học tập, **không phải** hồ sơ đánh giá tác động theo quy định pháp luật.

1. **Loại dữ liệu và phân loại:** 26 hồ sơ khách tổng hợp trong `data/customers.json` (tên, CCCD, SĐT, STK, email, `related_tickets`) được coi là `restricted`; ticket trong `corpus/` (45 file) là nội dung không tin cậy, phân loại `internal`. Không có dữ liệu cá nhân thật.
2. **Mục đích xử lý và principal:** `support_l1` chỉ tìm ticket (`summarize-tickets`, `support-reply`), không được đọc hồ sơ. `dpo` được tìm ticket và đọc hồ sơ cho `support-reply` (`data/principals.json`). Principal chỉ là bản mô phỏng chọn bằng `--as`, không có xác thực.
3. **Dữ liệu đi qua đâu:** Run A (`search_docs`, che PII bằng `agent/pii.py`) → chỉ truyền danh sách số ticket lấy từ tên file → Run B (`read_customer`, tra `related_tickets`) → `http_post` tới sink `127.0.0.1:10024` luôn bị policy chặn → mọi quyết định ghi vào `reports/ledger.jsonl` (chỉ `args_hash`, không có PII thô). Điểm kiểm soát: `agent/policy.py:79-80`, `agent/runner.py:83-125`.
4. **Bằng chứng deny/allow và giới hạn:**
   - Trước khi chặn: `reports/attack-before.log` có 4 POST mang record giả của KH-000999.
   - Sau khi chặn (`--as dpo`, cùng câu hỏi): `reports/attack-after.log` rỗng (0 byte). Ledger 23 dòng, `verify()` = True; dòng 23 là `http_post` decision=deny, `on_behalf_of=dpo`, có `reason`. `dpo` vẫn đọc được hồ sơ gắn với ticket (dòng 2: `read_customer` allow).
   - Giới hạn: mock LLM nhận diện bằng marker, không đại diện model thật; principal giả lập; regex PII chỉ đạt trên test set tổng hợp (không phát hiện tên/địa chỉ, dễ nhầm STK 12 số không nhãn thành CCCD); ledger một file không phát hiện được xoá dòng cuối hay viết lại cả file; `dpo` vẫn đọc hồ sơ KH-000999 và chỉ bước gửi ra ngoài bị chặn; không có cơ chế xoá dữ liệu hay thời hạn lưu trữ.
