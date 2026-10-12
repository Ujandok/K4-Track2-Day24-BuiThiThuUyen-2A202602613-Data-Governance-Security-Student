# Secret giả trong lịch sử Git — checkpoint 4

- **Scanner và phiên bản:** Gitleaks v8.30.1 (`gitleaks version` → `8.30.1`), cấu hình `.gitleaks.toml`.
- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`, 2026-10-09). File đã bị xoá ở commit sau.
- **File, rule và kết quả quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose .` quét 13 commit, báo **1 finding**, exit code 1 (đúng dự kiến): rule `lab24-synthetic-token`, file `lab-fake-secret.txt`, fingerprint `1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1`. Giá trị được che bởi `--redact`. Đây là token giả, vô hiệu, do đề bài cài sẵn; không phải lỗi bảo mật thật.
- **Kết quả quét file hiện tại:** `gitleaks dir --config .gitleaks.toml --redact .` → `no leaks found`, exit code 0. Không phải thêm allowlist nào, không tắt rule nào trong `.gitleaks.toml`.
- **Nếu đây là credential thật, cần xử lý thế nào:** phải **thu hồi/rotate ngay** tại dịch vụ đã cấp token (cấp token mới, vô hiệu token cũ), rà log sử dụng của token để tìm truy cập trái phép trong khoảng thời gian nó nằm trong repo, rồi xử lý các bản sao còn lại (fork, clone, CI cache, bản đã push lên remote). Chỉ sau đó mới cân nhắc viết lại lịch sử để dọn dấu vết.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:** xoá file ở commit mới không xoá được token khỏi lịch sử Git; ai clone repo vẫn lấy được commit `1bdd849`, và token vẫn dùng được cho đến khi bị thu hồi. Pin dependency (`requirements.lock` có hash) chỉ bảo vệ chuỗi cung ứng gói cài, và hook pre-commit chỉ chặn secret **mới** trước khi commit; cả hai không làm token đã lộ mất hiệu lực. Chỉ rotate/thu hồi mới xử lý được secret đã lộ.

## Biện pháp đã đặt

- `.pre-commit-config.yaml`: hook `gitleaks-system` từ `https://github.com/gitleaks/gitleaks`, pin `rev: v8.30.1`, `pass_filenames: false`, quét thư mục hiện tại bằng `gitleaks dir --config .gitleaks.toml`.
- `requirements.lock`: sinh bằng `pip-compile --generate-hashes`; cài lại bằng `pip install --require-hashes -r requirements.lock`.
