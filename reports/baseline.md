# Baseline — checkpoint 1

1. Agent có identity mỗi run chưa? Chưa. (`agent/loop.py:27` `_naive_loop`: không principal, không `run_id`)
2. Ai cho phép `http_post`? Không ai cả. (`agent/loop.py:44`: gọi `tools.http_post` thẳng, không qua policy)
3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Phía agent không có chứng cứ nào, chứng cứ duy nhất nằm ở bên nhận. (body POST tạo ở `agent/loop.py:44` từ `collected` dòng 37-41; sink đã nhận được ghi ở `reports/sink.log` do `sink/sink.py` ghi)
