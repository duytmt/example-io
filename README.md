# Example I/O

Bộ công cụ web nhỏ phục vụ test API, SMTP, Port Checker và DMARC Checker.

## Thành phần

- `api/` - API Request Tester + proxy backend
- `smtp/` - SMTP test tool
- `port-checker/` - TCP port checker
- `dmarc-record-validation/` - DMARC Checker

## Lưu ý bảo mật

- Không đặt file config thật trong webroot.
- File config chạy production nên đặt ngoài webroot, ví dụ:
  - `/opt/example-private/api-config.php`
- Repo chỉ giữ file mẫu cấu hình:
  - `api/config.php.example`

## Deploy nhanh

Xem thêm tại `DEPLOY.md`.

## Update...
