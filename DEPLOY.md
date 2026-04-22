# Deploy Notes

## 1. Code location

```bash
/opt/example
```

## 2. Private config

Tạo thư mục private ngoài webroot:

```bash
sudo install -d -m 0750 /opt/example-private
sudo chgrp www-data /opt/example-private
```

Tạo file config từ mẫu:

```bash
sudo cp /opt/example/api/config.php.example /opt/example-private/api-config.php
sudo chown root:www-data /opt/example-private/api-config.php
sudo chmod 0640 /opt/example-private/api-config.php
```

## 3. Runtime directories

```bash
sudo install -d -o www-data -g www-data -m 0755 /opt/example/api/cache
sudo install -d -o www-data -g www-data -m 0755 /opt/example/api/cache/data
sudo install -d -o www-data -g www-data -m 0755 /opt/example/api/logs
```

## 4. Nginx + PHP-FPM

Site root:

```bash
/opt/example
```

PHP backend cần chạy được qua PHP-FPM.

## 5. Sau mỗi lần pull

```bash
cd /opt/example
git pull
php -l api/proxy.php
systemctl reload nginx
systemctl restart php8.3-fpm
```

## 6. Kiểm tra nhanh

```bash
curl -sS -D - http://127.0.0.1/api/proxy.php \
  -H 'Host: example.io.vn' \
  -H 'Content-Type: application/json' \
  --data '{"url":"https://google.com","method":"GET"}'
```
