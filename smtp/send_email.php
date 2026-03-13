<?php
// send_email.php - SMTP Test Tool Backend
// Security: validate + sanitize all inputs, no error display in production

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';

// ============================================================
// Helper: JSON error response
// ============================================================
function jsonError(string $msg, int $code = 400): void {
    http_response_code($code);
    echo "<div style='padding:20px;color:#ff6b6b;'>❌ " . htmlspecialchars($msg) . "</div>";
    exit;
}

// ============================================================
// 1. Validate SMTP Host (non-empty, no injection chars)
// ============================================================
$smtp_host = trim($_POST['smtp_host'] ?? '');
if (empty($smtp_host) || !preg_match('/^[a-zA-Z0-9.\-]+$/', $smtp_host)) {
    jsonError('SMTP Host không hợp lệ.');
}

// ============================================================
// 2. Validate SMTP Port (chỉ chấp nhận 25, 465, 587)
// ============================================================
$allowed_ports = [25, 465, 587];
$smtp_port = (int)($_POST['smtp_port'] ?? 0);
if (!in_array($smtp_port, $allowed_ports, true)) {
    jsonError('Port không hợp lệ. Chỉ chấp nhận: 25, 465, 587.');
}

// ============================================================
// 3. Validate SMTP Secure (whitelist)
// ============================================================
$allowed_secure = ['ssl', 'tls', ''];
$smtp_secure = trim($_POST['smtp_secure'] ?? '');
if (!in_array($smtp_secure, $allowed_secure, true)) {
    jsonError('Kiểu mã hóa không hợp lệ.');
}

// ============================================================
// 4. Validate SMTP Username (email format)
// ============================================================
$smtp_user = trim($_POST['smtp_user'] ?? '');
if (empty($smtp_user) || !filter_var($smtp_user, FILTER_VALIDATE_EMAIL)) {
    jsonError('Tài khoản SMTP phải là địa chỉ email hợp lệ.');
}

// ============================================================
// 5. Validate Password (non-empty)
// ============================================================
$smtp_pass = $_POST['smtp_pass'] ?? '';
if (empty($smtp_pass)) {
    jsonError('Mật khẩu SMTP không được để trống.');
}

// ============================================================
// 6. Validate Recipient Email
// ============================================================
$to = trim($_POST['to'] ?? '');
if (empty($to) || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
    jsonError('Email nhận kết quả không hợp lệ.');
}

// ============================================================
// 7. Send Email via PHPMailer
// ============================================================
$mail = new PHPMailer(true);

try {
    $mail->isSMTP();
    $mail->Host       = $smtp_host;
    $mail->SMTPAuth   = true;
    $mail->Username   = $smtp_user;
    $mail->Password   = $smtp_pass;
    $mail->Port       = $smtp_port;

    // Encryption
    if (!empty($smtp_secure)) {
        $mail->SMTPSecure = $smtp_secure;
    } else {
        $mail->SMTPAutoTLS = false;
        $mail->SMTPSecure  = false;
    }

    $mail->setFrom($smtp_user, 'SMTP Test Tool');
    $mail->addAddress($to);

    $mail->Subject = 'SMTP Configuration Test - Success';
    $mail->Body    = "Your SMTP configuration has been successfully verified.\n\nServer: $smtp_host:$smtp_port\nEncryption: " . ($smtp_secure ?: 'None');
    $mail->isHTML(false);

    $mail->send();
    echo "<div style='padding:20px;color:#4caf50;'>✔️ Gửi mail thành công tới <strong>" . htmlspecialchars($to) . "</strong>!</div>";

} catch (Exception $e) {
    // Không expose stack trace - chỉ log ErrorInfo an toàn
    echo "<div style='padding:20px;color:#ff6b6b;'>❌ Gửi thất bại: " . htmlspecialchars($mail->ErrorInfo) . "</div>";
}
