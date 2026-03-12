<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Dùng Composer: $ composer require phpmailer/phpmailer
require 'vendor/autoload.php';

// Nếu không dùng Composer,Cần include tay:
// require 'PHPMailer/src/PHPMailer.php';
// require 'PHPMailer/src/SMTP.php';
// require 'PHPMailer/src/Exception.php';

$mail = new PHPMailer(true);

try {
    $mail->isSMTP();
    $mail->Host = $_POST['smtp_host'];
    $mail->SMTPAuth = true;
    $mail->Username = $_POST['smtp_user'];
    $mail->Password = $_POST['smtp_pass'];
    $mail->Port = $_POST['smtp_port'];

    // Encryption
    if (!empty($_POST['smtp_secure'])) {
        $mail->SMTPSecure = $_POST['smtp_secure'];
    } else {
        $mail->SMTPAutoTLS = false;
        $mail->SMTPSecure = false;
    }

    $mail->setFrom($_POST['smtp_user'], 'SMTP Test Tool');
    $mail->addAddress($_POST['to']);

    // Nội dung mặc định
    $mail->Subject = 'SMTP Configuration Success';
    $mail->Body = 'Your SMTP has been successfully configured.';
    $mail->isHTML(false);

    $mail->send();
    echo "<div style='padding:20px;color:green;'>✔️ Gửi mail thành công!</div>";
} catch (Exception $e) {
    echo "<div style='padding:20px;color:red;'>❌ Gửi thất bại: {$mail->ErrorInfo}</div>";
}
