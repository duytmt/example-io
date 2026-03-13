<?php
// convert.php - SSL Converter Backend
// Hỗ trợ convert: PEM ↔ DER, PEM → PFX, PFX → PEM
// Security: xử lý file trong /tmp/, xóa ngay, không lưu cert trên server

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

// ============================================================
// Helper
// ============================================================
function jsonError(string $msg, int $code = 400): void {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

function jsonOk(array $data): void {
    echo json_encode($data);
    exit;
}

// ============================================================
// 1. Validate input_format & output_format
// ============================================================
$allowedFormats = ['PEM', 'DER', 'PFX'];
$inputFormat  = strtoupper(trim($_POST['input_format']  ?? ''));
$outputFormat = strtoupper(trim($_POST['output_format'] ?? ''));

if (!in_array($inputFormat, $allowedFormats, true))  jsonError('Input format không hợp lệ.');
if (!in_array($outputFormat, $allowedFormats, true)) jsonError('Output format không hợp lệ.');
if ($inputFormat === $outputFormat) jsonError('Input và Output format phải khác nhau.');

$pfxPassword = $_POST['pfx_password'] ?? '';

// ============================================================
// 2. Get cert content (paste or file upload)
// ============================================================
$certContent = null; // raw bytes
$keyContent  = null; // PEM string (optional)

if (!empty($_POST['cert_text'])) {
    // Paste mode: text input
    $certContent = trim($_POST['cert_text']);
    if (!empty($_POST['key_text'])) {
        $keyContent = trim($_POST['key_text']);
    }
} elseif (!empty($_FILES['cert_file']['tmp_name'])) {
    // Upload mode
    $file = $_FILES['cert_file'];

    // Validate type (chặn upload PHP/executable)
    $allowedExts  = ['pem', 'crt', 'cer', 'key', 'pfx', 'p12', 'der'];
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, $allowedExts, true)) {
        jsonError('Định dạng file không được hỗ trợ: .' . $ext);
    }

    // Max size: 1MB (cert files should be tiny)
    if ($file['size'] > 1 * 1024 * 1024) {
        jsonError('File quá lớn. Tối đa 1MB.');
    }

    $certContent = file_get_contents($file['tmp_name']);
} else {
    jsonError('Không có dữ liệu certificate. Vui lòng paste hoặc upload file.');
}

// ============================================================
// 3. Perform conversion using OpenSSL PHP functions
// ============================================================
// Temp file paths – dùng để feed vào openssl_*, xóa sau khi dùng
$tmpDir = sys_get_temp_dir();
$tmpCert = tempnam($tmpDir, 'ssl_cert_');
$tmpKey  = tempnam($tmpDir, 'ssl_key_');
$tmpOut  = tempnam($tmpDir, 'ssl_out_');

// Cleanup function
register_shutdown_function(function() use ($tmpCert, $tmpKey, $tmpOut) {
    foreach ([$tmpCert, $tmpKey, $tmpOut] as $f) {
        if ($f && file_exists($f)) @unlink($f);
    }
});

// Write cert content to temp file
file_put_contents($tmpCert, $certContent);
if ($keyContent) file_put_contents($tmpKey, $keyContent);

// ---- PEM → DER ----
if ($inputFormat === 'PEM' && $outputFormat === 'DER') {
    $cert = openssl_x509_read($certContent);
    if (!$cert) jsonError('Không thể đọc PEM certificate. Kiểm tra lại nội dung.');

    openssl_x509_export_to_file($cert, $tmpOut, false); // PEM first
    $cmd = "openssl x509 -in " . escapeshellarg($tmpOut) . " -outform DER -out " . escapeshellarg($tmpOut . '.der') . " 2>&1";
    exec($cmd, $output, $code);
    if ($code !== 0) {
        // Fallback: use PHP openssl_x509_export với outform DER (PHP không native support, dùng exec nếu có)
        // Thử cách khác: export PEM raw → manual base64 decode header/footer
        jsonError('Lỗi khi convert sang DER. OpenSSL exec: ' . implode(', ', $output));
    }
    $derBytes = file_get_contents($tmpOut . '.der');
    @unlink($tmpOut . '.der');
    jsonOk([
        'success'  => true,
        'content'  => base64_encode($derBytes), // base64 để transfer
        'base64'   => base64_encode($derBytes),
        'filename' => 'certificate',
    ]);
}

// ---- DER → PEM ----
if ($inputFormat === 'DER' && $outputFormat === 'PEM') {
    // certContent có thể là binary hoặc base64-encoded
    // Nếu text mode thì cần decode
    $rawBytes = $certContent;
    if (ctype_print($certContent) && strpos($certContent, 'BEGIN') === false) {
        // Có thể là base64 của DER
        $decoded = base64_decode($certContent, true);
        if ($decoded !== false) $rawBytes = $decoded;
    }
    file_put_contents($tmpCert, $rawBytes);
    $cmd = "openssl x509 -inform DER -in " . escapeshellarg($tmpCert) . " -outform PEM 2>&1";
    exec($cmd, $output, $code);
    if ($code !== 0) jsonError('Lỗi convert DER → PEM: ' . implode("\n", $output));
    jsonOk([
        'success'  => true,
        'content'  => implode("\n", $output),
        'filename' => 'certificate',
    ]);
}

// ---- PEM → PFX ----
if ($inputFormat === 'PEM' && $outputFormat === 'PFX') {
    if (!$keyContent) {
        jsonError('Cần Private Key để tạo PFX. Vui lòng paste Private Key vào ô Key Text.');
    }
    $passArg = $pfxPassword
        ? '-password pass:' . escapeshellarg($pfxPassword)
        : '-password pass: -passout pass:';

    $cmd = "openssl pkcs12 -export "
         . "-in " . escapeshellarg($tmpCert) . " "
         . "-inkey " . escapeshellarg($tmpKey) . " "
         . "-out " . escapeshellarg($tmpOut) . " "
         . "-passout pass:" . escapeshellarg($pfxPassword) . " 2>&1";
    exec($cmd, $output, $code);
    if ($code !== 0) jsonError('Lỗi tạo PFX: ' . implode("\n", $output));
    $pfxBytes = file_get_contents($tmpOut);
    jsonOk([
        'success'  => true,
        'content'  => '(Binary PFX – click Download để tải về)',
        'base64'   => base64_encode($pfxBytes),
        'filename' => 'certificate',
    ]);
}

// ---- PFX → PEM ----
if ($inputFormat === 'PFX' && $outputFormat === 'PEM') {
    $cmd = "openssl pkcs12 -in " . escapeshellarg($tmpCert)
         . " -out " . escapeshellarg($tmpOut)
         . " -nodes "
         . " -passin pass:" . escapeshellarg($pfxPassword) . " 2>&1";
    exec($cmd, $output, $code);
    if ($code !== 0) jsonError('Lỗi đọc PFX. Kiểm tra lại password: ' . implode("\n", $output));
    $pemContent = file_get_contents($tmpOut);
    jsonOk([
        'success'  => true,
        'content'  => $pemContent,
        'filename' => 'certificate',
    ]);
}

// ---- PFX → DER ----
if ($inputFormat === 'PFX' && $outputFormat === 'DER') {
    // PFX → PEM first, then PEM → DER
    $tmpPem = tempnam($tmpDir, 'ssl_pem_');
    $cmd1 = "openssl pkcs12 -in " . escapeshellarg($tmpCert)
          . " -out " . escapeshellarg($tmpPem)
          . " -nodes -nokeys"
          . " -passin pass:" . escapeshellarg($pfxPassword) . " 2>&1";
    exec($cmd1, $o1, $c1);
    if ($c1 !== 0) { @unlink($tmpPem); jsonError('Lỗi đọc PFX: ' . implode("\n", $o1)); }

    $cmd2 = "openssl x509 -inform PEM -in " . escapeshellarg($tmpPem)
          . " -outform DER -out " . escapeshellarg($tmpOut) . " 2>&1";
    exec($cmd2, $o2, $c2);
    @unlink($tmpPem);
    if ($c2 !== 0) jsonError('Lỗi convert sang DER: ' . implode("\n", $o2));

    $derBytes = file_get_contents($tmpOut);
    jsonOk([
        'success'  => true,
        'content'  => '(Binary DER – click Download để tải về)',
        'base64'   => base64_encode($derBytes),
        'filename' => 'certificate',
    ]);
}

// ---- DER → PFX (phải có private key) ----
if ($inputFormat === 'DER' && $outputFormat === 'PFX') {
    if (!$keyContent) jsonError('Cần Private Key (PEM format) để tạo PFX từ DER.');

    $cmd1 = "openssl x509 -inform DER -in " . escapeshellarg($tmpCert)
          . " -outform PEM -out " . escapeshellarg($tmpOut) . " 2>&1";
    exec($cmd1, $o1, $c1);
    if ($c1 !== 0) jsonError('Lỗi đọc DER: ' . implode("\n", $o1));

    $tmpPem = $tmpOut;
    $cmd2 = "openssl pkcs12 -export"
          . " -in " . escapeshellarg($tmpPem)
          . " -inkey " . escapeshellarg($tmpKey)
          . " -out " . escapeshellarg($tmpOut . '.pfx')
          . " -passout pass:" . escapeshellarg($pfxPassword) . " 2>&1";
    exec($cmd2, $o2, $c2);
    if ($c2 !== 0) jsonError('Lỗi tạo PFX: ' . implode("\n", $o2));

    $pfxBytes = file_get_contents($tmpOut . '.pfx');
    @unlink($tmpOut . '.pfx');
    jsonOk([
        'success'  => true,
        'content'  => '(Binary PFX – click Download để tải về)',
        'base64'   => base64_encode($pfxBytes),
        'filename' => 'certificate',
    ]);
}

jsonError('Cặp convert ' . $inputFormat . ' → ' . $outputFormat . ' chưa được hỗ trợ.');
