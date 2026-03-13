<?php
// check.php - Port Checker Backend
// Dùng cURL (luôn sẵn) thay vì fsockopen (thường bị disable trên shared hosting)
// SSRF Protection: Block private/reserved IP ranges

// Luôn trả về JSON - tránh HTML leak vào response
ini_set('display_errors', 0);
error_reporting(0);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// ============================================================
// Helper
// ============================================================
function jsonOut(array $data, int $code = 200): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

// ============================================================
// 1. Parse JSON Input
// ============================================================
$raw = file_get_contents('php://input');
$input = json_decode($raw, true);

if (!$input || !isset($input['host'], $input['port'])) {
    jsonOut(['error' => 'Thiếu tham số host hoặc port.'], 400);
}

$host = trim((string)$input['host']);
$port = (int)$input['port'];

// ============================================================
// 2. Validate Port
// ============================================================
if ($port < 1 || $port > 65535) {
    jsonOut(['error' => 'Port không hợp lệ. Range: 1–65535.'], 400);
}

// ============================================================
// 3. Validate Host format
// ============================================================
if (empty($host) || !preg_match('/^[a-zA-Z0-9.\-]+$/', $host)) {
    jsonOut(['error' => 'Host chứa ký tự không hợp lệ.'], 400);
}

// ============================================================
// 4. Resolve hostname → IP (để kiểm tra SSRF)
// ============================================================
$ip = gethostbyname($host);

// Nếu resolve thất bại, gethostbyname trả về hostname gốc
if ($ip === $host && !filter_var($host, FILTER_VALIDATE_IP)) {
    // Thử thêm lần nữa với dns_get_record
    $dnsResult = @dns_get_record($host, DNS_A);
    if (!empty($dnsResult)) {
        $ip = $dnsResult[0]['ip'];
    } else {
        jsonOut(['error' => 'Không thể phân giải hostname: ' . htmlspecialchars($host, ENT_QUOTES)], 400);
    }
}

// Validate IP hợp lệ
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    jsonOut(['error' => 'IP không hợp lệ sau khi phân giải: ' . htmlspecialchars($ip, ENT_QUOTES)], 400);
}

// ============================================================
// 5. Block Private / Reserved IP Ranges (SSRF Protection)
// ============================================================
function ipInCidr(string $ip, string $cidr): bool {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
    [$subnet, $bits] = explode('/', $cidr);
    $ipLong     = ip2long($ip);
    $subnetLong = ip2long($subnet);
    $mask       = -1 << (32 - (int)$bits);
    return ($ipLong & $mask) === ($subnetLong & $mask);
}

$privateRanges = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '100.64.0.0/10',
    '192.0.0.0/24',
    '192.0.2.0/24',
    '198.51.100.0/24',
    '203.0.113.0/24',
    '0.0.0.0/8',
    '240.0.0.0/4',
    '255.255.255.255/32',
];

foreach ($privateRanges as $range) {
    if (ipInCidr($ip, $range)) {
        jsonOut(['error' => 'Private/Reserved IP không được phép quét (SSRF protection).'], 403);
    }
}

// ============================================================
// 6. TCP Port Check via cURL (CURLOPT_CONNECT_ONLY)
//    Hoạt động trên hầu hết shared hosting - không cần fsockopen
// ============================================================
$startMs = round(microtime(true) * 1000);

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => "http://$ip:$port",   // URL dùng IP đã resolve (tránh bypass SSRF)
    CURLOPT_CONNECT_ONLY   => true,                  // Chỉ handshake TCP, không gửi HTTP request
    CURLOPT_TIMEOUT        => 5,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_INTERFACE      => '', // Không ép interface
]);

$result  = curl_exec($ch);
$errno   = curl_errno($ch);
$errmsg  = curl_error($ch);
$info    = curl_getinfo($ch);
curl_close($ch);

$endMs   = round(microtime(true) * 1000);
$latency = $endMs - $startMs;

// errno === 0 hoặc errno === 56 (Got nothing) = kết nối TCP thành công
// errno === 7  (Connection refused) = port closed
// errno === 28 (Timeout) = timeout / filtered
// errno === 6  (Couldn't resolve host) - không xảy ra vì đã resolve ở trên

$isOpen = ($errno === 0 || $errno === 56);

jsonOut([
    'host'       => $host,
    'ip'         => $ip,
    'port'       => $port,
    'open'       => $isOpen,
    'latency_ms' => $latency,
    'reason'     => $isOpen ? null : $errmsg,
]);
