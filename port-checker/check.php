<?php
// check.php - Port Checker Backend
// Kiểm tra TCP port có mở hay không trên domain/IP được chỉ định
// SSRF Protection: Block private IP ranges

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

// ============================================================
// Helper: trả về JSON error
// ============================================================
function jsonError(string $msg, int $code = 400): void {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

// ============================================================
// 1. Parse Input
// ============================================================
$input = json_decode(file_get_contents('php://input'), true);
if (!$input || empty($input['host']) || !isset($input['port'])) {
    jsonError('Thiếu tham số host hoặc port.');
}

$host = trim($input['host']);
$port = (int)$input['port'];

// ============================================================
// 2. Validate Port (1 - 65535)
// ============================================================
if ($port < 1 || $port > 65535) {
    jsonError('Port không hợp lệ. Range: 1–65535.');
}

// ============================================================
// 3. Validate & Resolve Host (SSRF Protection)
// ============================================================

// Chỉ cho phép hostname hợp lệ: domain hoặc public IPv4/IPv6
if (!preg_match('/^[a-zA-Z0-9.\-:]+$/', $host)) {
    jsonError('Host chứa ký tự không hợp lệ.');
}

// Resolve hostname → IP để kiểm tra private range
$resolved = gethostbyname($host);
if ($resolved === $host && !filter_var($host, FILTER_VALIDATE_IP)) {
    // Không resolve được và không phải IP hợp lệ
    jsonError('Không thể phân giải hostname: ' . htmlspecialchars($host));
}

$ip = filter_var($resolved, FILTER_VALIDATE_IP) ? $resolved : $host;

// ============================================================
// 4. Block Private / Reserved IP Ranges (SSRF)
// ============================================================
$privateRanges = [
    // IPv4 Private
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    // Loopback
    '127.0.0.0/8',
    // Link-local
    '169.254.0.0/16',
    // RFC 6598 (Shared Address)
    '100.64.0.0/10',
    // CGNAT
    '192.0.0.0/24',
    // Documentation
    '192.0.2.0/24',
    '198.51.100.0/24',
    '203.0.113.0/24',
    // Broadcast
    '255.255.255.255/32',
];

foreach ($privateRanges as $range) {
    if (ipInCidr($ip, $range)) {
        jsonError('Private/Reserved IP không được phép quét để ngăn SSRF.', 403);
    }
}

// ============================================================
// 5. TCP Port Check via fsockopen
// ============================================================
$timeout = 3; // giây
$startTime = microtime(true);

$connection = @fsockopen($host, $port, $errno, $errstr, $timeout);
$latency = round((microtime(true) - $startTime) * 1000); // ms

if ($connection !== false) {
    fclose($connection);
    echo json_encode([
        'host'       => $host,
        'port'       => $port,
        'open'       => true,
        'latency_ms' => $latency,
    ]);
} else {
    echo json_encode([
        'host'       => $host,
        'port'       => $port,
        'open'       => false,
        'latency_ms' => $latency,
        'reason'     => $errstr,
    ]);
}

// ============================================================
// Helper: Kiểm tra IP có nằm trong CIDR không
// ============================================================
function ipInCidr(string $ip, string $cidr): bool {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
    [$subnet, $mask] = explode('/', $cidr);
    $ipLong     = ip2long($ip);
    $subnetLong = ip2long($subnet);
    $maskLong   = ~((1 << (32 - (int)$mask)) - 1);
    return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
}
