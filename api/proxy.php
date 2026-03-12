<?php
// proxy.php - API Gateway / Proxy Backend
// Xử lý request từ Frontend, ngăn chặn SSRF, thêm CORS, Rate Limit, Caching, Log
// Nhận vào JSON { "url": "...", "method": "...", "headers": {...}, "body": ... }

// Load configuration
$config = require __DIR__ . '/config.php';

// Helper: Logging
function logRequest($message) {
    global $config;
    if ($config['logging']['enabled']) {
        $logFile = $config['logging']['path'];
        $logDir = dirname($logFile);
        if (!is_dir($logDir)) mkdir($logDir, 0777, true);
        
        $entry = date('Y-m-d H:i:s') . " - " . $_SERVER['REMOTE_ADDR'] . " - " . $message . PHP_EOL;
        file_put_contents($logFile, $entry, FILE_APPEND);
    }
}

// 1. CORS - Cho phép Frontend gọi API này
header("Access-Control-Allow-Origin: *"); // Hoặc set cụ thể domain nếu cần bảo mật nghiêm ngặt hơn
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// 2. Rate Limiting (Simple File-Based per IP)
$ip = $_SERVER['REMOTE_ADDR'];
$rateLimitFile = __DIR__ . '/cache/rate_limit_' . md5($ip) . '.json';
$rateConfig = $config['rate_limit'];

if ($rateConfig['enabled']) {
    $limitData = ['count' => 0, 'start_time' => time()];
    
    if (file_exists($rateLimitFile)) {
        $limitData = json_decode(file_get_contents($rateLimitFile), true);
    }
    
    if (time() - $limitData['start_time'] > $rateConfig['period']) {
        // Reset period
        $limitData = ['count' => 1, 'start_time' => time()];
    } else {
        $limitData['count']++;
        if ($limitData['count'] > $rateConfig['limit']) {
            http_response_code(429);
            echo json_encode(['error' => 'Too Many Requests (Rate Limit Exceeded)']);
            exit;
        }
    }
    
    // Save state
    file_put_contents($rateLimitFile, json_encode($limitData));
}

// 3. Parse Request
$input = json_decode(file_get_contents('php://input'), true);

// Fallback cho GET request trực tiếp (nếu testing bằng browser)
if (!$input && isset($_GET['url'])) {
    $input = [
        'url' => $_GET['url'],
        'method' => $_SERVER['REQUEST_METHOD'],
        'headers' => [],
        'body' => null
    ];
}

if (!$input || empty($input['url'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing URL parameter']);
    exit;
}

$targetUrl = $input['url'];
$method = strtoupper($input['method'] ?? 'GET');
$headers = $input['headers'] ?? [];
$body = $input['body'] ?? null;

// 4. Validate URL & Prevent SSRF (Whitelist Check)
$parsedUrl = parse_url($targetUrl);
$host = $parsedUrl['host'] ?? '';

$isAllowed = false;
foreach ($config['allowed_domains'] as $allowed) {
    if ($host === $allowed || str_ends_with($host, '.' . $allowed)) {
        $isAllowed = true;
        break;
    }
}

if (!$isAllowed) {
    logRequest("Blocked SSRF attempt: $targetUrl");
    http_response_code(403);
    echo json_encode(['error' => 'Domain not allowed in whitelist', 'allowed_domains' => $config['allowed_domains']]);
    exit;
}

// 5. Caching (Chỉ cache GET requests)
$cacheFile = '';
if ($method === 'GET' && $config['cache']['enabled']) {
    $cacheKey = md5($targetUrl . json_encode($headers)); // Cache dựa trên URL và Headers
    $cacheFile = $config['cache']['path'] . $cacheKey . '.json';
    
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < $config['cache']['ttl'])) {
        logRequest("Cache HIT: $targetUrl");
        header('Content-Type: application/json');
        echo file_get_contents($cacheFile);
        exit;
    }
}

// 6. Proxy Request (Using CURL)
$ch = curl_init();

// Prepare Headers
$requestHeaders = [];
foreach ($headers as $key => $value) {
    $requestHeaders[] = "$key: $value";
}

// Inject API Key (Hidden from client)
if (isset($config['api_keys'][$host])) {
    $requestHeaders[] = "Authorization: " . $config['api_keys'][$host];
}

curl_setopt($ch, CURLOPT_URL, $targetUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_HTTPHEADER, $requestHeaders);

// Handle Methods
if ($method !== 'GET') {
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    if ($body) {
        $bodyContent = is_array($body) ? json_encode($body) : $body;
        curl_setopt($ch, CURLOPT_POSTFIELDS, $bodyContent);
        // Ensure Content-Type is set if body exists
        $hasContentType = false;
        foreach($requestHeaders as $h) {
            if (stripos($h, 'Content-Type') !== false) $hasContentType = true;
        }
        if (!$hasContentType) {
            $requestHeaders[] = 'Content-Type: application/json';
            curl_setopt($ch, CURLOPT_HTTPHEADER, $requestHeaders);
        }
    }
}

// Execute
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error = curl_error($ch);
curl_close($ch);

if ($response === false) {
    logRequest("Upstream Error: $targetUrl - $error");
    http_response_code(502);
    echo json_encode(['error' => 'Upstream API Error', 'details' => $error]);
    exit;
}

// 7. Save Cache (If GET and Success)
if ($method === 'GET' && $httpCode >= 200 && $httpCode < 300 && $config['cache']['enabled']) {
    if (!is_dir(dirname($cacheFile))) mkdir(dirname($cacheFile), 0777, true);
    file_put_contents($cacheFile, $response);
}

// 8. Log & Respond
logRequest("Proxy Success: $method $targetUrl ($httpCode)");
http_response_code($httpCode);
header('Content-Type: application/json'); // Assumes JSON response from API, adjust if needed
echo $response;
