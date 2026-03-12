<?php
// config.php - Configuration for API Gateway

return [
    // Danh sách các domain được phép gọi (Whitelist)
    // Để ngăn chặn SSRF, chỉ cho phép các domain tin cậy
    'allowed_domains' => [
        'google.com',
        'inet.vn',
        'whois.inet.vn',
        'n8n.ipi.vn',
        
    ],

    // API Keys (Hidden from client)
    // Client gọi: https://api.github.com/...
    // Server tự động inject Authorization header
    'api_keys' => [
        'api.github.com' => 'Bearer YOUR_GITHUB_TOKEN_HERE',
        // 'other-api.com' => 'Basic ...'
    ],

    // Cấu hình Rate Limit
    'rate_limit' => [
        'enabled' => true,
        'limit' => 60, // 60 requests
        'period' => 60, // trong 60 giây
        'storage' => __DIR__ . '/cache/rate_limit.json'
    ],

    // Cấu hình Cache
    'cache' => [
        'enabled' => true,
        'ttl' => 300, // 5 phút
        'path' => __DIR__ . '/cache/data/'
    ],

    // Cấu hình Log
    'logging' => [
        'enabled' => true,
        'path' => __DIR__ . '/logs/access.log'
    ]
];
