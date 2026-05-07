<?php
// check.php - DMARC Record Checker Backend
// Kiểm tra bản ghi DMARC (_dmarc.domain) sử dụng DNS lookup

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

// ============================================================
// Helper functions
// ============================================================
function jsonError(string $msg, int $code = 400): void {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

function jsonResponse(array $data): void {
    echo json_encode($data);
    exit;
}

// ============================================================
// 1. Validate domain input
// ============================================================
$domain = trim($_POST['domain'] ?? '');

if (empty($domain)) {
    jsonError('Domain name không được để trống.');
}

// Validate domain format (simple check)
if (!preg_match('/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i', $domain)) {
    jsonError('Domain name không hợp lệ. Vui lòng nhập domain đúng định dạng.');
}

// ============================================================
// 2. Check DMARC record using DNS lookup
// ============================================================
$dmarc_domain = '_dmarc.' . $domain;

try {
    // Use dns_get_record to fetch TXT records for _dmarc.domain
    $records = dns_get_record($dmarc_domain, DNS_TXT);

    if ($records === false) {
        // No records found
        jsonResponse([
            'found' => false,
            'domain' => $domain,
            'message' => "Không tìm thấy bản ghi DMARC cho $domain"
        ]);
    }

    // Filter for DMARC records (should start with v=DMARC1)
    $dmarc_record = null;
    foreach ($records as $record) {
        if (isset($record['txt'])) {
            $txt = $record['txt'];
            if (strpos($txt, 'v=DMARC1') !== false) {
                $dmarc_record = $txt;
                break;
            }
        }
    }

    if ($dmarc_record) {
        jsonResponse([
            'found' => true,
            'domain' => $domain,
            'record' => $dmarc_record
        ]);
    } else {
        // Records exist but no DMARC record found
        jsonResponse([
            'found' => false,
            'domain' => $domain,
            'message' => "Không tìm thấy bản ghi DMARC cho $domain"
        ]);
    }
} catch (Exception $e) {
    // DNS lookup failed or other error
    jsonResponse([
        'found' => false,
        'domain' => $domain,
        'message' => "Không tìm thấy bản ghi DMARC cho $domain"
    ]);
}
?>
