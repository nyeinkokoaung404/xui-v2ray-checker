<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST');
header('Access-Control-Allow-Headers: Content-Type');

// API Metadata
$API_INFO = [
    'api_owner' => 'Channel 404 Team',
    'owner_contact' => '@nkka404',
    'updates_channel' => '@premium_channel_404',
    'channel_link' => 'https://t.me/premium_channel_404',
    'version' => '2.0',
    'description' => 'Premium V2Ray Account Checker',
    'features' => [
        'Multi-panel support',
        'All protocol types (VMess, VLESS, Trojan, Shadowsocks)',
        'Traffic monitoring',
        'Expiry tracking'
    ]
];

// X-UI Panel Configuration
$PANELS = [
    'VIP Singapore 🇸🇬 Server' => [
        'url' => 'http://35.5.43.65.32:12345/w0MW874U8fevz8D/',
        'username' => 'admin',
        'password' => 'admin'
    ],
    'VIP India 🇮🇳 Server' => [
        'url' => 'http://35.5.43.65.32:12345/HgU4NwQGXoVWXsk/',
        'username' => 'admin',
        'password' => 'admin'
    ],
    'VIP Thailand 🇹🇭 Server' => [
        'url' => 'http://35.5.43.65.32:12345/XrrhV86iIGYQOdT/',
        'username' => 'admin',
        'password' => 'admin'
    ],
    'VIP Japan 🇯🇵 Server' => [
        'url' => 'http://35.5.43.65.32:12345/v1OmtYoEw0kiRBb/',
        'username' => 'admin',
        'password' => 'admin'
    ]
];

function formatBytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
    
    if ($bytes <= 0) return ['value' => 0, 'unit' => 'B', 'text' => '0 B'];
    if ($bytes === -1) return ['value' => 0, 'unit' => 'Unlimited', 'text' => 'Unlimited'];
    
    $pow = floor(log($bytes) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    
    return [
        'value' => round($bytes, $precision),
        'unit' => $units[$pow],
        'text' => round($bytes, $precision) . ' ' . $units[$pow]
    ];
}

function formatExpiryTime($timestamp) {
    // If timestamp is 0 or negative (used for 'never expires' or days remaining based on negative value)
    if ($timestamp <= 0) {
        // If it's explicitly 0 (often means never expires in some systems)
        if ($timestamp === 0) {
            return [
                'timestamp' => 0,
                'formatted' => 'Never Expires',
                'detailed' => 'Never Expires',
                'days_remaining' => -1,
                'status' => 'active'
            ];
        } else { // Handle negative timestamps as days remaining directly (as seen in Python code)
            $days = intval($timestamp / -86400); // 86400 seconds in a day
            return [
                'timestamp' => $timestamp,
                'formatted' => "{$days} Day" . ($days != 1 ? 's' : ''),
                'detailed' => "{$days} Day" . ($days != 1 ? 's' : ''),
                'days_remaining' => $days,
                'status' => 'active'
            ];
        }
    }
    
    // Convert milliseconds to seconds if necessary (X-UI often uses milliseconds)
    if ($timestamp > 1000000000000) { // Arbitrary large number to detect milliseconds timestamp
        $timestamp = intval($timestamp / 1000);
    }

    $now = time();
    $remaining = $timestamp - $now;
    
    if ($remaining <= 0) return [
        'timestamp' => $timestamp,
        'formatted' => 'Expired',
        'detailed' => 'Expired',
        'days_remaining' => 0,
        'status' => 'expired'
    ];
    
    $days = floor($remaining / 86400);
    $hours = floor(($remaining % 86400) / 3600);
    $minutes = floor(($remaining % 3600) / 60);
    // Seconds are not shown in detailed expiry string in Python, but included for completeness.
    // $seconds = $remaining % 60;
    
    $time_parts = [];
    if ($days > 0) {
        $time_parts[] = "{$days} day" . ($days != 1 ? 's' : '');
    }
    if ($hours > 0) {
        $time_parts[] = "{$hours} hour" . ($hours != 1 ? 's' : '');
    }
    // Always include minutes if no days/hours, or if minutes > 0
    if ($minutes > 0 || empty($time_parts)) {
        $time_parts[] = "{$minutes} minute" . ($minutes != 1 ? 's' : '');
    }
    
    $rem_time_str = implode(' ', $time_parts);
    $expiry_date_str = date('Y-m-d H:i:s', $timestamp);
    
    return [
        'timestamp' => $timestamp,
        'formatted' => $rem_time_str, // Matches Python's first expiry return
        'detailed' => $expiry_date_str, // Matches Python's second expiry return
        'days_remaining' => $days,
        'status' => $days <= 7 ? 'expiring_soon' : 'active' // This status is custom to PHP script
    ];
}

function cleanPercentage($percentage) {
    $rounded = round($percentage);
    $cleaned = max(0, min(100, $rounded));
    return $cleaned . '%';
}

function prettyJsonResponse($data) {
    // Format traffic data if present
    if (isset($data['up']) || isset($data['down']) || isset($data['total'])) {
        $totalBytes = $data['total'] ?? 0;
        $usedBytes = ($data['up'] ?? 0) + ($data['down'] ?? 0);
        
        $data['traffic'] = [
            'upload' => formatBytes($data['up'] ?? 0),
            'download' => formatBytes($data['down'] ?? 0),
            'total' => $totalBytes <= 0 ? formatBytes(-1) : formatBytes($totalBytes),
            'used' => formatBytes($usedBytes),
            'remaining' => $totalBytes <= 0 ? 
                formatBytes(-1) : 
                formatBytes(max(0, $totalBytes - $usedBytes)),
            'usage_percentage' => $totalBytes > 0 ? 
                cleanPercentage(($usedBytes / $totalBytes) * 100) : '0%'
        ];
    }
    
    // Format expiry time if present
    if (isset($data['expiryTime'])) {
        $expiryResult = formatExpiryTime($data['expiryTime']);
        $data['expiry'] = [
            'remaining_time_text' => $expiryResult['formatted'], // Matches Python's rem_time
            'expiry_date_formatted' => $expiryResult['detailed'], // Matches Python's expiry_date
            'days_remaining' => $expiryResult['days_remaining'],
            'status' => $expiryResult['status']
        ];
        // Remove original expiryTime from top-level if we put it in 'expiry' object
        unset($data['expiryTime']);
    }
    
    $response = [
        'api_info' => $GLOBALS['API_INFO'],
        'data' => $data,
        'timestamp' => time(),
        'success' => !isset($data['error'])
    ];
    
    return json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

function parseConfig($config) {
    $config = trim($config);
    
    try {
        // Check if it's an email first
        if (filter_var($config, FILTER_VALIDATE_EMAIL)) {
            return [
                'type' => 'email',
                'value' => $config,
                'email' => $config
            ];
        }
        
        // VMESS
        if (strpos($config, 'vmess://') === 0) {
            $data = substr($config, 8);
            $padding = strlen($data) % 4;
            if ($padding > 0) $data .= str_repeat('=', 4 - $padding);
            
            $decoded = base64_decode($data);
            if ($decoded === false) return ['error' => 'Invalid VMess base64'];
            
            $json = json_decode($decoded, true);
            if (!$json) {
                // Try to find UUID even if not valid JSON, for cases like raw UUIDs within vmess links
                preg_match('/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i', $decoded, $matches);
                if ($matches) {
                    return [
                        'type' => 'vmess',
                        'value' => $matches[0],
                        'email' => $matches[0], // Use UUID as email fallback for identification
                        'method' => 'auto'
                    ];
                }
                return ['error' => 'Invalid VMess JSON or UUID not found'];
            }
            
            return [
                'type' => 'vmess',
                'value' => $json['id'] ?? '',
                'email' => $json['ps'] ?? $json['id'] ?? 'VMess Account', // Use 'id' as fallback for email
                'method' => $json['method'] ?? 'auto'
            ];
        }
        
        // VLESS
        if (strpos($config, 'vless://') === 0) {
            $data = substr($config, 8);
            $parts = explode('@', $data);
            if (count($parts) < 1) return ['error' => 'Invalid VLESS format']; // Should be at least UUID part
            
            $uuid = $parts[0];
            if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uuid)) {
                return ['error' => 'Invalid VLESS UUID'];
            }
            
            return [
                'type' => 'vless',
                'value' => $uuid,
                'email' => $uuid, // Use UUID as email for identification
                'method' => 'none'
            ];
        }
        
        // Trojan
        if (strpos($config, 'trojan://') === 0) {
            $data = substr($config, 9);
            $parts = explode('@', $data);
            if (count($parts) < 1) return ['error' => 'Invalid Trojan format'];
            
            return [
                'type' => 'trojan',
                'value' => $parts[0], // password part
                'email' => $parts[0], // Use password as email for identification
                'method' => 'tls'
            ];
        }
        
        // Shadowsocks
        if (strpos($config, 'ss://') === 0) {
            $data = substr($config, 5);
            $atPos = strpos($data, '@');
            if ($atPos === false) { // Simple ss://password@server:port format
                $encoded = $data;
            } else {
                $encoded = substr($data, 0, $atPos);
            }
            
            $padding = strlen($encoded) % 4;
            if ($padding > 0) $encoded .= str_repeat('=', 4 - $padding);
            
            $decoded = base64_decode($encoded);
            if ($decoded === false) return ['error' => 'Invalid SS base64'];
            
            $parts = explode(':', $decoded);
            if (count($parts) < 2) return ['error' => 'Invalid SS config'];
            
            return [
                'type' => 'shadowsocks',
                'value' => end($parts), // password part
                'email' => end($parts), // Use password as email for identification
                'method' => $parts[0] ?? 'aes-256-gcm' // encryption method
            ];
        }
        
        // Raw UUID (VMESS/VLESS)
        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $config)) {
            return [
                'type' => 'uuid',
                'value' => $config,
                'email' => $config, // Use UUID as email for identification
                'method' => 'auto'
            ];
        }
        
        // If nothing else matches, treat as email (last attempt)
        return [
            'type' => 'email',
            'value' => $config,
            'email' => $config
        ];
        
    } catch (Exception $e) {
        return ['error' => 'Config parse error: ' . $e->getMessage()];
    }
}

/**
 * Fetches account information from V2Ray panels.
 * This version significantly improves cookie handling and endpoint probing.
 *
 * @param array $parsedConfig The parsed configuration (e.g., UUID, email, password)
 * @return array Account information or an error array.
 */
function fetchAccountInfo($parsedConfig) {
    global $PANELS;

    $user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

    foreach ($PANELS as $panelName => $panel) {
        $ch = curl_init();
        $panel_url = rtrim($panel['url'], '/') . '/'; // Ensure trailing slash

        // Initialize session cookies for this panel
        $cookies = [];
        $cookie_header = '';

        // --- Step 1: Login to the panel ---
        curl_setopt($ch, CURLOPT_URL, $panel_url . 'login');
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'username' => $panel['username'],
            'password' => $panel['password']
        ]));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true); // Get headers to read Set-Cookie
        curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15); // Increased timeout
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // For self-signed or untrusted certs, use with caution

        $loginResponse = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if (curl_errno($ch)) {
            // Log this error for debugging
            // error_log("Panel {$panelName} login CURL error: " . curl_error($ch));
            curl_close($ch);
            continue; // Try next panel
        }

        if ($http_code != 200) {
            // Log this error for debugging
            // error_log("Panel {$panelName} login HTTP error: {$http_code}. Response: {$loginResponse}");
            curl_close($ch);
            continue; // Try next panel
        }
        
        // Extract cookies from login response headers
        preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $loginResponse, $matches);
        foreach ($matches[1] as $item) {
            parse_str($item, $cookie);
            $cookies = array_merge($cookies, $cookie);
        }
        
        // Prepare Cookie header for subsequent requests
        foreach ($cookies as $key => $value) {
            $cookie_header .= "{$key}={$value}; ";
        }
        $cookie_header = rtrim($cookie_header, '; ');

        if (empty($cookie_header)) {
            // No cookies received after login, indicates a potential login failure or misconfiguration
            curl_close($ch);
            continue;
        }

        // --- Step 2: Get inbounds list from the panel ---
        $endpoints_to_try = ["xui/inbound/list", "panel/inbound/list"];
        $inbounds = null;

        foreach ($endpoints_to_try as $endpoint) {
            curl_setopt($ch, CURLOPT_URL, $panel_url . $endpoint);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, '');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ["Cookie: {$cookie_header}"]); // Send extracted cookies
            curl_setopt($ch, CURLOPT_HEADER, false); // No need for headers in this response
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

            $inboundResponse = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

            if (curl_errno($ch) || $http_code != 200 || empty($inboundResponse)) {
                // error_log("Panel {$panelName} endpoint {$endpoint} CURL/HTTP error. Trying next endpoint.");
                continue; // Try next endpoint
            }

            $decoded_response = json_decode($inboundResponse, true);
            if (json_last_error() === JSON_ERROR_NONE && isset($decoded_response['success']) && $decoded_response['success']) {
                $inbounds = $decoded_response;
                break; // Found successful endpoint
            }
            // error_log("Panel {$panelName} endpoint {$endpoint} JSON decode error or success=false.");
        }
        curl_close($ch);

        if (!$inbounds || !isset($inbounds['obj'])) {
            continue; // Could not get valid inbounds from this panel, try next
        }

        // --- Step 3: Search through inbounds for the account ---
        foreach ($inbounds['obj'] as $inbound) {
            // Check for both 'clientStats' and 'clientInfo' keys (like Python script)
            $clients_data = $inbound['clientStats'] ?? $inbound['clientInfo'] ?? null;
            $inbound_settings = json_decode($inbound['settings'], true);
            $clients_config = $inbound_settings['clients'] ?? [];

            // If clients_data is not available (older panels or different structure)
            // Or if it's the newer format where clientStats are separate and need to be matched
            if ($clients_data !== null && !empty($clients_data)) {
                 // Newer X-UI where 'clientStats' (or 'clientInfo') is directly available
                foreach ($clients_config as $client_conf) { // Iterate through client configs for matching
                    foreach ($clients_data as $client_stat) { // Iterate through stats to find matching stat
                        if (!isset($client_stat['email']) || !isset($client_conf['email'])) continue;

                        if (strcasecmp($client_stat['email'], $client_conf['email']) === 0) {
                            $match_id = $client_conf['id'] ?? '';
                            $match_password = $client_conf['password'] ?? '';
                            $match_email = $client_conf['email'] ?? '';
                            $matched_client = $client_conf; // This is the client config matched by email
                            $matched_stat = $client_stat; // This is the stat matched by email

                            $is_matched = false;
                            switch ($parsedConfig['type']) {
                                case 'email':
                                    $is_matched = (strcasecmp($match_email, $parsedConfig['value']) === 0);
                                    break;
                                case 'vmess':
                                case 'vless':
                                case 'uuid':
                                    $is_matched = (strcasecmp($match_id, $parsedConfig['value']) === 0);
                                    break;
                                case 'shadowsocks':
                                case 'trojan':
                                    $is_matched = (strcasecmp($match_password, $parsedConfig['value']) === 0);
                                    break;
                            }

                            if ($is_matched) {
                                $totalGB = $matched_client['totalGB'] ?? 0;
                                // Handle totalGB field correctly (similar to Python logic)
                                $totalBytes = ($totalGB > 0) ? 
                                    (($totalGB > 1000000) ? $totalGB : $totalGB * 1024 * 1024 * 1024) : // Convert GB to bytes
                                    0;

                                return [
                                    'panel_name' => $panelName,
                                    'protocol' => strtolower($inbound['protocol']),
                                    'email' => $matched_client['email'] ?? $parsedConfig['email'],
                                    'up' => $matched_stat['up'] ?? 0,
                                    'down' => $matched_stat['down'] ?? 0,
                                    'total' => $totalBytes,
                                    'expiryTime' => isset($matched_client['expiryTime']) ? intval($matched_client['expiryTime']) : 0, // Ensure integer, keep as milliseconds for formatExpiryTime to convert
                                    'enable' => $matched_client['enable'] ?? true,
                                    'method' => $parsedConfig['method'] ?? '',
                                    'matched_by' => $parsedConfig['type']
                                ];
                            }
                        }
                    }
                }
            } else { // Older X-UI or basic inbound format, where 'up', 'down', 'total' are directly in inbound object
                // If the inbound itself has the direct stats, match by remark (email) or direct fields
                $remark = $inbound['remark'] ?? '';
                $id_from_settings = $inbound_settings['id'] ?? '';
                $password_from_settings = $inbound_settings['password'] ?? ''; // For direct SS/Trojan inbounds
                
                $is_matched = false;
                switch ($parsedConfig['type']) {
                    case 'email':
                        $is_matched = (strcasecmp($remark, $parsedConfig['value']) === 0);
                        break;
                    case 'vmess':
                    case 'vless':
                    case 'uuid':
                        $is_matched = (strcasecmp($id_from_settings, $parsedConfig['value']) === 0);
                        break;
                    case 'shadowsocks':
                    case 'trojan':
                        // If password exists directly in inbound settings, use that
                        $is_matched = (strcasecmp($password_from_settings, $parsedConfig['value']) === 0);
                        // Also check if the remark itself is the password for older simple setups
                        if (!$is_matched) {
                             $is_matched = (strcasecmp($remark, $parsedConfig['value']) === 0);
                        }
                        break;
                }

                if ($is_matched) {
                    $totalBytes = $inbound['total'] ?? 0;
                    // Note: totalGB is not directly present in this old format, 'total' is in bytes
                    // If 'total' is in GB and needs conversion, adjust here.
                    // Assuming 'total' here is already in bytes for older panels.

                    return [
                        'panel_name' => $panelName,
                        'protocol' => strtolower($inbound['protocol']),
                        'email' => $inbound['remark'] ?? $parsedConfig['email'],
                        'up' => $inbound['up'] ?? 0,
                        'down' => $inbound['down'] ?? 0,
                        'total' => $totalBytes,
                        'expiryTime' => isset($inbound['expiryTime']) ? intval($inbound['expiryTime']) : 0,
                        'enable' => $inbound['enable'] ?? true,
                        'method' => $parsedConfig['method'] ?? '',
                        'matched_by' => $parsedConfig['type']
                    ];
                }
            }
        }
    }
    
    return ['error' => 'Account not found in any panel'];
}

// Main request handler
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['config'])) {
    // Handle GET request with ?config= parameter
    $parsed = parseConfig($_GET['config']);
    
    if (isset($parsed['error'])) {
        echo prettyJsonResponse(['error' => $parsed['error']]);
        exit;
    }
    
    $accountInfo = fetchAccountInfo($parsed);
    echo prettyJsonResponse($accountInfo);
    exit;
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle POST request with JSON body
    $input = json_decode(file_get_contents('php://input'), true);
    $config = $input['config'] ?? '';
    
    $parsed = parseConfig($config);
    
    if (isset($parsed['error'])) {
        echo prettyJsonResponse(['error' => $parsed['error']]);
        exit;
    }
    
    $accountInfo = fetchAccountInfo($parsed);
    echo prettyJsonResponse($accountInfo);
    exit;
}

// Default response for invalid requests
echo prettyJsonResponse([
    'error' => 'Invalid request',
    'usage' => [
        'GET' => '/api.php?config=YOUR_CONFIG',
        'POST' => 'Send JSON: {"config":"YOUR_CONFIG"}'
    ],
    'supported_formats' => [
        'vmess://',
        'vless://',
        'ss://',
        'trojan://',
        'Raw UUID',
        'Email'
    ]
]);

?>
