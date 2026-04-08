<?php
// Load .env
$env = [];
foreach (file(__DIR__ . '/.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
    if (str_starts_with(trim($line), '#')) continue;
    [$k, $v] = explode('=', $line, 2);
    $env[trim($k)] = trim($v);
}

require __DIR__ . '/vendor/phpmailer/PHPMailer.php';
require __DIR__ . '/vendor/phpmailer/SMTP.php';
require __DIR__ . '/vendor/phpmailer/Exception.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'Method not allowed']);
    exit;
}

// --- Layer 1: Honeypot ---
if (!empty($_POST['website'])) {
    echo json_encode(['ok' => true]); // Silently succeed
    exit;
}

// --- Layer 2: Time check (bots submit too fast) ---
$ts = (int)($_POST['ts'] ?? 0);
$elapsed = (int)(microtime(true) * 1000) - $ts;
if ($ts === 0 || $elapsed < 3000) {
    echo json_encode(['ok' => true]); // Silently succeed
    exit;
}

// --- Layer 3: Cloudflare Turnstile verification ---
$turnstileToken = $_POST['cf-turnstile-response'] ?? '';
if (empty($turnstileToken)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Security check failed. Please reload and try again.']);
    exit;
}
$verify = curl_init();
curl_setopt_array($verify, [
    CURLOPT_URL            => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => http_build_query([
        'secret'   => $env['TURNSTILE_SECRET'],
        'response' => $turnstileToken,
        'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 5,
]);
$result = json_decode(curl_exec($verify), true);
curl_close($verify);
if (empty($result['success'])) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Security check failed. Please try again.']);
    exit;
}

// --- Layer 4: Rate limiting (3 submissions per IP per hour) ---
$ip       = preg_replace('/[^a-f0-9:.]/', '', $_SERVER['REMOTE_ADDR'] ?? '');
$rateDir  = __DIR__ . '/.ratelimit';
$rateFile = $rateDir . '/' . md5($ip) . '.json';
$now      = time();
$window   = 3600;
$limit    = 3;

$log = file_exists($rateFile) ? json_decode(file_get_contents($rateFile), true) : [];
$log = array_filter($log, fn($t) => $t > $now - $window);

if (count($log) >= $limit) {
    http_response_code(429);
    echo json_encode(['ok' => false, 'error' => 'Too many submissions. Please try again later.']);
    exit;
}
// Note: rate limit slot is only written after input validation passes

// --- Validate inputs ---
$name    = trim($_POST['name'] ?? '');
$email   = trim($_POST['email'] ?? '');
$message = trim($_POST['message'] ?? '');

if (!$name || !$email || !$message) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'All fields are required.']);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Invalid email address.']);
    exit;
}

$domain = substr($email, strrpos($email, '@') + 1);
if (!checkdnsrr($domain, 'MX') && !checkdnsrr($domain, 'A')) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Email domain doesn\'t look valid. Please check your address.']);
    exit;
}

$name    = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
$message = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');

// All validation passed — now count this against the rate limit
$log[] = $now;
file_put_contents($rateFile, json_encode(array_values($log)), LOCK_EX);

// --- Send via SES SMTP ---
$mail = new PHPMailer(true);
try {
    $mail->isSMTP();
    $mail->Host       = $env['SES_SMTP_HOST'];
    $mail->SMTPAuth   = true;
    $mail->Username   = $env['SES_SMTP_USER'];
    $mail->Password   = $env['SES_SMTP_PASS'];
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port       = 587;

    $mail->setFrom($env['SES_FROM'], 'lxdesigns.fi');
    $mail->addAddress($env['SES_TO']);
    $mail->addReplyTo($email, $name);

    $mail->Subject = "Contact: $name";
    $mail->Body    = "Name: $name\nEmail: $email\n\n$message";

    $mail->send();
    echo json_encode(['ok' => true]);
} catch (Exception $e) {
    http_response_code(500);
    error_log('PHPMailer error: ' . $mail->ErrorInfo);
    echo json_encode(['ok' => false, 'error' => 'Failed to send. Please email contact@lxdesigns.fi directly.']);
}
