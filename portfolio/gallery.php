<?php
$dir = $_GET['dir'] ?? '';

// Sanitise: only allow simple directory names, no path traversal
if (!preg_match('/^[a-z0-9_-]+$/', $dir)) {
    http_response_code(400);
    exit;
}

$path = __DIR__ . '/' . $dir . '/';
if (!is_dir($path)) {
    http_response_code(404);
    exit;
}

$extensions = ['jpg', 'jpeg', 'png', 'webp'];
$photos = [];

foreach (scandir($path) as $file) {
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    if (in_array($ext, $extensions, true)) {
        $photos[] = $file;
    }
}

sort($photos);

header('Content-Type: application/json');
echo json_encode($photos);
