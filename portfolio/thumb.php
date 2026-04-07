<?php
$dir  = $_GET['dir']  ?? '';
$file = $_GET['file'] ?? '';

// Sanitise inputs
if (!preg_match('/^[a-z0-9_-]+$/', $dir) || !preg_match('/^[a-zA-Z0-9_\-\.]+$/', $file)) {
    http_response_code(400);
    exit;
}

$src  = __DIR__ . '/' . $dir . '/' . $file;
$ext  = strtolower(pathinfo($file, PATHINFO_EXTENSION));

if (!file_exists($src) || !in_array($ext, ['jpg', 'jpeg', 'png', 'webp'], true)) {
    http_response_code(404);
    exit;
}

$thumbDir  = __DIR__ . '/' . $dir . '/thumbs/';
$thumbFile = $thumbDir . $file;

// Serve cached thumbnail if it exists and is newer than source
if (file_exists($thumbFile) && filemtime($thumbFile) >= filemtime($src)) {
    header('Content-Type: image/' . ($ext === 'jpg' ? 'jpeg' : $ext));
    readfile($thumbFile);
    exit;
}

// Generate thumbnail (max 600px wide, maintain aspect ratio)
$maxW = 600;

switch ($ext) {
    case 'jpg': case 'jpeg': $img = imagecreatefromjpeg($src); break;
    case 'png':              $img = imagecreatefrompng($src);  break;
    case 'webp':             $img = imagecreatefromwebp($src); break;
    default: http_response_code(415); exit;
}

[$srcW, $srcH] = getimagesize($src);
$scale = min(1, $maxW / $srcW);
$dstW  = (int)($srcW * $scale);
$dstH  = (int)($srcH * $scale);

$thumb = imagecreatetruecolor($dstW, $dstH);
imagecopyresampled($thumb, $img, 0, 0, 0, 0, $dstW, $dstH, $srcW, $srcH);

if (!is_dir($thumbDir)) {
    mkdir($thumbDir, 0755, true);
}

imagejpeg($thumb, $thumbFile, 85);
imagedestroy($img);
imagedestroy($thumb);

header('Content-Type: image/jpeg');
readfile($thumbFile);
