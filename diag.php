<?php
// Debug tool. Discloses user/seal status — restricted to localhost only.
header('Content-Type: text/plain; charset=utf-8');

$remote = $_SERVER['REMOTE_ADDR'] ?? '';
if (php_sapi_name() !== 'cli' && !in_array($remote, ['127.0.0.1', '::1'], true)) {
    http_response_code(403);
    echo "Forbidden\n";
    exit;
}

$dbPath = __DIR__ . DIRECTORY_SEPARATOR . 'auth.db';
try {
    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    echo "DB error\n";
    exit;
}

$username = isset($_GET['u']) ? trim($_GET['u']) : '';
if ($username === '') {
    echo "Usage: diag.php?u=username\n";
    exit;
}

$stmt = $pdo->prepare('SELECT username, device_code_hash, recovery_hash, created_at FROM users WHERE username = :u LIMIT 1');
$stmt->execute([':u' => $username]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$row) {
    echo "User not found\n";
    exit;
}

$stmt = $pdo->prepare('SELECT COUNT(*) AS c FROM device_seals WHERE username = :u');
$stmt->execute([':u' => $username]);
$deviceCount = (int)($stmt->fetch(PDO::FETCH_ASSOC)['c'] ?? 0);

$codeStatus = ($row['device_code_hash'] === null || $row['device_code_hash'] === '') ? 'UNSET' : 'SET';
$recStatus = ($row['recovery_hash'] === null || $row['recovery_hash'] === '') ? 'UNSET' : 'SET';

echo "username: " . $row['username'] . "\n";
echo "password: (stored)\n";
echo "enrolled_devices: " . $deviceCount . "\n";
echo "device_code: " . $codeStatus . "\n";
echo "recovery_phrase: " . $recStatus . "\n";
echo "created_at: " . $row['created_at'] . "\n";
