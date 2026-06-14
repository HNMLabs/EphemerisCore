<?php
// Debug tool. Allows overwriting a device seal — restricted to localhost only.
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
$seal = isset($_GET['seal']) ? strtolower(trim($_GET['seal'])) : '';

if ($username === '' || $seal === '') {
    echo "Usage: fix_seal.php?u=username&seal=64hex\n";
    exit;
}
if (!preg_match('/^[0-9a-f]{64}$/', $seal)) {
    echo "Invalid seal format\n";
    exit;
}

$chk = $pdo->prepare('SELECT id FROM users WHERE username = :u LIMIT 1');
$chk->execute([':u' => $username]);
if (!$chk->fetch()) {
    echo "User not found\n";
    exit;
}

$pdo->exec('CREATE TABLE IF NOT EXISTS device_seals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    seal TEXT NOT NULL,
    label TEXT,
    created_at TEXT NOT NULL
)');

$stmt = $pdo->prepare('INSERT INTO device_seals (username, seal, label, created_at) VALUES (:u, :s, :l, :c)');
$stmt->execute([':u' => $username, ':s' => $seal, ':l' => 'manual', ':c' => date('c')]);

echo "Device seal added for user: {$username}\n";
