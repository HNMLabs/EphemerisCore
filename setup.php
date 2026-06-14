<?php
// Run once to create SQLite DB and seed demo users.
header('Content-Type: text/plain; charset=utf-8');

$dbPath = __DIR__ . DIRECTORY_SEPARATOR . 'auth.db';

try {
    if (!extension_loaded('pdo_sqlite')) {
        echo "Hata: pdo_sqlite eklentisi yuklu degil.\n";
        exit;
    }

    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $pdo->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        seal TEXT,
        device_code_hash TEXT,
        recovery_hash TEXT,
        created_at TEXT NOT NULL
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS device_seals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        seal TEXT NOT NULL,
        label TEXT,
        created_at TEXT NOT NULL
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        token TEXT NOT NULL,
        created_at TEXT NOT NULL
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS used_hashes (
        hash TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        ip TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT \'login\',
        created_at INTEGER NOT NULL
    )');

    $seed = [
        ['kullanici', 'sifre123'],
        ['admin', 'admin123']
    ];

    $stmt = $pdo->prepare('INSERT OR IGNORE INTO users (username, password, created_at) VALUES (:u, :p, :c)');
    foreach ($seed as $row) {
        $stmt->execute([
            ':u' => $row[0],
            ':p' => $row[1],
            ':c' => date('c')
        ]);
    }

    echo "DB hazir: auth.db\n";
    echo "Seed kullanicilar: kullanici / sifre123, admin / admin123\n";
} catch (Exception $e) {
    http_response_code(500);
    echo "DB kurulum hatasi.\n";
    echo "Detay: " . $e->getMessage();
}
