<?php
// Planetary Distance-Based Auth (Prototype)
// NOT for production use. TLS required in real deployments.
//
// Auth model:
//  - Everyday login on an enrolled device: password + planet + PIN + device seal.
//  - First device bootstraps the account and is issued an 8-digit device code
//    and a recovery phrase (shown once).
//  - Additional devices require password + the 8-digit device code.
//  - Lost everything? The recovery phrase resets device access (and optionally
//    the password).

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// --- Security tunables ---------------------------------------------------
const TS_WINDOW       = 120;   // max allowed clock skew between client ts and server (seconds)
const REPLAY_TTL      = 600;   // how long a used login hash is remembered (seconds)
const SESSION_TTL     = 86400; // session token lifetime (seconds)
const MAX_FAILS       = 10;    // failed login attempts per username+ip within FAIL_WINDOW
const FAIL_WINDOW     = 300;
const MAX_CODE_FAILS  = 5;     // wrong device-code attempts before lockout
const CODE_WINDOW     = 900;
const MAX_REC_FAILS   = 5;     // wrong recovery attempts before lockout
const REC_WINDOW      = 3600;
const ATTEMPT_KEEP    = 3600;  // prune attempt rows older than this

// Only accept POST (allow CLI for tests/tooling).
if (php_sapi_name() !== 'cli' && ($_SERVER['REQUEST_METHOD'] ?? 'POST') !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'message' => 'Method not allowed.']);
    exit;
}

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);

if (!is_array($data)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'message' => 'Invalid request.']);
    exit;
}

$action = isset($data['action']) ? trim($data['action']) : '';
// Usernames are case-insensitive (matches client-side localStorage keys).
$username = isset($data['username']) ? strtolower(trim($data['username'])) : '';
$planet = isset($data['planet']) ? strtolower(trim($data['planet'])) : '';
$pin = isset($data['pin']) ? trim($data['pin']) : '';
$ts = isset($data['ts']) ? intval($data['ts']) : 0;
$hash = isset($data['hash']) ? strtolower(trim($data['hash'])) : '';
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'cli';
$now = time();

// SQLite user store (prototype)
$dbPath = __DIR__ . DIRECTORY_SEPARATOR . 'auth.db';
try {
    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'message' => 'Database connection error.']);
    exit;
}

// Ensure schema
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

// Lightweight migrations for databases created by older versions.
function ensureColumn(PDO $pdo, string $table, string $col, string $decl): void {
    $cols = $pdo->query("PRAGMA table_info($table)")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($cols as $c) {
        if (($c['name'] ?? '') === $col) {
            return;
        }
    }
    $pdo->exec("ALTER TABLE $table ADD COLUMN $col $decl");
}
ensureColumn($pdo, 'users', 'seal', 'TEXT');
ensureColumn($pdo, 'users', 'device_code_hash', 'TEXT');
ensureColumn($pdo, 'users', 'recovery_hash', 'TEXT');
ensureColumn($pdo, 'login_attempts', 'kind', "TEXT NOT NULL DEFAULT 'login'");

// One-time migration: copy a legacy single seal into device_seals.
$legacy = $pdo->query("SELECT username, seal FROM users WHERE seal IS NOT NULL AND seal != ''")->fetchAll(PDO::FETCH_ASSOC);
foreach ($legacy as $u) {
    $chk = $pdo->prepare('SELECT 1 FROM device_seals WHERE username = :u LIMIT 1');
    $chk->execute([':u' => $u['username']]);
    if (!$chk->fetch()) {
        $ins = $pdo->prepare('INSERT INTO device_seals (username, seal, label, created_at) VALUES (:u, :s, :l, :c)');
        $ins->execute([':u' => $u['username'], ':s' => $u['seal'], ':l' => 'legacy', ':c' => date('c')]);
    }
}

// Housekeeping: prune expired replay/attempt rows.
$stmt = $pdo->prepare('DELETE FROM used_hashes WHERE created_at < :t');
$stmt->execute([':t' => $now - REPLAY_TTL]);
$stmt = $pdo->prepare('DELETE FROM login_attempts WHERE created_at < :t');
$stmt->execute([':t' => $now - ATTEMPT_KEEP]);

// --- Helpers -------------------------------------------------------------
function jsonOut(int $code, array $payload): void {
    http_response_code($code);
    echo json_encode($payload);
    exit;
}

function hashSecret(string $s): string {
    $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
    return password_hash($s, $algo);
}

function verifySecret(string $s, ?string $hash): bool {
    return $hash !== null && $hash !== '' && password_verify($s, $hash);
}

function normalizePhrase(string $s): string {
    return preg_replace('/\s+/u', ' ', trim(mb_strtolower($s, 'UTF-8')));
}

function validSession(PDO $pdo, string $username, string $token): bool {
    if ($username === '' || $token === '') {
        return false;
    }
    $stmt = $pdo->prepare('SELECT created_at FROM sessions WHERE username = :u AND token = :t LIMIT 1');
    $stmt->execute([':u' => $username, ':t' => $token]);
    $sess = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$sess) {
        return false;
    }
    $created = strtotime($sess['created_at']);
    return $created !== false && (time() - $created) <= SESSION_TTL;
}

function countAttempts(PDO $pdo, string $u, string $ip, string $kind, int $since): int {
    $st = $pdo->prepare('SELECT COUNT(*) AS c FROM login_attempts WHERE username = :u AND ip = :i AND kind = :k AND created_at >= :t');
    $st->execute([':u' => $u, ':i' => $ip, ':k' => $kind, ':t' => $since]);
    return (int)($st->fetch(PDO::FETCH_ASSOC)['c'] ?? 0);
}

function recordAttempt(PDO $pdo, string $u, string $ip, string $kind, int $now): void {
    $st = $pdo->prepare('INSERT INTO login_attempts (username, ip, kind, created_at) VALUES (:u, :i, :k, :c)');
    $st->execute([':u' => $u, ':i' => $ip, ':k' => $kind, ':c' => $now]);
}

function clearAttempts(PDO $pdo, string $u, string $ip, string $kind): void {
    $st = $pdo->prepare('DELETE FROM login_attempts WHERE username = :u AND ip = :i AND kind = :k');
    $st->execute([':u' => $u, ':i' => $ip, ':k' => $kind]);
}

function userSeals(PDO $pdo, string $username): array {
    $st = $pdo->prepare('SELECT seal FROM device_seals WHERE username = :u');
    $st->execute([':u' => $username]);
    return $st->fetchAll(PDO::FETCH_COLUMN);
}

function issueSession(PDO $pdo, string $username, int $now): string {
    $token = bin2hex(random_bytes(16));
    $st = $pdo->prepare('INSERT INTO sessions (username, token, created_at) VALUES (:u, :t, :c)');
    $st->execute([':u' => $username, ':t' => $token, ':c' => date('c')]);
    return $token;
}

$PLANETS = [
    'mars' => ['name' => 'Mars', 'a' => 1.523679, 'e' => 0.0934, 'period' => 686.98, 'phase' => 0.6],
    'venus' => ['name' => 'Venus', 'a' => 0.723332, 'e' => 0.0068, 'period' => 224.70, 'phase' => 1.2],
    'jupiter' => ['name' => 'Jupiter', 'a' => 5.2044, 'e' => 0.0489, 'period' => 4332.59, 'phase' => 2.4],
    'saturn' => ['name' => 'Saturn', 'a' => 9.5826, 'e' => 0.0565, 'period' => 10759.22, 'phase' => 0.9]
];
$AU_KM = 149597870.7;
$J2000 = 946684800; // 2000-01-01 00:00:00 UTC

function planetDistanceKm($planetKey, $ts, $PLANETS, $AU_KM, $J2000) {
    $p = $PLANETS[$planetKey];
    $days = ($ts - $J2000) / 86400.0;
    $M = 2 * M_PI * ($days / $p['period']) + $p['phase'];
    $rPlanet = $p['a'] * (1 - $p['e'] * cos($M));

    $aE = 1.0000; $eE = 0.0167; $periodE = 365.256; $phaseE = 0.0;
    $ME = 2 * M_PI * ($days / $periodE) + $phaseE;
    $rEarth = $aE * (1 - $eE * cos($ME));

    $angle = abs($M - $ME);
    $dAU = sqrt($rEarth*$rEarth + $rPlanet*$rPlanet - 2*$rEarth*$rPlanet*cos($angle));
    return $dAU * $AU_KM;
}

function sha512hex($s) {
    return hash('sha512', $s);
}

// Validate the planet/pin/ts/hash credential, returning the matched seal,
// password-only flag, and distance. Used by login and authorize_device.
function checkCredential(string $pwd, array $seals, string $planet, string $pin, int $ts, string $hash, array $PLANETS, float $AU_KM, int $J2000): array {
    $matchedSeal = null;
    $pwOnly = false;
    $okDistance = 0.0;
    for ($dt = -2; $dt <= 2; $dt++) {
        $shiftedTs = ($ts + $dt) - intval($pin) * 60;
        $dist = planetDistanceKm($planet, $shiftedTs, $PLANETS, $AU_KM, $J2000);
        $distFixed = number_format($dist, 3, '.', '');
        foreach ($seals as $seal) {
            if (hash_equals(sha512hex($pwd . $distFixed . $seal), $hash)) {
                return ['seal' => $seal, 'pwOnly' => false, 'distance' => $dist];
            }
        }
        if (!$pwOnly && hash_equals(sha512hex($pwd . $distFixed), $hash)) {
            $pwOnly = true;
            $okDistance = $dist;
        }
    }
    return ['seal' => $matchedSeal, 'pwOnly' => $pwOnly, 'distance' => $okDistance];
}

// =======================================================================
// Actions
// =======================================================================

if ($action === 'verify_session') {
    $token = isset($data['token']) ? trim($data['token']) : '';
    if (validSession($pdo, $username, $token)) {
        jsonOut(200, ['ok' => true]);
    }
    jsonOut(401, ['ok' => false, 'message' => 'Invalid or expired session.']);
}

if ($action === 'register_user') {
    $password = isset($data['password']) ? $data['password'] : '';
    if ($username === '' || $password === '') {
        jsonOut(400, ['ok' => false, 'message' => 'Missing fields.']);
    }
    $stmt = $pdo->prepare('INSERT INTO users (username, password, created_at) VALUES (:u, :p, :c)');
    try {
        $stmt->execute([':u' => $username, ':p' => $password, ':c' => date('c')]);
        jsonOut(200, ['ok' => true, 'message' => 'Registration successful. Please login.']);
    } catch (Exception $e) {
        jsonOut(409, ['ok' => false, 'message' => 'User already exists.']);
    }
}

if ($action === 'enroll_device') {
    // First-device bootstrap. Requires a valid session (from the first login)
    // and that the user has no enrolled devices yet.
    $seal = isset($data['seal']) ? strtolower(trim($data['seal'])) : '';
    $token = isset($data['token']) ? trim($data['token']) : '';

    if ($username === '' || $seal === '' || $token === '') {
        jsonOut(400, ['ok' => false, 'message' => 'Missing fields.']);
    }
    if (!preg_match('/^[0-9a-f]{64}$/', $seal)) {
        jsonOut(400, ['ok' => false, 'message' => 'Invalid seal.']);
    }
    if (!validSession($pdo, $username, $token)) {
        jsonOut(403, ['ok' => false, 'message' => 'Invalid session.']);
    }

    $stmt = $pdo->prepare('SELECT id FROM users WHERE username = :u LIMIT 1');
    $stmt->execute([':u' => $username]);
    if (!$stmt->fetch()) {
        jsonOut(403, ['ok' => false, 'message' => 'User not found.']);
    }
    if (count(userSeals($pdo, $username)) > 0) {
        jsonOut(409, ['ok' => false, 'message' => 'Account already set up. Use your device code to add this device.']);
    }

    // Generate the 8-digit device code and a 6-word recovery phrase. These are
    // shown to the user once and only their argon2 hashes are stored.
    $code = str_pad((string)random_int(0, 99999999), 8, '0', STR_PAD_LEFT);
    $words = array_values(array_unique(require __DIR__ . '/wordlist.php'));
    $n = count($words);
    $picked = [];
    for ($i = 0; $i < 6; $i++) {
        $picked[] = $words[random_int(0, $n - 1)];
    }
    $phrase = implode(' ', $picked);

    $stmt = $pdo->prepare('UPDATE users SET seal = NULL, device_code_hash = :dc, recovery_hash = :rh WHERE username = :u');
    $stmt->execute([':dc' => hashSecret($code), ':rh' => hashSecret(normalizePhrase($phrase)), ':u' => $username]);

    $ins = $pdo->prepare('INSERT INTO device_seals (username, seal, label, created_at) VALUES (:u, :s, :l, :c)');
    $ins->execute([':u' => $username, ':s' => $seal, ':l' => 'first', ':c' => date('c')]);

    jsonOut(200, [
        'ok' => true,
        'message' => 'Device sealed.',
        'deviceCode' => $code,
        'recoveryPhrase' => $phrase
    ]);
}

if ($action === 'authorize_device') {
    // Add a subsequent device: requires password proof AND the 8-digit code.
    $code = isset($data['code']) ? preg_replace('/\s+/', '', (string)$data['code']) : '';
    $seal = isset($data['seal']) ? strtolower(trim($data['seal'])) : '';

    if ($username === '' || $planet === '' || $pin === '' || $ts <= 0 || $hash === '' || $code === '' || $seal === '') {
        jsonOut(400, ['ok' => false, 'message' => 'Missing fields.']);
    }
    if (!preg_match('/^[0-9a-f]{64}$/', $seal) || !preg_match('/^[0-9a-f]{128}$/', $hash) ||
        !preg_match('/^[0-9]{4}$/', $pin) || !preg_match('/^[0-9]{8}$/', $code) || !isset($PLANETS[$planet])) {
        jsonOut(400, ['ok' => false, 'message' => 'Invalid fields.']);
    }
    if (abs($now - $ts) > TS_WINDOW) {
        jsonOut(403, ['ok' => false, 'message' => 'Request expired. Check your clock and try again.']);
    }
    if (countAttempts($pdo, $username, $clientIp, 'device_code', $now - CODE_WINDOW) >= MAX_CODE_FAILS) {
        jsonOut(429, ['ok' => false, 'message' => 'Too many attempts. Try again later.']);
    }

    $stmt = $pdo->prepare('SELECT password, device_code_hash FROM users WHERE username = :u LIMIT 1');
    $stmt->execute([':u' => $username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        recordAttempt($pdo, $username, $clientIp, 'device_code', $now);
        jsonOut(403, ['ok' => false, 'message' => 'Authorization failed.']);
    }

    // Prove the password (password-only hash).
    $res = checkCredential($row['password'], [], $planet, $pin, $ts, $hash, $PLANETS, $AU_KM, $J2000);
    if (!$res['pwOnly']) {
        recordAttempt($pdo, $username, $clientIp, 'device_code', $now);
        jsonOut(403, ['ok' => false, 'message' => 'Authorization failed.']);
    }
    // Prove the device code.
    if (!verifySecret($code, $row['device_code_hash'])) {
        recordAttempt($pdo, $username, $clientIp, 'device_code', $now);
        jsonOut(403, ['ok' => false, 'message' => 'Invalid device code.']);
    }

    // Consume the proof hash (replay protection).
    try {
        $st = $pdo->prepare('INSERT INTO used_hashes (hash, created_at) VALUES (:h, :c)');
        $st->execute([':h' => $hash, ':c' => $now]);
    } catch (Exception $e) {
        jsonOut(403, ['ok' => false, 'message' => 'Replay detected.']);
    }

    $ins = $pdo->prepare('INSERT INTO device_seals (username, seal, label, created_at) VALUES (:u, :s, :l, :c)');
    $ins->execute([':u' => $username, ':s' => $seal, ':l' => 'added', ':c' => date('c')]);
    clearAttempts($pdo, $username, $clientIp, 'device_code');

    $token = issueSession($pdo, $username, $now);
    jsonOut(200, ['ok' => true, 'message' => 'Device authorized.', 'token' => $token, 'needsEnroll' => false]);
}

if ($action === 'recover') {
    // Recovery phrase resets device access and (optionally) the password.
    $phrase = isset($data['recovery']) ? (string)$data['recovery'] : '';
    $newPassword = isset($data['newPassword']) ? (string)$data['newPassword'] : '';

    if ($username === '' || $phrase === '') {
        jsonOut(400, ['ok' => false, 'message' => 'Missing fields.']);
    }
    if (countAttempts($pdo, $username, $clientIp, 'recovery', $now - REC_WINDOW) >= MAX_REC_FAILS) {
        jsonOut(429, ['ok' => false, 'message' => 'Too many attempts. Try again later.']);
    }

    $stmt = $pdo->prepare('SELECT recovery_hash FROM users WHERE username = :u LIMIT 1');
    $stmt->execute([':u' => $username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || !verifySecret(normalizePhrase($phrase), $row['recovery_hash'])) {
        recordAttempt($pdo, $username, $clientIp, 'recovery', $now);
        jsonOut(403, ['ok' => false, 'message' => 'Recovery failed.']);
    }

    // Reset device access so the user can bootstrap a fresh first device.
    $pdo->prepare('DELETE FROM device_seals WHERE username = :u')->execute([':u' => $username]);
    $pdo->prepare('DELETE FROM sessions WHERE username = :u')->execute([':u' => $username]);
    if ($newPassword !== '') {
        $pdo->prepare('UPDATE users SET password = :p WHERE username = :u')
            ->execute([':p' => $newPassword, ':u' => $username]);
    }
    // Invalidate the old device code/recovery; new ones are issued on re-enroll.
    $pdo->prepare('UPDATE users SET device_code_hash = NULL, recovery_hash = NULL WHERE username = :u')
        ->execute([':u' => $username]);
    clearAttempts($pdo, $username, $clientIp, 'recovery');

    $token = issueSession($pdo, $username, $now);
    jsonOut(200, ['ok' => true, 'message' => 'Recovery successful. Enroll this device.', 'token' => $token, 'needsEnroll' => true]);
}

// =======================================================================
// Main login
// =======================================================================

if ($username === '' || $planet === '' || $pin === '' || $ts <= 0 || $hash === '') {
    jsonOut(400, ['ok' => false, 'message' => 'Missing fields.']);
}
if (!preg_match('/^[0-9]{4}$/', $pin)) {
    jsonOut(400, ['ok' => false, 'message' => 'PIN must be exactly 4 digits.']);
}
if (!preg_match('/^[0-9a-f]{128}$/', $hash)) {
    jsonOut(400, ['ok' => false, 'message' => 'Invalid hash.']);
}
if (abs($now - $ts) > TS_WINDOW) {
    jsonOut(403, ['ok' => false, 'message' => 'Request expired. Check your clock and try again.']);
}
if (!isset($PLANETS[$planet])) {
    jsonOut(400, ['ok' => false, 'message' => 'Invalid planet.']);
}
if (countAttempts($pdo, $username, $clientIp, 'login', $now - FAIL_WINDOW) >= MAX_FAILS) {
    jsonOut(429, ['ok' => false, 'message' => 'Too many attempts. Try again later.']);
}

$stmt = $pdo->prepare('SELECT password FROM users WHERE username = :u LIMIT 1');
$stmt->execute([':u' => $username]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

function loginFailed(PDO $pdo, string $username, string $ip, int $now): void {
    recordAttempt($pdo, $username, $ip, 'login', $now);
    jsonOut(403, ['ok' => false, 'message' => 'Login failed']);
}

if (!$row) {
    loginFailed($pdo, $username, $clientIp, $now);
}

$pwd = $row['password'];
$seals = userSeals($pdo, $username);
$okPlanetName = $PLANETS[$planet]['name'];

$res = checkCredential($pwd, $seals, $planet, $pin, $ts, $hash, $PLANETS, $AU_KM, $J2000);

if ($res['seal'] === null && !$res['pwOnly']) {
    loginFailed($pdo, $username, $clientIp, $now);
}

// Correct password but no matching device seal.
if ($res['seal'] === null && $res['pwOnly'] && count($seals) > 0) {
    // Known account on a new/unrecognized device — require the device code.
    jsonOut(403, [
        'ok' => false,
        'needsDeviceAuth' => true,
        'message' => 'New device detected. Enter your 8-digit device code to authorize it.'
    ]);
}

// Successful login (enrolled device, or first-device bootstrap).
try {
    $st = $pdo->prepare('INSERT INTO used_hashes (hash, created_at) VALUES (:h, :c)');
    $st->execute([':h' => $hash, ':c' => $now]);
} catch (Exception $e) {
    jsonOut(403, ['ok' => false, 'message' => 'Replay detected.']);
}

clearAttempts($pdo, $username, $clientIp, 'login');
$token = issueSession($pdo, $username, $now);
$needsEnroll = ($res['seal'] === null); // pwOnly + zero seals => bootstrap first device
$msg = "Login successful: {$okPlanetName} is currently " . number_format($res['distance'], 3, '.', '') . " km away";
jsonOut(200, ['ok' => true, 'message' => $msg, 'token' => $token, 'needsEnroll' => $needsEnroll]);
