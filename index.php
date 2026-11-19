<?php
declare(strict_types=1);

$projectRoot = __DIR__;
require_once $projectRoot . '/src/ApkSigner.php';

$signer = new ApkSigner([
    'jar_path'         => getenv('UBER_APK_SIGNER_JAR')
                            ?: $projectRoot . '/tools/uber-apk-signer.jar',
    'output_directory' => $projectRoot . '/data/signed',
    'max_upload_bytes' => 314572800,
    'timeout_seconds'  => 180,
    'file_ttl_seconds' => 3600,
]);

// ============================================================
// ANDROID API ENDPOINT — no CSRF, API key auth
// POST /api/sign   Header: X-Api-Key: howler_sign_2024
// ============================================================
$uri = strtok($_SERVER['REQUEST_URI'] ?? '/', '?');

if ($uri === '/api/sign') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'POST only']);
        exit;
    }

    $apiKey   = $_SERVER['HTTP_X_API_KEY'] ?? '';
    $validKey = getenv('API_KEY') ?: 'howler_sign_2024';

    if (!hash_equals($validKey, $apiKey)) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Invalid API key']);
        exit;
    }

    if (empty($_FILES['apk'])) {
        http_response_code(422);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'No APK file received']);
        exit;
    }

    try {
        $result = $signer->sign($_FILES['apk']);
        header('Content-Type: application/json');
        echo json_encode(['ok' => true, 'file' => $result]);
    } catch (Throwable $e) {
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => $e->getMessage()]);
    }
    exit;
}

// ============================================================
// WEB UI — original code (unchanged)
// ============================================================
session_start();

$signerReady = is_file(
    getenv('UBER_APK_SIGNER_JAR') ?: $projectRoot . '/tools/uber-apk-signer.jar'
);

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function jsonResponse(array $payload, int $statusCode = 200): never
{
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

if (isset($_GET['download'])) {
    $signer->streamDownload((string) $_GET['download']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfHeader = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $csrfForm   = $_POST['csrf_token'] ?? '';

    if (!hash_equals($_SESSION['csrf_token'],
            (string)($csrfHeader ?: $csrfForm))) {
        jsonResponse(['ok' => false,
            'message' => 'Session expired. Refresh and try again.'], 419);
    }

    if (!isset($_FILES['apk'])) {
        jsonResponse(['ok' => false,
            'message' => 'Choose an APK before signing.'], 422);
    }

    try {
        $result = $signer->sign($_FILES['apk']);
        jsonResponse(['ok' => true,
            'message' => 'APK signed successfully.',
            'file'    => $result]);
    } catch (InvalidArgumentException $e) {
        jsonResponse(['ok' => false, 'message' => $e->getMessage()], 422);
    } catch (RuntimeException $e) {
        $msg = $e->getMessage();
        error_log('[APK signer] ' . $msg);
        jsonResponse(['ok' => false,
            'message' => str_contains($msg, 'not installed')
                ? $msg
                : 'Signing failed. Check the APK.'], 500);
    }
}

$csrfToken = htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Howler APK Signer</title>
    <link rel="stylesheet" href="/public/assets/styles.css">
</head>
<body>
<main class="shell">
    <nav class="nav glass">
        <a class="brand" href="/">
            <span class="brand-mark">H</span>
            <span><strong>HOWLER</strong><small>APK SIGNER</small></span>
        </a>
        <div class="nav-status">
            <span class="status-dot"></span>
            <span><?= $signerReady ? 'READY' : 'SETUP NEEDED' ?></span>
        </div>
    </nav>

    <section class="hero">
        <h1>APK Signing<br><em>made easy.</em></h1>
    </section>

    <section class="workspace-grid">
        <div class="upload-card glass">
            <form id="sign-form" novalidate>
                <input type="hidden" name="csrf_token"
                       value="<?= $csrfToken ?>">
                <label class="dropzone" for="apk-input">
                    <input id="apk-input" name="apk" type="file"
                           accept=".apk" hidden>
                    <span class="drop-title">Drop APK here</span>
                    <span class="drop-subtitle">or browse</span>
                </label>
                <button class="primary-button" id="sign-button"
                        type="submit" disabled>Sign APK</button>
            </form>
            <p class="form-status" id="form-status"></p>
        </div>
    </section>
</main>
<script>
    window.REDLINE_CSRF = <?= json_encode($_SESSION['csrf_token']) ?>;
</script>
<script src="/public/assets/app.js"></script>
</body>
</html>