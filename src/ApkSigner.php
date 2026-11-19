<?php

declare(strict_types=1);

final class ApkSigner
{
    private string $javaBinary;
    private string $jarPath;
    private string $outputDirectory;
    private int $maxBytes;
    private int $timeoutSeconds;
    private int $fileTtlSeconds;

    public function __construct(array $config)
    {
        $this->javaBinary = (string) ($config['java_binary'] ?? 'java');
        $this->jarPath = (string) ($config['jar_path'] ?? dirname(__DIR__) . '/tools/uber-apk-signer.jar');
        $this->outputDirectory = (string) ($config['output_directory'] ?? dirname(__DIR__) . '/data/signed');
        $this->maxBytes = (int) ($config['max_upload_bytes'] ?? 314572800);
        $this->timeoutSeconds = (int) ($config['timeout_seconds'] ?? 180);
        $this->fileTtlSeconds = max(60, (int) ($config['file_ttl_seconds'] ?? 3600));
    }

    public function sign(array $upload): array
    {
        $this->validateUpload($upload);

        if (!is_file($this->jarPath)) {
            throw new RuntimeException(
                'Uber APK Signer is not installed yet. Put uber-apk-signer.jar in the tools folder '
                . 'or set UBER_APK_SIGNER_JAR.'
            );
        }

        if (!is_dir($this->outputDirectory) && !mkdir($this->outputDirectory, 0750, true) && !is_dir($this->outputDirectory)) {
            throw new RuntimeException('The signed APK output folder could not be created.');
        }

        $this->cleanupExpiredOutputs();

        $jobDirectory = sys_get_temp_dir() . '/redline-signer-' . bin2hex(random_bytes(8));
        $inputPath = $jobDirectory . '/input.apk';
        $signerOutput = $jobDirectory . '/signed';

        if (!mkdir($signerOutput, 0700, true) && !is_dir($signerOutput)) {
            throw new RuntimeException('A temporary signing workspace could not be created.');
        }

        try {
            if (!copy((string) $upload['tmp_name'], $inputPath)) {
                throw new RuntimeException('The uploaded APK could not be copied to the signing workspace.');
            }

            $command = $this->buildCommand($inputPath, $signerOutput);
            $result = $this->runCommand($command);

            if ($result['exit_code'] !== 0) {
                $details = trim($result['stderr'] ?: $result['stdout']);
                throw new RuntimeException(
                    'Uber APK Signer failed.'
                    . ($details !== '' ? ' ' . substr($details, -2000) : '')
                );
            }

            $signedPath = $this->findSignedApk($signerOutput);
            if ($signedPath === null) {
                throw new RuntimeException('The signer completed without producing a signed APK.');
            }

            $jobId = bin2hex(random_bytes(16));
            $fileName = 'signed_' . $jobId . '.apk';
            $destination = rtrim($this->outputDirectory, '/') . '/' . $fileName;

            if (!copy($signedPath, $destination)) {
                throw new RuntimeException('The signed APK could not be saved.');
            }

            chmod($destination, 0640);

            return [
                'id' => $jobId,
                'name' => $fileName,
                'size' => filesize($destination) ?: 0,
                'download_url' => '/?download=' . rawurlencode($jobId),
            ];
        } finally {
            $this->removeDirectory($jobDirectory);
        }
    }

    public function streamDownload(string $jobId): never
    {
        if (!preg_match('/^[a-f0-9]{32}$/', $jobId)) {
            http_response_code(404);
            exit('Signed APK not found.');
        }

        $path = rtrim($this->outputDirectory, '/') . '/signed_' . $jobId . '.apk';
        if (!is_file($path)) {
            http_response_code(404);
            exit('Signed APK not found.');
        }

        header('Content-Type: application/vnd.android.package-archive');
        header('Content-Length: ' . (string) filesize($path));
        header('Content-Disposition: attachment; filename="signed_' . $jobId . '.apk"');
        header('X-Content-Type-Options: nosniff');
        readfile($path);
        exit;
    }

    private function validateUpload(array $upload): void
    {
        if (($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            $message = match ((int) ($upload['error'] ?? UPLOAD_ERR_NO_FILE)) {
                UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'The APK is larger than the upload limit.',
                UPLOAD_ERR_PARTIAL => 'The APK upload was interrupted. Please try again.',
                default => 'Please select an APK file.',
            };
            throw new InvalidArgumentException($message);
        }

        $name = (string) ($upload['name'] ?? '');
        $temporaryPath = (string) ($upload['tmp_name'] ?? '');
        $size = (int) ($upload['size'] ?? 0);

        if (strtolower(pathinfo($name, PATHINFO_EXTENSION)) !== 'apk') {
            throw new InvalidArgumentException('Only .apk files are accepted.');
        }

        if ($size <= 0 || $size > $this->maxBytes || !is_uploaded_file($temporaryPath)) {
            throw new InvalidArgumentException('The APK is empty, too large, or was not uploaded safely.');
        }

        $mime = (new finfo(FILEINFO_MIME_TYPE))->file($temporaryPath);
        $header = file_get_contents($temporaryPath, false, null, 0, 4);
        $isZip = $header === "PK\x03\x04" || $header === "PK\x05\x06" || $header === "PK\x07\x08";

        if (!$isZip || !in_array($mime, ['application/zip', 'application/java-archive', 'application/octet-stream'], true)) {
            throw new InvalidArgumentException('The selected file does not look like a valid APK archive.');
        }
    }

    private function buildCommand(string $inputPath, string $outputDirectory): string
    {
        $arguments = [
            escapeshellarg($this->javaBinary),
            '-jar',
            escapeshellarg($this->jarPath),
            '--apks',
            escapeshellarg($inputPath),
            '--out',
            escapeshellarg($outputDirectory),
            '--allowResign',
        ];

        $optionalArguments = [
            '--ks' => getenv('APK_SIGNER_KEYSTORE') ?: '',
            '--ksAlias' => getenv('APK_SIGNER_KEY_ALIAS') ?: '',
            '--ksPass' => getenv('APK_SIGNER_KEYSTORE_PASSWORD') ?: '',
            '--ksKeyPass' => getenv('APK_SIGNER_KEY_PASSWORD') ?: '',
        ];

        foreach ($optionalArguments as $flag => $value) {
            if ($value !== '') {
                $arguments[] = $flag;
                $arguments[] = escapeshellarg($value);
            }
        }

        return implode(' ', $arguments);
    }

    private function runCommand(string $command): array
    {
        $pipes = [];
        $process = proc_open(
            $command,
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes
        );

        if (!is_resource($process)) {
            throw new RuntimeException('The Java signing process could not be started.');
        }

        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $startedAt = microtime(true);
        $stdout = '';
        $stderr = '';
        $exitCode = null;

        do {
            $stdout .= stream_get_contents($pipes[1]);
            $stderr .= stream_get_contents($pipes[2]);
            $status = proc_get_status($process);

            if ((microtime(true) - $startedAt) > $this->timeoutSeconds) {
                proc_terminate($process, 9);
                $stderr .= ' Signing timed out.';
                $exitCode = 124;
                break;
            }

            if (!$status['running']) {
                $exitCode = (int) $status['exitcode'];
                break;
            }

            usleep(100000);
        } while (true);

        $stdout .= stream_get_contents($pipes[1]);
        $stderr .= stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $closeExitCode = proc_close($process);

        return [
            // proc_close() may return -1 after proc_get_status() observes
            // process completion, so prefer the captured terminal status.
            'exit_code' => $exitCode !== null && $exitCode >= 0 ? $exitCode : $closeExitCode,
            'stdout' => $stdout,
            'stderr' => $stderr,
        ];
    }

    private function findSignedApk(string $directory): ?string
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && strtolower($file->getExtension()) === 'apk') {
                return $file->getPathname();
            }
        }

        return null;
    }

    private function removeDirectory(string $directory): void
    {
        if (!is_dir($directory)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $file) {
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }

        rmdir($directory);
    }

    private function cleanupExpiredOutputs(): void
    {
        $cutoff = time() - $this->fileTtlSeconds;
        $files = glob(rtrim($this->outputDirectory, '/') . '/signed_*.apk');

        if ($files === false) {
            return;
        }

        foreach ($files as $file) {
            if (is_file($file) && (filemtime($file) ?: time()) < $cutoff) {
                @unlink($file);
            }
        }
    }
}
