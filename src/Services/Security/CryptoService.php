<?php

declare(strict_types=1);

namespace WpSecure\Services\Security;

use WpSecure\Constants\PluginConstants;

/**
 * Encrypts and decrypts sensitive plugin data using WordPress salts.
 */
final class CryptoService
{
    private const CIPHER_METHOD = 'aes-256-cbc';

    /**
     * Encrypt a plaintext value for storage.
     *
     * @param string $plaintext Value to encrypt.
     *
     * @return string
     */
    public function encrypt(string $plaintext): string
    {
        $key = $this->deriveKey();
        $iv = random_bytes(openssl_cipher_iv_length(self::CIPHER_METHOD));
        $ciphertext = openssl_encrypt($plaintext, self::CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv);

        if ($ciphertext === false) {
            return $plaintext;
        }

        return PluginConstants::ENCRYPTED_VALUE_PREFIX . base64_encode($iv . $ciphertext);
    }

    /**
     * Decrypt a stored value, supporting legacy plaintext entries.
     *
     * @param string $stored Stored ciphertext or legacy plaintext.
     *
     * @return string|null Returns null when decryption fails.
     */
    public function decrypt(string $stored): ?string
    {
        if (!str_starts_with($stored, PluginConstants::ENCRYPTED_VALUE_PREFIX)) {
            return $stored;
        }

        $payload = base64_decode(
            substr($stored, strlen(PluginConstants::ENCRYPTED_VALUE_PREFIX)),
            true
        );

        if ($payload === false) {
            return null;
        }

        $ivLength = openssl_cipher_iv_length(self::CIPHER_METHOD);
        $iv = substr($payload, 0, $ivLength);
        $ciphertext = substr($payload, $ivLength);
        $key = $this->deriveKey();
        $plaintext = openssl_decrypt($ciphertext, self::CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv);

        if ($plaintext === false) {
            return null;
        }

        return $plaintext;
    }

    /**
     * Hash a request fingerprint from IP address and user agent.
     *
     * @return string
     */
    public function hashFingerprint(): string
    {
        $ip = $this->getClientIp();
        $userAgent = isset($_SERVER['HTTP_USER_AGENT'])
            ? sanitize_text_field(wp_unslash((string) $_SERVER['HTTP_USER_AGENT']))
            : '';

        return hash_hmac('sha256', $ip . '|' . $userAgent, wp_salt('auth'));
    }

    /**
     * Derive a symmetric encryption key from WordPress salts.
     *
     * @return string
     */
    private function deriveKey(): string
    {
        return hash('sha256', wp_salt('secure_auth') . wp_salt('logged_in'), true);
    }

    /**
     * Resolve the client IP address from proxy-aware headers.
     *
     * @return string
     */
    public function getClientIp(): string
    {
        $candidates = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'REMOTE_ADDR',
        ];

        foreach ($candidates as $header) {
            if (!isset($_SERVER[$header])) {
                continue;
            }

            $value = sanitize_text_field(wp_unslash((string) $_SERVER[$header]));

            if ($header === 'HTTP_X_FORWARDED_FOR') {
                $parts = explode(',', $value);
                $value = trim($parts[0]);
            }

            if (filter_var($value, FILTER_VALIDATE_IP)) {
                return $value;
            }
        }

        return '0.0.0.0';
    }
}
