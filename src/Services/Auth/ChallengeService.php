<?php

declare(strict_types=1);

namespace WpSecure\Services\Auth;

use WpSecure\Constants\PluginConstants;
use WpSecure\Services\Security\CryptoService;
use WpSecure\Services\Settings\SecuritySettingsService;

/**
 * Manages secure two-factor authentication challenges via WordPress transients.
 */
final class ChallengeService
{
    private CryptoService $cryptoService;

    private SecuritySettingsService $securitySettingsService;

    /**
     * @param CryptoService|null $cryptoService Crypto service dependency.
     * @param SecuritySettingsService|null $securitySettingsService Security settings dependency.
     */
    public function __construct(
        ?CryptoService $cryptoService = null,
        ?SecuritySettingsService $securitySettingsService = null
    ) {
        $this->cryptoService = $cryptoService ?? new CryptoService();
        $this->securitySettingsService = $securitySettingsService ?? new SecuritySettingsService();
    }

    /**
     * Create a new authentication challenge and issue a secure token.
     *
     * @param int $userId WordPress user ID.
     * @param string $emailCode Plaintext email verification code.
     * @param string $authMethod Active authentication method.
     *
     * @return string Challenge token for the client.
     */
    public function create(int $userId, string $emailCode, string $authMethod = PluginConstants::AUTH_METHOD_EMAIL): string
    {
        $token = bin2hex(random_bytes(32));
        $payload = [
            'user_id' => $userId,
            'code_hash' => wp_hash_password($emailCode),
            'fingerprint' => $this->cryptoService->hashFingerprint(),
            'attempts' => 0,
            'resend_count' => 0,
            'last_resend' => 0,
            'created' => time(),
            'auth_method' => $authMethod,
        ];

        set_transient(
            $this->buildTransientKey($token),
            $payload,
            $this->getCodeExpirySeconds()
        );

        $this->setChallengeCookie($token);

        return $token;
    }

    /**
     * Retrieve challenge data by token.
     *
     * @param string $token Challenge token.
     *
     * @return array<string, mixed>|null
     */
    public function get(string $token): ?array
    {
        if (!$this->isValidTokenFormat($token)) {
            return null;
        }

        $payload = get_transient($this->buildTransientKey($token));

        if (!is_array($payload)) {
            return null;
        }

        return $payload;
    }

    /**
     * Resolve the active challenge token from POST data or cookie.
     *
     * @return string
     */
    public function resolveToken(): string
    {
        if (isset($_POST['wp_secure_token'])) {
            $token = sanitize_text_field(wp_unslash((string) $_POST['wp_secure_token']));

            if ($this->isValidTokenFormat($token)) {
                return $token;
            }
        }

        if (isset($_COOKIE[PluginConstants::CHALLENGE_COOKIE_NAME])) {
            $token = sanitize_text_field(wp_unslash((string) $_COOKIE[PluginConstants::CHALLENGE_COOKIE_NAME]));

            if ($this->isValidTokenFormat($token)) {
                return $token;
            }
        }

        return '';
    }

    /**
     * Check whether a valid, non-expired challenge exists for the token.
     *
     * @param string $token Challenge token.
     *
     * @return bool
     */
    public function hasActiveChallenge(string $token): bool
    {
        $challenge = $this->get($token);

        if ($challenge === null) {
            return false;
        }

        $elapsed = time() - (int) ($challenge['created'] ?? 0);

        return $elapsed < $this->getCodeExpirySeconds();
    }

    /**
     * Validate the request fingerprint against the stored challenge.
     *
     * @param array<string, mixed> $challenge Challenge payload.
     *
     * @return bool
     */
    public function validateFingerprint(array $challenge): bool
    {
        $storedFingerprint = (string) ($challenge['fingerprint'] ?? '');

        if ($storedFingerprint === '') {
            return false;
        }

        return hash_equals($storedFingerprint, $this->cryptoService->hashFingerprint());
    }

    /**
     * Verify an email code against the stored challenge hash.
     *
     * @param string $token Challenge token.
     * @param string $enteredCode User-submitted code.
     *
     * @return bool
     */
    public function verifyEmailCode(string $token, string $enteredCode): bool
    {
        $challenge = $this->get($token);

        if ($challenge === null) {
            return false;
        }

        $codeHash = (string) ($challenge['code_hash'] ?? '');

        return $codeHash !== '' && wp_check_password($enteredCode, $codeHash);
    }

    /**
     * Increment failed verification attempts and refresh the transient TTL.
     *
     * @param string $token Challenge token.
     *
     * @return int Updated attempt count.
     */
    public function incrementAttempts(string $token): int
    {
        $challenge = $this->get($token);

        if ($challenge === null) {
            return $this->securitySettingsService->getMaxVerifyAttempts();
        }

        $challenge['attempts'] = (int) ($challenge['attempts'] ?? 0) + 1;
        $remainingTtl = max(
            1,
            $this->getCodeExpirySeconds() - (time() - (int) $challenge['created'])
        );

        set_transient($this->buildTransientKey($token), $challenge, $remainingTtl);

        return (int) $challenge['attempts'];
    }

    /**
     * Update the email verification code after a resend request.
     *
     * @param string $token Challenge token.
     * @param string $newCode New plaintext verification code.
     *
     * @return bool
     */
    public function rotateEmailCode(string $token, string $newCode): bool
    {
        $challenge = $this->get($token);

        if ($challenge === null) {
            return false;
        }

        $challenge['code_hash'] = wp_hash_password($newCode);
        $challenge['resend_count'] = (int) ($challenge['resend_count'] ?? 0) + 1;
        $challenge['last_resend'] = time();
        $challenge['attempts'] = 0;

        $remainingTtl = max(
            1,
            $this->getCodeExpirySeconds() - (time() - (int) $challenge['created'])
        );

        return set_transient($this->buildTransientKey($token), $challenge, $remainingTtl);
    }

    /**
     * Update the preferred authentication method for an active challenge.
     *
     * @param string $token Challenge token.
     * @param string $authMethod Authentication method identifier.
     *
     * @return bool
     */
    public function setAuthMethod(string $token, string $authMethod): bool
    {
        $challenge = $this->get($token);

        if ($challenge === null) {
            return false;
        }

        $challenge['auth_method'] = $authMethod;

        $remainingTtl = max(
            1,
            $this->getCodeExpirySeconds() - (time() - (int) $challenge['created'])
        );

        return set_transient($this->buildTransientKey($token), $challenge, $remainingTtl);
    }

    /**
     * Get the user ID associated with a challenge token.
     *
     * @param string $token Challenge token.
     *
     * @return int|null
     */
    public function getUserId(string $token): ?int
    {
        $challenge = $this->get($token);

        if ($challenge === null) {
            return null;
        }

        return (int) ($challenge['user_id'] ?? 0) ?: null;
    }

    /**
     * Get the active authentication method for a challenge.
     *
     * @param string $token Challenge token.
     *
     * @return string
     */
    public function getAuthMethod(string $token): string
    {
        $challenge = $this->get($token);

        if ($challenge === null) {
            return PluginConstants::AUTH_METHOD_EMAIL;
        }

        return (string) ($challenge['auth_method'] ?? PluginConstants::AUTH_METHOD_EMAIL);
    }

    /**
     * Destroy a challenge and clear its client cookie.
     *
     * @param string $token Challenge token.
     *
     * @return void
     */
    public function destroy(string $token): void
    {
        if ($this->isValidTokenFormat($token)) {
            delete_transient($this->buildTransientKey($token));
        }

        $this->clearChallengeCookie();
    }

    /**
     * Destroy the currently active challenge from cookie or POST data.
     *
     * @return void
     */
    public function destroyCurrent(): void
    {
        $token = $this->resolveToken();

        if ($token !== '') {
            $this->destroy($token);
        }
    }

    /**
     * Set the HttpOnly challenge cookie for the client.
     *
     * @param string $token Challenge token.
     *
     * @return void
     */
    private function setChallengeCookie(string $token): void
    {
        if (headers_sent()) {
            return;
        }

        setcookie(
            PluginConstants::CHALLENGE_COOKIE_NAME,
            $token,
            [
                'expires' => time() + $this->getCodeExpirySeconds(),
                'path' => COOKIEPATH ?: '/',
                'domain' => COOKIE_DOMAIN ?: '',
                'secure' => is_ssl(),
                'httponly' => true,
                'samesite' => 'Strict',
            ]
        );

        $_COOKIE[PluginConstants::CHALLENGE_COOKIE_NAME] = $token;
    }

    /**
     * Clear the challenge cookie from the client.
     *
     * @return void
     */
    private function clearChallengeCookie(): void
    {
        if (headers_sent()) {
            return;
        }

        setcookie(
            PluginConstants::CHALLENGE_COOKIE_NAME,
            '',
            [
                'expires' => time() - 3600,
                'path' => COOKIEPATH ?: '/',
                'domain' => COOKIE_DOMAIN ?: '',
                'secure' => is_ssl(),
                'httponly' => true,
                'samesite' => 'Strict',
            ]
        );

        unset($_COOKIE[PluginConstants::CHALLENGE_COOKIE_NAME]);
    }

    /**
     * Build the transient storage key for a challenge token.
     *
     * @param string $token Challenge token.
     *
     * @return string
     */
    private function buildTransientKey(string $token): string
    {
        return PluginConstants::CHALLENGE_TRANSIENT_PREFIX . hash('sha256', $token);
    }

    /**
     * Validate the challenge token format.
     *
     * @param string $token Challenge token.
     *
     * @return bool
     */
    private function isValidTokenFormat(string $token): bool
    {
        return (bool) preg_match('/^[a-f0-9]{64}$/', $token);
    }

    /**
     * Get the configured verification code expiry time in seconds.
     *
     * @return int
     */
    private function getCodeExpirySeconds(): int
    {
        return $this->securitySettingsService->getCodeExpirySeconds();
    }
}
