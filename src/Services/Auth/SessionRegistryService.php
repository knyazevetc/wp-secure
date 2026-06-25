<?php

declare(strict_types=1);

namespace WpSecure\Services\Auth;

use WpSecure\Constants\PluginConstants;
use WpSecure\Services\Security\CryptoService;
use WpSecure\Services\Security\GeoLocationService;
use WpSecure\Services\Security\UserAgentParserService;
use WP_Session_Tokens;

/**
 * Encrypted registry of WordPress login sessions with remote revocation support.
 */
final class SessionRegistryService
{
    private CryptoService $cryptoService;

    private UserAgentParserService $userAgentParserService;

    private GeoLocationService $geoLocationService;

    /**
     * @param CryptoService|null $cryptoService Crypto service dependency.
     * @param UserAgentParserService|null $userAgentParserService User-Agent parser dependency.
     * @param GeoLocationService|null $geoLocationService Geolocation dependency.
     */
    public function __construct(
        ?CryptoService $cryptoService = null,
        ?UserAgentParserService $userAgentParserService = null,
        ?GeoLocationService $geoLocationService = null
    ) {
        $this->cryptoService = $cryptoService ?? new CryptoService();
        $this->userAgentParserService = $userAgentParserService ?? new UserAgentParserService();
        $this->geoLocationService = $geoLocationService ?? new GeoLocationService();
    }

    /**
     * Register or refresh a session after WordPress sets the auth cookie.
     *
     * @param int $userId WordPress user ID.
     * @param string $token WordPress session token.
     *
     * @return void
     */
    public function registerSession(int $userId, string $token): void
    {
        if ($userId <= 0 || $token === '') {
            return;
        }

        $registry = $this->loadRegistry($userId);
        $sessionId = $this->resolveSessionIdFromRawToken($token);
        $now = time();
        $ip = $this->cryptoService->getClientIp();
        $userAgent = $this->getCurrentUserAgent();

        if (!isset($registry[$sessionId])) {
            $registry[$sessionId] = $this->buildSessionEntry($ip, $userAgent, $now, $now);
            $registry[$sessionId]['raw_token'] = $this->encryptField($token);
        } else {
            $registry[$sessionId]['last_seen'] = $now;
            $registry[$sessionId]['ip'] = $this->encryptField($ip);
            $registry[$sessionId] = $this->enrichSessionEntry($registry[$sessionId], $ip, $userAgent);

            if (!isset($registry[$sessionId]['raw_token'])) {
                $registry[$sessionId]['raw_token'] = $this->encryptField($token);
            }
        }

        $this->saveRegistry($userId, $registry);
    }

    /**
     * Update last-seen timestamp for the current session in the admin area.
     *
     * @param int $userId WordPress user ID.
     *
     * @return void
     */
    public function touchCurrentSession(int $userId): void
    {
        if ($userId <= 0 || !is_admin()) {
            return;
        }

        $token = wp_get_session_token();

        if ($token === false || $token === '') {
            return;
        }

        $registry = $this->loadRegistry($userId);
        $sessionId = $this->resolveSessionIdFromRawToken($token);

        if (!isset($registry[$sessionId])) {
            $this->registerSession($userId, $token);

            return;
        }

        $ip = $this->cryptoService->getClientIp();
        $userAgent = $this->getCurrentUserAgent();
        $registry[$sessionId]['last_seen'] = time();
        $registry[$sessionId]['ip'] = $this->encryptField($ip);
        $registry[$sessionId] = $this->enrichSessionEntry($registry[$sessionId], $ip, $userAgent);
        $this->saveRegistry($userId, $registry);
    }

    /**
     * Synchronize encrypted registry with native WordPress session tokens.
     *
     * @param int $userId WordPress user ID.
     *
     * @return void
     */
    public function syncWithWordPress(int $userId): void
    {
        if ($userId <= 0) {
            return;
        }

        $manager = WP_Session_Tokens::get_instance($userId);
        $wpSessions = $manager->get_all();
        $registry = $this->loadRegistry($userId);
        $activeIds = [];

        foreach ($wpSessions as $verifier => $session) {
            if (!is_array($session)) {
                continue;
            }

            $sessionId = (string) $verifier;
            $activeIds[$sessionId] = true;
            $loginAt = isset($session['login']) ? (int) $session['login'] : time();
            $ip = isset($session['ip']) ? (string) $session['ip'] : '0.0.0.0';
            $ua = isset($session['ua']) ? (string) $session['ua'] : '';

            if (!isset($registry[$sessionId])) {
                $registry[$sessionId] = $this->buildSessionEntry($ip, $ua, $loginAt, $loginAt);

                continue;
            }

            if (!isset($registry[$sessionId]['login_at']) || $registry[$sessionId]['login_at'] <= 0) {
                $registry[$sessionId]['login_at'] = $loginAt;
            }

            $registry[$sessionId] = $this->enrichSessionEntry($registry[$sessionId], $ip, $ua);
        }

        foreach (array_keys($registry) as $sessionId) {
            if (!isset($activeIds[$sessionId])) {
                unset($registry[$sessionId]);
            }
        }

        $this->saveRegistry($userId, $registry);
    }

    /**
     * Return current and other sessions prepared for admin display.
     *
     * @param int $userId WordPress user ID.
     *
     * @return array{
     *     current: array<string, mixed>|null,
     *     others: list<array<string, mixed>>
     * }
     */
    public function getGroupedSessionsForDisplay(int $userId): array
    {
        $this->syncWithWordPress($userId);

        $rawToken = wp_get_session_token();

        if (is_string($rawToken) && $rawToken !== '') {
            $currentSessionId = $this->resolveSessionIdFromRawToken($rawToken);
            $registry = $this->loadRegistry($userId);

            if ($currentSessionId !== '' && !isset($registry[$currentSessionId])) {
                $this->registerSession($userId, $rawToken);
                $this->syncWithWordPress($userId);
            }
        }

        $currentSessionId = $this->resolveCurrentSessionId();
        $registry = $this->loadRegistry($userId);
        $sessions = $this->getAllSessionTokensFresh($userId);
        $current = null;
        $others = [];

        foreach ($sessions as $verifier => $session) {
            if (!is_array($session)) {
                continue;
            }

            $verifierKey = (string) $verifier;
            $entry = $registry[$verifierKey] ?? null;

            if (!is_array($entry)) {
                $loginAt = isset($session['login']) ? (int) $session['login'] : time();
                $ip = isset($session['ip']) ? (string) $session['ip'] : '0.0.0.0';
                $ua = isset($session['ua']) ? (string) $session['ua'] : '';
                $entry = $this->buildSessionEntry($ip, $ua, $loginAt, $loginAt);
            }

            $isCurrent = $currentSessionId !== '' && hash_equals($currentSessionId, $verifierKey);
            $row = $this->buildDisplayRow($verifierKey, $entry, $isCurrent);

            if ($isCurrent) {
                $current = $row;
            } else {
                $others[] = $row;
            }
        }

        usort(
            $others,
            static function (array $left, array $right): int {
                return $right['last_seen'] <=> $left['last_seen'];
            }
        );

        return [
            'current' => $current,
            'others' => $others,
        ];
    }

    /**
     * Destroy a single non-current session selected by its display row index.
     *
     * @param int $userId WordPress user ID.
     * @param int $otherIndex Zero-based index in the "other sessions" table.
     *
     * @return bool
     */
    public function destroyOtherSessionByIndex(int $userId, int $otherIndex): bool
    {
        if ($userId <= 0 || $otherIndex < 0) {
            return false;
        }

        $currentRawToken = wp_get_session_token();

        if (!is_string($currentRawToken) || $currentRawToken === '') {
            return false;
        }

        $this->syncWithWordPress($userId);

        $grouped = $this->getGroupedSessionsForDisplay($userId);

        if (!isset($grouped['others'][$otherIndex])) {
            return false;
        }

        $verifierToRemove = (string) $grouped['others'][$otherIndex]['session_id'];

        if ($verifierToRemove === '' || !$this->isValidSessionId($verifierToRemove)) {
            return false;
        }

        $registry = $this->loadRegistry($userId);
        $entry = $registry[$verifierToRemove] ?? null;

        if (is_array($entry) && isset($entry['raw_token'])) {
            $rawToken = $this->decryptField((string) $entry['raw_token']);

            if (is_string($rawToken) && $rawToken !== '') {
                WP_Session_Tokens::get_instance($userId)->destroy($rawToken);
                $this->clearSessionCaches($userId);

                if (!$this->sessionVerifierExists($userId, $verifierToRemove)) {
                    unset($registry[$verifierToRemove]);
                    $this->saveRegistry($userId, $registry);

                    return true;
                }
            }
        }

        if (!$this->destroySessionByVerifier($userId, $verifierToRemove)) {
            return false;
        }

        unset($registry[$verifierToRemove]);
        $this->saveRegistry($userId, $registry);

        return !$this->sessionVerifierExists($userId, $verifierToRemove);
    }

    /**
     * Destroy a single remote session by opaque session identifier.
     *
     * @param int $userId WordPress user ID.
     * @param string $sessionId Hashed session identifier from the registry.
     *
     * @return bool
     */
    public function destroySession(int $userId, string $sessionId): bool
    {
        if (!$this->isValidSessionId($sessionId)) {
            return false;
        }

        $this->syncWithWordPress($userId);

        $registry = $this->loadRegistry($userId);
        $entry = isset($registry[$sessionId]) && is_array($registry[$sessionId])
            ? $registry[$sessionId]
            : null;

        if (is_array($entry) && isset($entry['raw_token'])) {
            $rawToken = $this->decryptField((string) $entry['raw_token']);

            if (is_string($rawToken) && $rawToken !== '') {
                WP_Session_Tokens::get_instance($userId)->destroy($rawToken);
                unset($registry[$sessionId]);
                $this->saveRegistry($userId, $registry);
                $this->clearSessionCaches($userId);

                return !$this->sessionVerifierExists($userId, $sessionId);
            }
        }

        $verifier = $this->findVerifierInWordPressSessions($userId, $sessionId);

        if ($verifier === null && is_array($entry)) {
            $verifier = $this->findVerifierByRegistryEntry($userId, $entry);
        }

        if ($verifier === null) {
            return false;
        }

        if (!$this->destroySessionByVerifier($userId, $verifier)) {
            return false;
        }

        unset($registry[$sessionId]);

        if ($verifier !== $sessionId) {
            unset($registry[$verifier]);
        }

        $this->saveRegistry($userId, $registry);

        return !$this->sessionVerifierExists($userId, $verifier);
    }

    /**
     * Destroy all sessions except the current browser session.
     *
     * @param int $userId WordPress user ID.
     *
     * @return int Number of destroyed sessions.
     */
    public function destroyOtherSessions(int $userId): int
    {
        $currentToken = wp_get_session_token();

        if (!is_string($currentToken) || $currentToken === '') {
            return 0;
        }

        $manager = WP_Session_Tokens::get_instance($userId);
        $beforeCount = count($manager->get_all());
        $manager->destroy_others($currentToken);
        $afterCount = count($manager->get_all());
        $destroyedCount = max(0, $beforeCount - $afterCount);

        $this->syncWithWordPress($userId);

        return $destroyedCount;
    }

    /**
     * Mask the trailing part of an IP address for safe display.
     *
     * @param string $ip IP address.
     *
     * @return string
     */
    public function maskIp(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);

            if (count($parts) === 4) {
                return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.***';
            }
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $segments = explode(':', $ip);
            $visible = array_slice($segments, 0, max(1, count($segments) - 1));

            return implode(':', $visible) . ':****';
        }

        return '***';
    }

    /**
     * Resolve the WordPress session verifier for a raw cookie token.
     *
     * @param string $rawToken Raw session token from the auth cookie.
     *
     * @return string
     */
    public function resolveSessionIdFromRawToken(string $rawToken): string
    {
        return hash('sha256', $rawToken);
    }

    /**
     * Resolve the verifier for the current browser session.
     *
     * @return string
     */
    public function resolveCurrentSessionId(): string
    {
        $rawToken = wp_get_session_token();

        if (!is_string($rawToken) || $rawToken === '') {
            return '';
        }

        return $this->resolveSessionIdFromRawToken($rawToken);
    }

    /**
     * Validate an opaque session identifier from a form submission.
     *
     * @param string $sessionId Session identifier.
     *
     * @return bool
     */
    public function isValidSessionId(string $sessionId): bool
    {
        return (bool) preg_match('/^[a-f0-9]{64}$/', $sessionId);
    }

    /**
     * @param string $ip IP address.
     * @param string $userAgent Browser user agent string.
     * @param int $loginAt Login timestamp.
     * @param int $lastSeen Last activity timestamp.
     *
     * @return array<string, int|string>
     */
    private function buildSessionEntry(string $ip, string $userAgent, int $loginAt, int $lastSeen): array
    {
        $entry = [
            'login_at' => $loginAt,
            'ip' => $this->encryptField($ip),
            'ua_hash' => $this->hashUserAgent($userAgent),
            'last_seen' => $lastSeen,
        ];

        return $this->enrichSessionEntry($entry, $ip, $userAgent);
    }

    /**
     * @param array<string, int|string> $entry Session registry entry.
     * @param string $ip IP address.
     * @param string $userAgent Browser user agent string.
     *
     * @return array<string, int|string>
     */
    private function enrichSessionEntry(array $entry, string $ip, string $userAgent): array
    {
        if ($userAgent !== '') {
            $parsed = $this->userAgentParserService->parse($userAgent);
            $entry['device'] = $this->encryptField($parsed['device']);
            $entry['browser'] = $this->encryptField($parsed['browser']);
            $entry['ua_hash'] = $this->hashUserAgent($userAgent);
        } elseif (!isset($entry['device']) || !isset($entry['browser'])) {
            $entry['device'] = $this->encryptField('Неизвестное устройство');
            $entry['browser'] = $this->encryptField('Неизвестный браузер');
        }

        if (!isset($entry['city']) || $this->decryptField((string) ($entry['city'] ?? '')) === null) {
            $city = $this->geoLocationService->resolveCity($ip);

            if ($city !== null) {
                $entry['city'] = $this->encryptField($city);
            }
        }

        return $entry;
    }

    /**
     * @param string $sessionId Opaque session identifier.
     * @param array<string, int|string> $entry Session registry entry.
     * @param bool $isCurrent Whether this is the current browser session.
     *
     * @return array<string, mixed>
     */
    private function buildDisplayRow(string $sessionId, array $entry, bool $isCurrent): array
    {
        $ip = $this->decryptField(isset($entry['ip']) ? (string) $entry['ip'] : '') ?? '0.0.0.0';
        $device = $this->decryptField(isset($entry['device']) ? (string) $entry['device'] : '')
            ?? 'Неизвестное устройство';
        $browser = $this->decryptField(isset($entry['browser']) ? (string) $entry['browser'] : '')
            ?? 'Неизвестный браузер';
        $city = $this->decryptField(isset($entry['city']) ? (string) $entry['city'] : '')
            ?? 'Не определено';

        return [
            'session_id' => $sessionId,
            'login_at' => isset($entry['login_at']) ? (int) $entry['login_at'] : 0,
            'last_seen' => isset($entry['last_seen']) ? (int) $entry['last_seen'] : 0,
            'masked_ip' => $this->maskIp($ip),
            'device' => $device,
            'browser' => $browser,
            'city' => $city,
            'is_current' => $isCurrent,
        ];
    }

    /**
     * @return string
     */
    private function getCurrentUserAgent(): string
    {
        return isset($_SERVER['HTTP_USER_AGENT'])
            ? sanitize_text_field(wp_unslash((string) $_SERVER['HTTP_USER_AGENT']))
            : '';
    }

    /**
     * @param string $userAgent Browser user agent string.
     *
     * @return string
     */
    private function hashUserAgent(string $userAgent): string
    {
        return hash('sha256', $userAgent);
    }

    /**
     * @param string $value Plaintext value.
     *
     * @return string
     */
    private function encryptField(string $value): string
    {
        return $this->cryptoService->encrypt($value);
    }

    /**
     * @param string $value Encrypted or legacy plaintext value.
     *
     * @return string|null
     */
    private function decryptField(string $value): ?string
    {
        if ($value === '') {
            return null;
        }

        $decrypted = $this->cryptoService->decrypt($value);

        return is_string($decrypted) && $decrypted !== '' ? $decrypted : null;
    }

    /**
     * @param int $userId WordPress user ID.
     *
     * @return array<string, array<string, mixed>>
     */
    private function getAllSessionTokensFresh(int $userId): array
    {
        $this->clearSessionCaches($userId);

        $sessions = get_user_meta($userId, 'session_tokens', true);

        if (is_array($sessions) && $sessions !== []) {
            return $sessions;
        }

        $manager = WP_Session_Tokens::get_instance($userId);
        $activeSessions = $manager->get_all();

        return is_array($activeSessions) ? $activeSessions : [];
    }

    /**
     * @param int $userId WordPress user ID.
     * @param string $verifier Session verifier key.
     *
     * @return bool
     */
    private function sessionVerifierExists(int $userId, string $verifier): bool
    {
        $sessions = $this->getAllSessionTokensFresh($userId);

        foreach (array_keys($sessions) as $key) {
            if (hash_equals((string) $key, $verifier)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Remove a WordPress session by its stored verifier key.
     *
     * @param int $userId WordPress user ID.
     * @param string $verifier Session verifier from session_tokens meta.
     *
     * @return bool
     */
    private function destroySessionByVerifier(int $userId, string $verifier): bool
    {
        $sessions = $this->getAllSessionTokensFresh($userId);

        if ($sessions === []) {
            return false;
        }

        $matchedVerifier = null;

        foreach (array_keys($sessions) as $key) {
            if (hash_equals((string) $key, $verifier)) {
                $matchedVerifier = (string) $key;
                break;
            }
        }

        if ($matchedVerifier === null) {
            return false;
        }

        unset($sessions[$matchedVerifier]);

        $this->clearSessionCaches($userId);

        if ($sessions === []) {
            delete_user_meta($userId, 'session_tokens');
        } else {
            update_user_meta($userId, 'session_tokens', $sessions);
        }

        $this->clearSessionCaches($userId);

        return true;
    }

    /**
     * @param int $userId WordPress user ID.
     * @param string $sessionId Session verifier candidate.
     *
     * @return string|null
     */
    private function findVerifierInWordPressSessions(int $userId, string $sessionId): ?string
    {
        $this->clearSessionCaches($userId);

        $sessions = get_user_meta($userId, 'session_tokens', true);

        if (!is_array($sessions)) {
            return null;
        }

        if (array_key_exists($sessionId, $sessions)) {
            return $sessionId;
        }

        foreach (array_keys($sessions) as $key) {
            if (hash_equals((string) $key, $sessionId)) {
                return (string) $key;
            }
        }

        return null;
    }

    /**
     * @param int $userId WordPress user ID.
     * @param array<string, int|string> $entry Registry session entry.
     *
     * @return string|null
     */
    private function findVerifierByRegistryEntry(int $userId, array $entry): ?string
    {
        $targetLogin = isset($entry['login_at']) ? (int) $entry['login_at'] : 0;
        $targetIp = $this->decryptField(isset($entry['ip']) ? (string) $entry['ip'] : '');

        if ($targetLogin <= 0 || !is_string($targetIp) || $targetIp === '') {
            return null;
        }

        $this->clearSessionCaches($userId);
        $sessions = get_user_meta($userId, 'session_tokens', true);

        if (!is_array($sessions)) {
            return null;
        }

        foreach ($sessions as $verifier => $session) {
            if (!is_array($session)) {
                continue;
            }

            $login = isset($session['login']) ? (int) $session['login'] : 0;
            $ip = isset($session['ip']) ? (string) $session['ip'] : '';

            if ($login === $targetLogin && $ip === $targetIp) {
                return (string) $verifier;
            }
        }

        return null;
    }

    /**
     * @param int $userId WordPress user ID.
     *
     * @return void
     */
    private function clearSessionCaches(int $userId): void
    {
        wp_cache_delete($userId, 'user_meta');
        wp_cache_delete($userId, 'users');

        $user = get_userdata($userId);

        if ($user instanceof \WP_User) {
            clean_user_cache($user);
        }
    }

    /**
     * @param int $userId WordPress user ID.
     *
     * @return array<string, array<string, int|string>>
     */
    private function loadRegistry(int $userId): array
    {
        $stored = get_user_meta($userId, PluginConstants::USER_META_SESSIONS, true);

        if (!is_string($stored) || $stored === '') {
            return [];
        }

        $json = $this->cryptoService->decrypt($stored);

        if ($json === null || $json === '') {
            return [];
        }

        $decoded = json_decode($json, true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * @param int $userId WordPress user ID.
     * @param array<string, array<string, int|string>> $registry Session registry payload.
     *
     * @return void
     */
    private function saveRegistry(int $userId, array $registry): void
    {
        $encoded = wp_json_encode($registry);

        if (!is_string($encoded)) {
            return;
        }

        update_user_meta(
            $userId,
            PluginConstants::USER_META_SESSIONS,
            $this->cryptoService->encrypt($encoded)
        );
    }
}
