<?php

declare(strict_types=1);

namespace WpSecure\Services\Auth;

use WpSecure\Constants\PluginConstants;
use WpSecure\Services\Security\CryptoService;

/**
 * Manages per-user two-factor authentication settings stored in user meta.
 */
final class UserTwoFactorService
{
    private CryptoService $cryptoService;

    /**
     * @param CryptoService|null $cryptoService Crypto service dependency.
     */
    public function __construct(?CryptoService $cryptoService = null)
    {
        $this->cryptoService = $cryptoService ?? new CryptoService();
    }

    /**
     * Check whether TOTP is enabled for a user.
     *
     * @param int $userId WordPress user ID.
     *
     * @return bool
     */
    public function isTotpEnabled(int $userId): bool
    {
        return (bool) get_user_meta($userId, PluginConstants::USER_META_TOTP_ENABLED, true);
    }

    /**
     * Get the stored TOTP secret for a user.
     *
     * @param int $userId WordPress user ID.
     *
     * @return string|null
     */
    public function getTotpSecret(int $userId): ?string
    {
        $stored = get_user_meta($userId, PluginConstants::USER_META_TOTP_SECRET, true);

        if (!is_string($stored) || $stored === '') {
            return null;
        }

        $secret = $this->cryptoService->decrypt($stored);

        return $secret !== null && $secret !== '' ? $secret : null;
    }

    /**
     * Save a TOTP secret for a user without enabling it yet.
     *
     * @param int $userId WordPress user ID.
     * @param string $secret Base32-encoded secret.
     *
     * @return void
     */
    public function saveTotpSecret(int $userId, string $secret): void
    {
        update_user_meta(
            $userId,
            PluginConstants::USER_META_TOTP_SECRET,
            $this->cryptoService->encrypt($secret)
        );
        update_user_meta($userId, PluginConstants::USER_META_TOTP_ENABLED, '0');
    }

    /**
     * Enable TOTP for a user after successful verification.
     *
     * @param int $userId WordPress user ID.
     *
     * @return void
     */
    public function enableTotp(int $userId): void
    {
        update_user_meta($userId, PluginConstants::USER_META_TOTP_ENABLED, '1');
    }

    /**
     * Disable TOTP and remove the stored secret for a user.
     *
     * @param int $userId WordPress user ID.
     *
     * @return void
     */
    public function disableTotp(int $userId): void
    {
        delete_user_meta($userId, PluginConstants::USER_META_TOTP_SECRET);
        delete_user_meta($userId, PluginConstants::USER_META_TOTP_ENABLED);
    }

    /**
     * Check whether a user can authenticate with TOTP.
     *
     * @param int $userId WordPress user ID.
     *
     * @return bool
     */
    public function canUseTotp(int $userId): bool
    {
        return $this->isTotpEnabled($userId) && $this->getTotpSecret($userId) !== null;
    }
}
