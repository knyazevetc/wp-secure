<?php

declare(strict_types=1);

namespace WpSecure\Services\Security;

use WpSecure\Constants\PluginConstants;
use WpSecure\Services\Settings\SecuritySettingsService;

/**
 * Tracks and enforces rate limits for login verification attempts.
 */
final class RateLimitService
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
     * Check whether an IP address exceeded challenge creation limits.
     *
     * @return bool
     */
    public function isIpChallengeLimitExceeded(): bool
    {
        $key = $this->buildIpKey('challenge');
        $count = (int) get_transient($key);

        return $count >= $this->securitySettingsService->getMaxChallengesPerIp();
    }

    /**
     * Record a new challenge creation attempt for the current IP.
     *
     * @return void
     */
    public function recordChallengeCreation(): void
    {
        $key = $this->buildIpKey('challenge');
        $count = (int) get_transient($key);
        set_transient(
            $key,
            $count + 1,
            $this->securitySettingsService->getIpRateWindowSeconds()
        );
    }

    /**
     * Check whether resending a verification code is allowed.
     *
     * @param int $resendCount Number of resends already performed.
     * @param int $lastResendTimestamp Unix timestamp of the last resend.
     *
     * @return bool
     */
    public function canResendCode(int $resendCount, int $lastResendTimestamp): bool
    {
        if ($resendCount >= $this->securitySettingsService->getMaxResendAttempts()) {
            return false;
        }

        if ($lastResendTimestamp === 0) {
            return true;
        }

        return (time() - $lastResendTimestamp) >= $this->securitySettingsService->getResendCooldownSeconds();
    }

    /**
     * Record a failed verification attempt for an IP address.
     *
     * @return void
     */
    public function recordFailedVerification(): void
    {
        $key = $this->buildIpKey('verify_fail');
        $count = (int) get_transient($key);
        set_transient(
            $key,
            $count + 1,
            $this->securitySettingsService->getIpRateWindowSeconds()
        );
    }

    /**
     * Check whether the current IP is temporarily blocked from verification.
     *
     * @return bool
     */
    public function isIpVerificationBlocked(): bool
    {
        $key = $this->buildIpKey('verify_fail');
        $count = (int) get_transient($key);

        return $count >= $this->securitySettingsService->getMaxVerifyAttempts() * 3;
    }

    /**
     * Build a transient key scoped to the current IP and action.
     *
     * @param string $action Rate limit action identifier.
     *
     * @return string
     */
    private function buildIpKey(string $action): string
    {
        $ipHash = hash('sha256', $this->cryptoService->getClientIp());

        return PluginConstants::RATE_LIMIT_TRANSIENT_PREFIX . $action . '_' . $ipHash;
    }
}
