<?php

declare(strict_types=1);

namespace WpSecure\Services\Settings;

use WpSecure\Constants\PluginConstants;

/**
 * Manages configurable security and rate-limit settings for the plugin.
 */
final class SecuritySettingsService
{
    /**
     * Get all security settings merged with defaults.
     *
     * @return array<string, int>
     */
    public function getSettings(): array
    {
        $stored = get_option(PluginConstants::OPTION_SECURITY_SETTINGS);

        if (!is_array($stored)) {
            return $this->getDefaults();
        }

        return $this->sanitize(array_merge($this->getDefaults(), $stored));
    }

    /**
     * Save security settings from admin form input.
     *
     * @param array<string, mixed> $input Raw submitted settings.
     *
     * @return void
     */
    public function saveSettings(array $input): void
    {
        update_option(
            PluginConstants::OPTION_SECURITY_SETTINGS,
            $this->sanitize($input)
        );
    }

    /**
     * Get the maximum number of verification code attempts per challenge.
     *
     * @return int
     */
    public function getMaxVerifyAttempts(): int
    {
        return $this->getSettings()['max_verify_attempts'];
    }

    /**
     * Get the maximum number of email code resend attempts per challenge.
     *
     * @return int
     */
    public function getMaxResendAttempts(): int
    {
        return $this->getSettings()['max_resend_attempts'];
    }

    /**
     * Get the cooldown between email code resend requests in seconds.
     *
     * @return int
     */
    public function getResendCooldownSeconds(): int
    {
        return $this->getSettings()['resend_cooldown_seconds'];
    }

    /**
     * Get the maximum number of login challenges allowed per IP address.
     *
     * @return int
     */
    public function getMaxChallengesPerIp(): int
    {
        return $this->getSettings()['max_challenges_per_ip'];
    }

    /**
     * Get the IP rate-limit window in seconds.
     *
     * @return int
     */
    public function getIpRateWindowSeconds(): int
    {
        return $this->getSettings()['ip_rate_window_seconds'];
    }

    /**
     * Get the verification code expiry time in seconds.
     *
     * @return int
     */
    public function getCodeExpirySeconds(): int
    {
        return $this->getSettings()['code_expiry_seconds'];
    }

    /**
     * Get the verification code expiry time in whole minutes for display.
     *
     * @return int
     */
    public function getCodeExpiryMinutes(): int
    {
        return (int) max(1, (int) ceil($this->getCodeExpirySeconds() / 60));
    }

    /**
     * Get the IP rate-limit window in whole minutes for display.
     *
     * @return int
     */
    public function getIpRateWindowMinutes(): int
    {
        return (int) max(1, (int) ceil($this->getIpRateWindowSeconds() / 60));
    }

    /**
     * Get default security settings.
     *
     * @return array<string, int>
     */
    private function getDefaults(): array
    {
        return [
            'max_verify_attempts' => PluginConstants::DEFAULT_MAX_VERIFY_ATTEMPTS,
            'max_resend_attempts' => PluginConstants::DEFAULT_MAX_RESEND_ATTEMPTS,
            'resend_cooldown_seconds' => PluginConstants::DEFAULT_RESEND_COOLDOWN_SECONDS,
            'max_challenges_per_ip' => PluginConstants::DEFAULT_MAX_CHALLENGES_PER_IP,
            'ip_rate_window_seconds' => PluginConstants::DEFAULT_IP_RATE_WINDOW_SECONDS,
            'code_expiry_seconds' => PluginConstants::DEFAULT_CODE_EXPIRY_SECONDS,
        ];
    }

    /**
     * Sanitize and clamp security settings to safe ranges.
     *
     * @param array<string, mixed> $input Raw settings input.
     *
     * @return array<string, int>
     */
    private function sanitize(array $input): array
    {
        return [
            'max_verify_attempts' => $this->clampInt(
                $input['max_verify_attempts'] ?? PluginConstants::DEFAULT_MAX_VERIFY_ATTEMPTS,
                1,
                20
            ),
            'max_resend_attempts' => $this->clampInt(
                $input['max_resend_attempts'] ?? PluginConstants::DEFAULT_MAX_RESEND_ATTEMPTS,
                0,
                10
            ),
            'resend_cooldown_seconds' => $this->clampInt(
                $input['resend_cooldown_seconds'] ?? PluginConstants::DEFAULT_RESEND_COOLDOWN_SECONDS,
                30,
                600
            ),
            'max_challenges_per_ip' => $this->clampInt(
                $input['max_challenges_per_ip'] ?? PluginConstants::DEFAULT_MAX_CHALLENGES_PER_IP,
                1,
                50
            ),
            'ip_rate_window_seconds' => $this->clampInt(
                $input['ip_rate_window_seconds'] ?? PluginConstants::DEFAULT_IP_RATE_WINDOW_SECONDS,
                300,
                3600
            ),
            'code_expiry_seconds' => $this->clampInt(
                $input['code_expiry_seconds'] ?? PluginConstants::DEFAULT_CODE_EXPIRY_SECONDS,
                120,
                1800
            ),
        ];
    }

    /**
     * Clamp an integer value to the given inclusive range.
     *
     * @param mixed $value Raw input value.
     * @param int $min Minimum allowed value.
     * @param int $max Maximum allowed value.
     *
     * @return int
     */
    private function clampInt(mixed $value, int $min, int $max): int
    {
        $intValue = (int) $value;

        return max($min, min($max, $intValue));
    }
}
