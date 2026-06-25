<?php

declare(strict_types=1);

namespace WpSecure\Login;

use WP_Error;
use WP_User;
use WpSecure\Actions\InitiateEmailChallengeAction;
use WpSecure\Actions\VerifyEmailCodeAction;
use WpSecure\Actions\VerifyTotpAction;
use WpSecure\Constants\PluginConstants;
use WpSecure\Services\Auth\ChallengeService;
use WpSecure\Services\Security\RateLimitService;
use WpSecure\Services\Settings\RoleSettingsService;

/**
 * Intercepts WordPress authentication to enforce two-factor verification.
 */
final class AuthenticationInterceptor
{
    private ChallengeService $challengeService;

    private RoleSettingsService $roleSettingsService;

    private RateLimitService $rateLimitService;

    private InitiateEmailChallengeAction $initiateEmailChallengeAction;

    private VerifyEmailCodeAction $verifyEmailCodeAction;

    private VerifyTotpAction $verifyTotpAction;

    /**
     * @param ChallengeService|null $challengeService Challenge service dependency.
     * @param RoleSettingsService|null $roleSettingsService Role settings dependency.
     * @param RateLimitService|null $rateLimitService Rate limit service dependency.
     * @param InitiateEmailChallengeAction|null $initiateEmailChallengeAction Email challenge action.
     * @param VerifyEmailCodeAction|null $verifyEmailCodeAction Email verification action.
     * @param VerifyTotpAction|null $verifyTotpAction TOTP verification action.
     */
    public function __construct(
        ?ChallengeService $challengeService = null,
        ?RoleSettingsService $roleSettingsService = null,
        ?RateLimitService $rateLimitService = null,
        ?InitiateEmailChallengeAction $initiateEmailChallengeAction = null,
        ?VerifyEmailCodeAction $verifyEmailCodeAction = null,
        ?VerifyTotpAction $verifyTotpAction = null
    ) {
        $this->challengeService = $challengeService ?? new ChallengeService();
        $this->roleSettingsService = $roleSettingsService ?? new RoleSettingsService();
        $this->rateLimitService = $rateLimitService ?? new RateLimitService();
        $this->initiateEmailChallengeAction = $initiateEmailChallengeAction ?? new InitiateEmailChallengeAction();
        $this->verifyEmailCodeAction = $verifyEmailCodeAction ?? new VerifyEmailCodeAction();
        $this->verifyTotpAction = $verifyTotpAction ?? new VerifyTotpAction();
    }

    /**
     * Intercept the WordPress authenticate filter and enforce 2FA for configured roles.
     *
     * @param WP_User|WP_Error|null $user Current authentication result.
     * @param string $username Submitted username.
     * @param string $password Submitted password.
     *
     * @return WP_User|WP_Error|null
     */
    public function intercept($user, string $username, string $password)
    {
        if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST') {
            return $user;
        }

        $token = $this->challengeService->resolveToken();

        if ($token !== '') {
            return $this->handleVerificationStep($token);
        }

        if ($user instanceof WP_Error) {
            return $user;
        }

        if ($user instanceof WP_User && !$this->roleSettingsService->isTwoFactorRequired($user)) {
            return $user;
        }

        if ($user instanceof WP_User) {
            if ($this->rateLimitService->isIpVerificationBlocked()) {
                return new WP_Error(
                    'rate_limit_exceeded',
                    '<strong>Ошибка:</strong> Слишком много неудачных попыток. Попробуйте позже.'
                );
            }

            $error = $this->initiateEmailChallengeAction->execute($user);

            return $error ?? $user;
        }

        return $user;
    }

    /**
     * Clear two-factor challenge data on logout.
     *
     * @return void
     */
    public function clearSession(): void
    {
        $this->challengeService->destroyCurrent();
    }

    /**
     * Handle the second authentication step with a verification code.
     *
     * @param string $token Challenge token.
     *
     * @return WP_User|WP_Error
     */
    private function handleVerificationStep(string $token)
    {
        $nonce = isset($_POST['wp_secure_nonce'])
            ? sanitize_text_field(wp_unslash((string) $_POST['wp_secure_nonce']))
            : '';

        if (!wp_verify_nonce($nonce, PluginConstants::NONCE_VERIFY_ACTION)) {
            $this->challengeService->destroy($token);

            return new WP_Error(
                'invalid_nonce',
                '<strong>Ошибка:</strong> Недействительный запрос. Попробуйте войти снова.'
            );
        }

        $verificationCode = isset($_POST['verification_code'])
            ? trim(wp_unslash((string) $_POST['verification_code']))
            : '';

        $totpCode = isset($_POST['totp_code'])
            ? sanitize_text_field(wp_unslash((string) $_POST['totp_code']))
            : '';

        if ($totpCode !== '') {
            return $this->verifyTotpAction->execute($token, $totpCode);
        }

        if ($verificationCode !== '') {
            return $this->verifyEmailCodeAction->execute($token, $verificationCode);
        }

        return new WP_Error(
            'verification_required',
            '<strong>Ошибка:</strong> Введите код подтверждения.'
        );
    }
}
