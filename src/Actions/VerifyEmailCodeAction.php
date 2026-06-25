<?php

declare(strict_types=1);

namespace WpSecure\Actions;

use WP_Error;
use WP_User;
use WpSecure\Services\Auth\ChallengeService;
use WpSecure\Services\Auth\EmailCodeService;
use WpSecure\Services\Security\RateLimitService;
use WpSecure\Services\Settings\SecuritySettingsService;

/**
 * Validates an email verification code submitted during login.
 */
final class VerifyEmailCodeAction
{
    private ChallengeService $challengeService;

    private RateLimitService $rateLimitService;

    private SecuritySettingsService $securitySettingsService;

    private EmailCodeService $emailCodeService;

    /**
     * @param ChallengeService|null $challengeService Challenge service dependency.
     * @param RateLimitService|null $rateLimitService Rate limit service dependency.
     * @param SecuritySettingsService|null $securitySettingsService Security settings dependency.
     * @param EmailCodeService|null $emailCodeService Email code service dependency.
     */
    public function __construct(
        ?ChallengeService $challengeService = null,
        ?RateLimitService $rateLimitService = null,
        ?SecuritySettingsService $securitySettingsService = null,
        ?EmailCodeService $emailCodeService = null
    ) {
        $this->challengeService = $challengeService ?? new ChallengeService();
        $this->rateLimitService = $rateLimitService ?? new RateLimitService();
        $this->securitySettingsService = $securitySettingsService ?? new SecuritySettingsService();
        $this->emailCodeService = $emailCodeService ?? new EmailCodeService();
    }

    /**
     * Verify the submitted email code and return the authenticated user.
     *
     * @param string $token Challenge token.
     * @param string $enteredCode Code entered by the user.
     *
     * @return WP_User|WP_Error
     */
    public function execute(string $token, string $enteredCode)
    {
        if ($this->rateLimitService->isIpVerificationBlocked()) {
            $this->challengeService->destroy($token);

            return new WP_Error(
                'rate_limit_exceeded',
                '<strong>Ошибка:</strong> Слишком много неудачных попыток. Попробуйте позже.'
            );
        }

        $challenge = $this->challengeService->get($token);

        if ($challenge === null || !$this->challengeService->hasActiveChallenge($token)) {
            $this->challengeService->destroy($token);

            return new WP_Error(
                'no_code',
                '<strong>Ошибка:</strong> Сессия истекла. Попробуйте войти снова.'
            );
        }

        if (!$this->challengeService->validateFingerprint($challenge)) {
            $this->challengeService->destroy($token);

            return new WP_Error(
                'session_invalid',
                '<strong>Ошибка:</strong> Недействительная сессия. Попробуйте войти снова.'
            );
        }

        if (!$this->emailCodeService->isValidFormat($enteredCode)) {
            return new WP_Error(
                'invalid_code_format',
                '<strong>Ошибка:</strong> Неверный формат кода. Введите код из письма целиком.'
            );
        }

        if (!$this->challengeService->verifyEmailCode($token, $enteredCode)) {
            $attempts = $this->challengeService->incrementAttempts($token);
            $this->rateLimitService->recordFailedVerification();

            if ($attempts >= $this->securitySettingsService->getMaxVerifyAttempts()) {
                $this->challengeService->destroy($token);

                return new WP_Error(
                    'too_many_attempts',
                    '<strong>Ошибка:</strong> Превышено число попыток. Войдите заново.'
                );
            }

            return new WP_Error(
                'invalid_code',
                '<strong>Ошибка:</strong> Неверный код подтверждения. Попробуйте еще раз.'
            );
        }

        $userId = $this->challengeService->getUserId($token);
        $this->challengeService->destroy($token);

        if ($userId === null) {
            return new WP_Error(
                'invalid_user',
                '<strong>Ошибка:</strong> Пользователь не найден.'
            );
        }

        $user = get_user_by('id', $userId);

        if (!$user instanceof WP_User) {
            return new WP_Error(
                'invalid_user',
                '<strong>Ошибка:</strong> Пользователь не найден.'
            );
        }

        return $user;
    }
}
