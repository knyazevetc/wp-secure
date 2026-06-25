<?php

declare(strict_types=1);

namespace WpSecure\Actions;

use WP_Error;
use WP_User;
use WpSecure\Services\Auth\ChallengeService;
use WpSecure\Services\Auth\TotpService;
use WpSecure\Services\Auth\UserTwoFactorService;
use WpSecure\Services\Security\RateLimitService;
use WpSecure\Services\Settings\SecuritySettingsService;

/**
 * Validates a TOTP code from an authenticator app during login.
 */
final class VerifyTotpAction
{
    private ChallengeService $challengeService;

    private TotpService $totpService;

    private UserTwoFactorService $userTwoFactorService;

    private RateLimitService $rateLimitService;

    private SecuritySettingsService $securitySettingsService;

    /**
     * @param ChallengeService|null $challengeService Challenge service dependency.
     * @param TotpService|null $totpService TOTP service dependency.
     * @param UserTwoFactorService|null $userTwoFactorService User settings dependency.
     * @param RateLimitService|null $rateLimitService Rate limit service dependency.
     * @param SecuritySettingsService|null $securitySettingsService Security settings dependency.
     */
    public function __construct(
        ?ChallengeService $challengeService = null,
        ?TotpService $totpService = null,
        ?UserTwoFactorService $userTwoFactorService = null,
        ?RateLimitService $rateLimitService = null,
        ?SecuritySettingsService $securitySettingsService = null
    ) {
        $this->challengeService = $challengeService ?? new ChallengeService();
        $this->totpService = $totpService ?? new TotpService();
        $this->userTwoFactorService = $userTwoFactorService ?? new UserTwoFactorService();
        $this->rateLimitService = $rateLimitService ?? new RateLimitService();
        $this->securitySettingsService = $securitySettingsService ?? new SecuritySettingsService();
    }

    /**
     * Verify the submitted TOTP code and return the authenticated user.
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

        $userId = $this->challengeService->getUserId($token);

        if ($userId === null || !$this->userTwoFactorService->canUseTotp($userId)) {
            return new WP_Error(
                'totp_not_configured',
                '<strong>Ошибка:</strong> Аутентификатор не настроен для этого аккаунта.'
            );
        }

        $secret = $this->userTwoFactorService->getTotpSecret($userId);

        if ($secret === null || !$this->totpService->verifyCode($secret, $enteredCode)) {
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
                'invalid_totp',
                '<strong>Ошибка:</strong> Неверный код из аутентификатора. Попробуйте еще раз.'
            );
        }

        $this->challengeService->destroy($token);

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
