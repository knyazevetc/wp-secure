<?php

declare(strict_types=1);

namespace WpSecure\Actions;

use WP_Error;
use WP_User;
use WpSecure\Constants\PluginConstants;
use WpSecure\Services\Auth\ChallengeService;
use WpSecure\Services\Auth\EmailCodeService;
use WpSecure\Services\Security\RateLimitService;

/**
 * Starts the email-based two-factor authentication challenge.
 */
final class InitiateEmailChallengeAction
{
    private EmailCodeService $emailCodeService;

    private ChallengeService $challengeService;

    private RateLimitService $rateLimitService;

    /**
     * @param EmailCodeService|null $emailCodeService Email code service dependency.
     * @param ChallengeService|null $challengeService Challenge service dependency.
     * @param RateLimitService|null $rateLimitService Rate limit service dependency.
     */
    public function __construct(
        ?EmailCodeService $emailCodeService = null,
        ?ChallengeService $challengeService = null,
        ?RateLimitService $rateLimitService = null
    ) {
        $this->emailCodeService = $emailCodeService ?? new EmailCodeService();
        $this->challengeService = $challengeService ?? new ChallengeService();
        $this->rateLimitService = $rateLimitService ?? new RateLimitService();
    }

    /**
     * Generate and send an email verification code for the given user.
     *
     * @param WP_User $user Authenticated WordPress user.
     *
     * @return WP_Error|null Returns an error when the challenge cannot proceed.
     */
    public function execute(WP_User $user): ?WP_Error
    {
        if ($this->rateLimitService->isIpChallengeLimitExceeded()) {
            return new WP_Error(
                'rate_limit_exceeded',
                '<strong>Ошибка:</strong> Слишком много попыток входа. Попробуйте позже.'
            );
        }

        $code = $this->emailCodeService->generateCode();
        $this->challengeService->create($user->ID, $code, PluginConstants::AUTH_METHOD_EMAIL);
        $this->rateLimitService->recordChallengeCreation();

        $sent = $this->emailCodeService->sendVerificationCode(
            $user->user_email,
            $code,
            $user->user_login
        );

        if (!$sent) {
            $this->challengeService->destroyCurrent();

            return new WP_Error(
                'email_send_failed',
                '<strong>Ошибка:</strong> Не удалось отправить код подтверждения. Проверьте настройки почты.'
            );
        }

        return new WP_Error(
            'verification_required',
            sprintf(
                '<strong>Код подтверждения отправлен на email:</strong> %s<br>Введите код ниже.',
                esc_html($this->emailCodeService->maskEmail($user->user_email))
            )
        );
    }
}
