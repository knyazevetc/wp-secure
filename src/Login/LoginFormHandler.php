<?php

declare(strict_types=1);

namespace WpSecure\Login;

use WpSecure\Constants\PluginConstants;
use WpSecure\Services\Auth\ChallengeService;
use WpSecure\Services\Auth\EmailCodeService;
use WpSecure\Services\Auth\UserTwoFactorService;
use WpSecure\Services\Security\RateLimitService;
use WpSecure\Services\Settings\SecuritySettingsService;

/**
 * Renders login form fields, handles resend requests, and enqueues login assets.
 */
final class LoginFormHandler
{
    private ChallengeService $challengeService;

    private EmailCodeService $emailCodeService;

    private UserTwoFactorService $userTwoFactorService;

    private RateLimitService $rateLimitService;

    private SecuritySettingsService $securitySettingsService;

    /**
     * @param ChallengeService|null $challengeService Challenge service dependency.
     * @param EmailCodeService|null $emailCodeService Email code service dependency.
     * @param UserTwoFactorService|null $userTwoFactorService User settings dependency.
     * @param RateLimitService|null $rateLimitService Rate limit service dependency.
     * @param SecuritySettingsService|null $securitySettingsService Security settings dependency.
     */
    public function __construct(
        ?ChallengeService $challengeService = null,
        ?EmailCodeService $emailCodeService = null,
        ?UserTwoFactorService $userTwoFactorService = null,
        ?RateLimitService $rateLimitService = null,
        ?SecuritySettingsService $securitySettingsService = null
    ) {
        $this->challengeService = $challengeService ?? new ChallengeService();
        $this->emailCodeService = $emailCodeService ?? new EmailCodeService();
        $this->userTwoFactorService = $userTwoFactorService ?? new UserTwoFactorService();
        $this->rateLimitService = $rateLimitService ?? new RateLimitService();
        $this->securitySettingsService = $securitySettingsService ?? new SecuritySettingsService();
    }

    /**
     * Render two-factor verification fields on the login form.
     *
     * @return void
     */
    public function renderTwoFactorFields(): void
    {
        $token = $this->challengeService->resolveToken();

        if ($token === '' || !$this->challengeService->hasActiveChallenge($token)) {
            return;
        }

        $challenge = $this->challengeService->get($token);

        if ($challenge === null || !$this->challengeService->validateFingerprint($challenge)) {
            $this->challengeService->destroy($token);

            return;
        }

        $userId = $this->challengeService->getUserId($token);
        $authMethod = $this->resolveAuthMethod($token);
        $canUseTotp = $userId !== null && $this->userTwoFactorService->canUseTotp($userId);
        $loginUrl = wp_login_url();
        $emailUrl = wp_nonce_url(
            add_query_arg('wp_secure_auth', PluginConstants::AUTH_METHOD_EMAIL, $loginUrl),
            PluginConstants::NONCE_VERIFY_ACTION,
            'wp_secure_nonce'
        );
        $totpUrl = wp_nonce_url(
            add_query_arg('wp_secure_auth', PluginConstants::AUTH_METHOD_TOTP, $loginUrl),
            PluginConstants::NONCE_VERIFY_ACTION,
            'wp_secure_nonce'
        );

        wp_nonce_field(PluginConstants::NONCE_VERIFY_ACTION, 'wp_secure_nonce');
        ?>
        <input type="hidden" name="wp_secure_token" value="<?php echo esc_attr($token); ?>">

        <div id="wp-secure-two-factor" class="wp-secure-two-factor">
            <?php if ($authMethod === PluginConstants::AUTH_METHOD_TOTP && $canUseTotp) : ?>
                <p>
                    <label for="totp_code">
                        <?php esc_html_e('Код из аутентификатора', 'wp-secure'); ?><br>
                        <input
                            type="text"
                            name="totp_code"
                            id="totp_code"
                            class="input wp-secure-code-input"
                            value=""
                            size="20"
                            autocomplete="one-time-code"
                            required="required"
                            pattern="[0-9]{6}"
                            maxlength="6"
                            placeholder="000000"
                            autofocus
                            inputmode="numeric"
                        >
                    </label>
                </p>
                <p class="verification-info">
                    <?php esc_html_e('Введите 6-значный код из приложения-аутентификатора.', 'wp-secure'); ?>
                </p>
            <?php else : ?>
                <p>
                    <label for="verification_code">
                        <?php esc_html_e('Код с почты', 'wp-secure'); ?><br>
                        <input
                            type="text"
                            name="verification_code"
                            id="verification_code"
                            class="input wp-secure-code-input wp-secure-code-input--email"
                            value=""
                            size="20"
                            autocomplete="one-time-code"
                            required="required"
                            minlength="<?php echo esc_attr((string) PluginConstants::CODE_LENGTH); ?>"
                            maxlength="<?php echo esc_attr((string) PluginConstants::CODE_LENGTH); ?>"
                            placeholder="Ab3#k9"
                            autofocus
                            spellcheck="false"
                            autocapitalize="off"
                        >
                    </label>
                </p>
                <p class="verification-info">
                    <?php
                    printf(
                        esc_html__(
                            'Код отправлен на вашу почту и действителен %d мин. Введите его целиком — буквы, цифры и символы, регистр важен.',
                            'wp-secure'
                        ),
                        $this->securitySettingsService->getCodeExpiryMinutes()
                    );
                    ?>
                </p>
                <?php
                $resendCount = (int) ($challenge['resend_count'] ?? 0);
                $lastResend = (int) ($challenge['last_resend'] ?? 0);

                if ($this->rateLimitService->canResendCode($resendCount, $lastResend)) :
                    $resendUrl = wp_nonce_url(
                        add_query_arg('resend_code', '1', $loginUrl),
                        PluginConstants::NONCE_RESEND_ACTION,
                        'wp_secure_nonce'
                    );
                    ?>
                    <p class="wp-secure-resend">
                        <a href="<?php echo esc_url($resendUrl); ?>">
                            <?php esc_html_e('Отправить код повторно', 'wp-secure'); ?>
                        </a>
                    </p>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($canUseTotp) : ?>
                <p class="wp-secure-alt-auth">
                    <a href="<?php echo esc_url($authMethod === PluginConstants::AUTH_METHOD_TOTP ? $emailUrl : $totpUrl); ?>">
                        <?php esc_html_e('Войти другим способом', 'wp-secure'); ?>
                    </a>
                </p>
            <?php endif; ?>
        </div>

        <style>
            #user_login,
            #user_pass,
            .user-pass-wrap,
            .forgetmenot {
                display: none !important;
            }
        </style>
        <script>
            (function () {
                var userLogin = document.getElementById('user_login');
                var userPass = document.getElementById('user_pass');

                if (userLogin) {
                    userLogin.removeAttribute('required');
                    userLogin.disabled = true;
                }

                if (userPass) {
                    userPass.removeAttribute('required');
                    userPass.disabled = true;
                }
            })();
        </script>
        <?php
    }

    /**
     * Handle a request to resend the email verification code.
     *
     * @return void
     */
    public function handleResendCode(): void
    {
        if (!isset($_GET['resend_code']) || $_GET['resend_code'] !== '1') {
            return;
        }

        $nonce = isset($_GET['wp_secure_nonce'])
            ? sanitize_text_field(wp_unslash((string) $_GET['wp_secure_nonce']))
            : '';

        if (!wp_verify_nonce($nonce, PluginConstants::NONCE_RESEND_ACTION)) {
            return;
        }

        $token = $this->challengeService->resolveToken();

        if ($token === '' || !$this->challengeService->hasActiveChallenge($token)) {
            return;
        }

        $challenge = $this->challengeService->get($token);

        if ($challenge === null || !$this->challengeService->validateFingerprint($challenge)) {
            $this->challengeService->destroy($token);

            return;
        }

        $resendCount = (int) ($challenge['resend_count'] ?? 0);
        $lastResend = (int) ($challenge['last_resend'] ?? 0);

        if (!$this->rateLimitService->canResendCode($resendCount, $lastResend)) {
            add_filter('login_message', static function (): string {
                return '<div id="login_error">Повторная отправка временно недоступна. Попробуйте позже.</div>';
            });

            return;
        }

        $userId = $this->challengeService->getUserId($token);

        if ($userId === null) {
            return;
        }

        $user = get_user_by('id', $userId);

        if (!$user) {
            return;
        }

        $code = $this->emailCodeService->generateCode();

        if (!$this->challengeService->rotateEmailCode($token, $code)) {
            return;
        }

        $this->emailCodeService->sendVerificationCode(
            $user->user_email,
            $code,
            $user->user_login
        );

        add_filter('login_message', static function (): string {
            return '<div id="login_error">Новый код отправлен на вашу почту.</div>';
        });
    }

    /**
     * Enqueue login page styles.
     *
     * @return void
     */
    public function enqueueAssets(): void
    {
        wp_enqueue_style(
            'wp-secure-login',
            WP_SECURE_PLUGIN_URL . 'assets/css/login.css',
            [],
            WP_SECURE_VERSION
        );

        wp_register_script('wp-secure-login', '', [], WP_SECURE_VERSION, true);
        wp_enqueue_script('wp-secure-login');
        wp_add_inline_script('wp-secure-login', $this->getBrandingScript());
    }

    /**
     * Insert the branding label immediately after the login form element.
     *
     * @return string
     */
    private function getBrandingScript(): string
    {
        return <<<'JS'
(function () {
    var form = document.getElementById('loginform');

    if (!form || document.getElementById('wp-secure-branding')) {
        return;
    }

    var branding = document.createElement('p');
    branding.id = 'wp-secure-branding';
    branding.className = 'wp-secure-branding';
    branding.textContent = 'Защищено wp-secure';
    form.insertAdjacentElement('afterend', branding);
})();
JS;
    }

    /**
     * Resolve the active authentication method for the login form.
     *
     * @param string $token Challenge token.
     *
     * @return string
     */
    private function resolveAuthMethod(string $token): string
    {
        if (
            isset($_GET['wp_secure_auth'])
            && isset($_GET['wp_secure_nonce'])
            && wp_verify_nonce(
                sanitize_text_field(wp_unslash((string) $_GET['wp_secure_nonce'])),
                PluginConstants::NONCE_VERIFY_ACTION
            )
        ) {
            $requestedMethod = sanitize_text_field(wp_unslash((string) $_GET['wp_secure_auth']));

            if ($requestedMethod === PluginConstants::AUTH_METHOD_TOTP) {
                $this->challengeService->setAuthMethod($token, PluginConstants::AUTH_METHOD_TOTP);

                return PluginConstants::AUTH_METHOD_TOTP;
            }

            if ($requestedMethod === PluginConstants::AUTH_METHOD_EMAIL) {
                $this->challengeService->setAuthMethod($token, PluginConstants::AUTH_METHOD_EMAIL);

                return PluginConstants::AUTH_METHOD_EMAIL;
            }
        }

        return $this->challengeService->getAuthMethod($token);
    }
}
