<?php

declare(strict_types=1);

namespace WpSecure\Admin;

use WpSecure\Services\Auth\TotpService;
use WpSecure\Services\Auth\UserTwoFactorService;

/**
 * Renders and handles OTP authenticator setup forms.
 */
final class TotpSetupSection
{
    private TotpService $totpService;

    private UserTwoFactorService $userTwoFactorService;

    /**
     * @param TotpService|null $totpService TOTP service dependency.
     * @param UserTwoFactorService|null $userTwoFactorService User settings dependency.
     */
    public function __construct(
        ?TotpService $totpService = null,
        ?UserTwoFactorService $userTwoFactorService = null
    ) {
        $this->totpService = $totpService ?? new TotpService();
        $this->userTwoFactorService = $userTwoFactorService ?? new UserTwoFactorService();
    }

    /**
     * Handle OTP-related form actions for a user.
     *
     * @param int $userId Target WordPress user ID.
     * @param string $action Form action identifier.
     *
     * @return void
     */
    public function handleAction(int $userId, string $action): void
    {
        if ($action === 'generate_secret') {
            $secret = $this->totpService->generateSecret();
            $this->userTwoFactorService->saveTotpSecret($userId, $secret);

            add_settings_error(
                'wp_secure',
                'secret_generated',
                'Новый секрет OTP создан. Отсканируйте QR-код или введите ключ вручную.',
                'updated'
            );

            return;
        }

        if ($action === 'enable_totp') {
            $secret = $this->userTwoFactorService->getTotpSecret($userId);
            $code = isset($_POST['totp_verify_code'])
                ? sanitize_text_field(wp_unslash((string) $_POST['totp_verify_code']))
                : '';

            if ($secret === null) {
                add_settings_error(
                    'wp_secure',
                    'no_secret',
                    'Сначала создайте OTP секрет.',
                    'error'
                );

                return;
            }

            if (!$this->totpService->verifyCode($secret, $code)) {
                add_settings_error(
                    'wp_secure',
                    'invalid_totp',
                    'Неверный код. Проверьте приложение-аутентификатор и попробуйте снова.',
                    'error'
                );

                return;
            }

            $this->userTwoFactorService->enableTotp($userId);

            add_settings_error(
                'wp_secure',
                'totp_enabled',
                'Аутентификатор успешно подключен.',
                'updated'
            );

            return;
        }

        if ($action === 'disable_totp') {
            $this->userTwoFactorService->disableTotp($userId);

            add_settings_error(
                'wp_secure',
                'totp_disabled',
                'Аутентификатор отключен.',
                'updated'
            );
        }
    }

    /**
     * Render OTP setup markup for a user.
     *
     * @param int $userId Target WordPress user ID.
     *
     * @return void
     */
    public function render(int $userId): void
    {
        $user = get_user_by('id', $userId);

        if (!$user) {
            return;
        }

        $secret = $this->userTwoFactorService->getTotpSecret($userId);
        $isEnabled = $this->userTwoFactorService->isTotpEnabled($userId);
        $issuer = get_bloginfo('name');
        $provisioningUri = $secret !== null
            ? $this->totpService->buildProvisioningUri($secret, $user->user_login, $issuer)
            : '';
        $qrCodeUrl = $provisioningUri !== ''
            ? $this->totpService->buildQrCodeUrl($provisioningUri)
            : '';

        if ($isEnabled) : ?>
            <p style="color: #008a20; font-weight: 600;">
                ✓ Аутентификатор подключен
            </p>
            <p>
                При входе вы можете использовать код из приложения
                (Google Authenticator, Microsoft Authenticator, Authy и др.)
                через ссылку «Войти другим способом».
            </p>
            <form method="post">
                <?php wp_nonce_field('wp_secure_settings'); ?>
                <input type="hidden" name="wp_secure_action" value="disable_totp">
                <?php submit_button('Отключить аутентификатор', 'delete', 'submit', false); ?>
            </form>
        <?php elseif ($secret !== null) : ?>
            <p>Отсканируйте QR-код в приложении-аутентификаторе или введите ключ вручную:</p>

            <p style="text-align: center;">
                <img
                    src="<?php echo esc_url($qrCodeUrl); ?>"
                    alt="QR-код для OTP"
                    width="200"
                    height="200"
                >
            </p>

            <p>
                <strong>Секретный ключ:</strong>
                <code style="font-size: 16px; letter-spacing: 2px;"><?php echo esc_html($secret); ?></code>
            </p>

            <p>Введите код из приложения, чтобы подтвердить настройку:</p>

            <form method="post" style="margin-bottom: 20px;">
                <?php wp_nonce_field('wp_secure_settings'); ?>
                <input type="hidden" name="wp_secure_action" value="enable_totp">
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">
                            <label for="totp_verify_code">Код из аутентификатора</label>
                        </th>
                        <td>
                            <input
                                type="text"
                                name="totp_verify_code"
                                id="totp_verify_code"
                                class="regular-text"
                                pattern="[0-9]{6}"
                                maxlength="6"
                                placeholder="000000"
                                required
                            >
                        </td>
                    </tr>
                </table>
                <?php submit_button('Подтвердить и включить', 'primary', 'submit', false); ?>
            </form>

            <form method="post">
                <?php wp_nonce_field('wp_secure_settings'); ?>
                <input type="hidden" name="wp_secure_action" value="generate_secret">
                <?php submit_button('Сгенерировать новый ключ', 'secondary', 'submit', false); ?>
            </form>
        <?php else : ?>
            <p>
                Создайте OTP-ключ и добавьте его в приложение-аутентификатор
                для альтернативного входа без ожидания письма.
            </p>
            <form method="post">
                <?php wp_nonce_field('wp_secure_settings'); ?>
                <input type="hidden" name="wp_secure_action" value="generate_secret">
                <?php submit_button('Создать OTP', 'primary', 'submit', false); ?>
            </form>
        <?php endif;
    }
}
