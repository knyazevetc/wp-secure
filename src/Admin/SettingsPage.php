<?php

declare(strict_types=1);

namespace WpSecure\Admin;

use WpSecure\Constants\PluginConstants;
use WpSecure\Services\Settings\PrimaryAdminService;
use WpSecure\Services\Settings\RoleSettingsService;
use WpSecure\Services\Settings\SecuritySettingsService;

/**
 * Renders the WP Secure global settings page for the primary administrator only.
 */
final class SettingsPage
{
    private PrimaryAdminService $primaryAdminService;

    private RoleSettingsService $roleSettingsService;

    private SecuritySettingsService $securitySettingsService;

    /**
     * @param PrimaryAdminService|null $primaryAdminService Primary admin service dependency.
     * @param RoleSettingsService|null $roleSettingsService Role settings dependency.
     * @param SecuritySettingsService|null $securitySettingsService Security settings dependency.
     */
    public function __construct(
        ?PrimaryAdminService $primaryAdminService = null,
        ?RoleSettingsService $roleSettingsService = null,
        ?SecuritySettingsService $securitySettingsService = null
    ) {
        $this->primaryAdminService = $primaryAdminService ?? new PrimaryAdminService();
        $this->roleSettingsService = $roleSettingsService ?? new RoleSettingsService();
        $this->securitySettingsService = $securitySettingsService ?? new SecuritySettingsService();
    }

    /**
     * Register the settings submenu page for the primary administrator.
     *
     * @return void
     */
    public function registerMenu(): void
    {
        if (!$this->primaryAdminService->isPrimaryAdmin()) {
            return;
        }

        add_options_page(
            'WP Secure',
            'WP Secure',
            'manage_options',
            PluginConstants::PAGE_SLUG_SETTINGS,
            [$this, 'renderPage']
        );
    }

    /**
     * Handle global settings form submissions.
     *
     * @return void
     */
    public function handleFormSubmission(): void
    {
        if (!isset($_POST['wp_secure_action'])) {
            return;
        }

        if (!$this->primaryAdminService->isPrimaryAdmin()) {
            return;
        }

        check_admin_referer('wp_secure_settings');

        $action = sanitize_text_field(wp_unslash((string) $_POST['wp_secure_action']));

        if ($action === 'save_roles') {
            $submittedRoles = isset($_POST['wp_secure_roles'])
                ? array_map('strval', (array) wp_unslash($_POST['wp_secure_roles']))
                : [];

            $this->roleSettingsService->saveEnabledRoles($submittedRoles);

            add_settings_error(
                'wp_secure',
                'roles_saved',
                'Настройки ролей сохранены.',
                'updated'
            );

            return;
        }

        if ($action === 'save_security') {
            $this->securitySettingsService->saveSettings([
                'max_verify_attempts' => $_POST['max_verify_attempts'] ?? null,
                'max_resend_attempts' => $_POST['max_resend_attempts'] ?? null,
                'resend_cooldown_seconds' => $_POST['resend_cooldown_seconds'] ?? null,
                'max_challenges_per_ip' => $_POST['max_challenges_per_ip'] ?? null,
                'ip_rate_window_seconds' => $_POST['ip_rate_window_seconds'] ?? null,
                'code_expiry_seconds' => $_POST['code_expiry_seconds'] ?? null,
            ]);

            add_settings_error(
                'wp_secure',
                'security_saved',
                'Настройки безопасности сохранены.',
                'updated'
            );
        }
    }

    /**
     * Render the global settings page markup.
     *
     * @return void
     */
    public function renderPage(): void
    {
        if (!$this->primaryAdminService->isPrimaryAdmin()) {
            wp_die(
                esc_html__('This page is available only to the primary site administrator (user ID 1).', 'wp-secure'),
                esc_html__('Access denied', 'wp-secure'),
                ['response' => 403]
            );
        }

        $enabledRoles = $this->roleSettingsService->getEnabledRoles();
        $availableRoles = $this->roleSettingsService->getAvailableRoles();
        $securitySettings = $this->securitySettingsService->getSettings();
        $authenticatorUrl = admin_url('options-general.php?page=' . PluginConstants::PAGE_SLUG_AUTHENTICATOR);
        $sessionsUrl = admin_url('options-general.php?page=' . PluginConstants::PAGE_SLUG_SESSIONS);
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <p>
                Глобальные настройки WP Secure. Доступно только главному администратору (user ID 1).
                OTP и аутентификатор настраиваются отдельно:
                <a href="<?php echo esc_url($authenticatorUrl); ?>">WP Secure OTP</a>.
                Управление сессиями:
                <a href="<?php echo esc_url($sessionsUrl); ?>">WP Secure Sessions</a>.
            </p>

            <div class="card" style="max-width: 720px; padding: 20px; margin-bottom: 20px;">
                <h2>Роли с двухфакторной аутентификацией</h2>
                <p>Выберите роли, для которых при входе будет требоваться подтверждение:</p>

                <form method="post">
                    <?php wp_nonce_field('wp_secure_settings'); ?>
                    <input type="hidden" name="wp_secure_action" value="save_roles">

                    <fieldset>
                        <legend class="screen-reader-text">Роли с 2FA</legend>
                        <?php foreach ($availableRoles as $roleSlug => $roleName) : ?>
                            <label style="display: block; margin-bottom: 8px;">
                                <input
                                    type="checkbox"
                                    name="wp_secure_roles[]"
                                    value="<?php echo esc_attr($roleSlug); ?>"
                                    <?php checked(in_array($roleSlug, $enabledRoles, true)); ?>
                                >
                                <?php echo esc_html($roleName); ?>
                                <code style="margin-left: 4px;"><?php echo esc_html($roleSlug); ?></code>
                            </label>
                        <?php endforeach; ?>
                    </fieldset>

                    <p class="description" style="margin-top: 12px;">
                        Пользователи выбранных ролей настраивают аутентификатор на странице
                        <a href="<?php echo esc_url($authenticatorUrl); ?>">WP Secure OTP</a>.
                    </p>

                    <?php submit_button('Сохранить роли', 'primary', 'submit', false); ?>
                </form>
            </div>

            <div class="card" style="max-width: 720px; padding: 20px;">
                <h2>Безопасность и лимиты</h2>
                <p>Настройте ограничения для защиты от перебора кодов и злоупотреблений:</p>

                <form method="post">
                    <?php wp_nonce_field('wp_secure_settings'); ?>
                    <input type="hidden" name="wp_secure_action" value="save_security">

                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row">
                                <label for="max_verify_attempts">Попыток ввода кода</label>
                            </th>
                            <td>
                                <input
                                    type="number"
                                    name="max_verify_attempts"
                                    id="max_verify_attempts"
                                    class="small-text"
                                    min="1"
                                    max="20"
                                    value="<?php echo esc_attr((string) $securitySettings['max_verify_attempts']); ?>"
                                    required
                                >
                                <p class="description">Максимум неудачных попыток ввода кода на одну сессию входа.</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="max_resend_attempts">Повторных отправок email</label>
                            </th>
                            <td>
                                <input
                                    type="number"
                                    name="max_resend_attempts"
                                    id="max_resend_attempts"
                                    class="small-text"
                                    min="0"
                                    max="10"
                                    value="<?php echo esc_attr((string) $securitySettings['max_resend_attempts']); ?>"
                                    required
                                >
                                <p class="description">Сколько раз можно запросить новый код на почту за одну попытку входа.</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="resend_cooldown_seconds">Пауза между resend (сек.)</label>
                            </th>
                            <td>
                                <input
                                    type="number"
                                    name="resend_cooldown_seconds"
                                    id="resend_cooldown_seconds"
                                    class="small-text"
                                    min="30"
                                    max="600"
                                    value="<?php echo esc_attr((string) $securitySettings['resend_cooldown_seconds']); ?>"
                                    required
                                >
                                <p class="description">Минимальный интервал между повторными отправками кода.</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="max_challenges_per_ip">Challenge с одного IP</label>
                            </th>
                            <td>
                                <input
                                    type="number"
                                    name="max_challenges_per_ip"
                                    id="max_challenges_per_ip"
                                    class="small-text"
                                    min="1"
                                    max="50"
                                    value="<?php echo esc_attr((string) $securitySettings['max_challenges_per_ip']); ?>"
                                    required
                                >
                                <p class="description">Сколько попыток входа с 2FA разрешено с одного IP за период ниже.</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="ip_rate_window_seconds">Окно лимита IP (сек.)</label>
                            </th>
                            <td>
                                <input
                                    type="number"
                                    name="ip_rate_window_seconds"
                                    id="ip_rate_window_seconds"
                                    class="small-text"
                                    min="300"
                                    max="3600"
                                    step="60"
                                    value="<?php echo esc_attr((string) $securitySettings['ip_rate_window_seconds']); ?>"
                                    required
                                >
                                <p class="description">
                                    Период для лимита challenge с IP.
                                    Сейчас: <?php echo esc_html((string) $this->securitySettingsService->getIpRateWindowMinutes()); ?> мин.
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="code_expiry_seconds">Срок действия кода (сек.)</label>
                            </th>
                            <td>
                                <input
                                    type="number"
                                    name="code_expiry_seconds"
                                    id="code_expiry_seconds"
                                    class="small-text"
                                    min="120"
                                    max="1800"
                                    step="60"
                                    value="<?php echo esc_attr((string) $securitySettings['code_expiry_seconds']); ?>"
                                    required
                                >
                                <p class="description">
                                    Время жизни кода с почты и сессии 2FA.
                                    Сейчас: <?php echo esc_html((string) $this->securitySettingsService->getCodeExpiryMinutes()); ?> мин.
                                </p>
                            </td>
                        </tr>
                    </table>

                    <?php submit_button('Сохранить лимиты', 'primary', 'submit', false); ?>
                </form>
            </div>
        </div>
        <?php
    }
}
