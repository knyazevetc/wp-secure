<?php

declare(strict_types=1);

namespace WpSecure\Admin;

use WpSecure\Constants\PluginConstants;
use WpSecure\Services\Auth\SessionRegistryService;
use WpSecure\Services\Settings\PrimaryAdminService;
use WpSecure\Services\Settings\RoleSettingsService;

/**
 * Renders the encrypted session management page for users with 2FA enabled.
 */
final class SessionsPage
{
    private PrimaryAdminService $primaryAdminService;

    private RoleSettingsService $roleSettingsService;

    private SessionRegistryService $sessionRegistryService;

    /**
     * @param PrimaryAdminService|null $primaryAdminService Primary admin service dependency.
     * @param RoleSettingsService|null $roleSettingsService Role settings dependency.
     * @param SessionRegistryService|null $sessionRegistryService Session registry dependency.
     */
    public function __construct(
        ?PrimaryAdminService $primaryAdminService = null,
        ?RoleSettingsService $roleSettingsService = null,
        ?SessionRegistryService $sessionRegistryService = null
    ) {
        $this->primaryAdminService = $primaryAdminService ?? new PrimaryAdminService();
        $this->roleSettingsService = $roleSettingsService ?? new RoleSettingsService();
        $this->sessionRegistryService = $sessionRegistryService ?? new SessionRegistryService();
    }

    /**
     * Register the sessions submenu page for users with 2FA enabled.
     *
     * @return void
     */
    public function registerMenu(): void
    {
        if (!$this->canAccessPage()) {
            return;
        }

        add_options_page(
            'WP Secure — Sessions',
            'WP Secure Sessions',
            'read',
            PluginConstants::PAGE_SLUG_SESSIONS,
            [$this, 'renderPage']
        );
    }

    /**
     * Handle session revocation form submissions.
     *
     * @return void
     */
    public function handleFormSubmission(): void
    {
        if (!isset($_POST['wp_secure_session_action'])) {
            return;
        }

        if (!$this->canAccessPage()) {
            return;
        }

        check_admin_referer(PluginConstants::NONCE_SESSIONS_ACTION);

        if ($this->isSessionActionRateLimited()) {
            add_settings_error(
                'wp_secure',
                'session_rate_limited',
                'Слишком много действий с сессиями. Подождите несколько минут.',
                'error'
            );

            return;
        }

        $this->recordSessionAction();

        $userId = get_current_user_id();
        $action = sanitize_text_field(wp_unslash((string) $_POST['wp_secure_session_action']));

        if ($action === 'revoke_session') {
            if (!isset($_POST['session_index'])) {
                add_settings_error(
                    'wp_secure',
                    'session_revoke_failed',
                    'Не удалось завершить выбранную сессию.',
                    'error'
                );

                return;
            }

            $sessionIndex = (int) wp_unslash((string) $_POST['session_index']);

            if (!$this->sessionRegistryService->destroyOtherSessionByIndex($userId, $sessionIndex)) {
                add_settings_error(
                    'wp_secure',
                    'session_revoke_failed',
                    'Не удалось завершить выбранную сессию.',
                    'error'
                );

                return;
            }

            add_settings_error(
                'wp_secure',
                'session_revoked',
                'Выбранная сессия завершена. Пользователь будет разлогинен при следующем запросе.',
                'updated'
            );

            return;
        }

        if ($action === 'revoke_other_sessions') {
            $destroyedCount = $this->sessionRegistryService->destroyOtherSessions($userId);

            if ($destroyedCount === 0) {
                add_settings_error(
                    'wp_secure',
                    'session_revoke_none',
                    'Других активных сессий не найдено.',
                    'updated'
                );

                return;
            }

            add_settings_error(
                'wp_secure',
                'sessions_revoked',
                sprintf(
                    'Завершено других сессий: %d. Эти устройства будут разлогинены при следующем запросе.',
                    $destroyedCount
                ),
                'updated'
            );
        }
    }

    /**
     * Register a session when WordPress sets the auth cookie.
     *
     * @param string $authCookie Authentication cookie value.
     * @param int $expire Cookie expiration timestamp.
     * @param int $expiration Session expiration timestamp.
     * @param int $userId WordPress user ID.
     * @param string $scheme Authentication scheme.
     * @param string $token WordPress session token.
     *
     * @return void
     */
    public function onAuthCookieSet(
        string $authCookie,
        int $expire,
        int $expiration,
        int $userId,
        string $scheme,
        string $token
    ): void {
        if ($userId <= 0 || $token === '') {
            return;
        }

        $user = get_user_by('id', $userId);

        if (!$user instanceof \WP_User || !$this->roleSettingsService->isTwoFactorRequired($user)) {
            return;
        }

        $this->sessionRegistryService->registerSession($userId, $token);
    }

    /**
     * Refresh the current session metadata during admin requests.
     *
     * @return void
     */
    public function touchCurrentSession(): void
    {
        if (!is_user_logged_in() || !is_admin()) {
            return;
        }

        if (!$this->canAccessPage()) {
            return;
        }

        $this->sessionRegistryService->touchCurrentSession(get_current_user_id());
    }

    /**
     * Render the session management page markup.
     *
     * @return void
     */
    public function renderPage(): void
    {
        if (!$this->canAccessPage()) {
            wp_die(
                esc_html__(
                    'This page is available only to users whose role requires two-factor authentication.',
                    'wp-secure'
                ),
                esc_html__('Access denied', 'wp-secure'),
                ['response' => 403]
            );
        }

        $userId = get_current_user_id();
        $groupedSessions = $this->sessionRegistryService->getGroupedSessionsForDisplay($userId);
        $currentSession = $groupedSessions['current'];
        $otherSessions = $groupedSessions['others'];
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <p>
                Активные входы в WordPress. IP, браузер и город хранятся в зашифрованном виде.
                Завершение сессии отключит доступ к админке на этом устройстве при следующем запросе.
            </p>

            <?php if ($this->primaryAdminService->isPrimaryAdmin()) : ?>
                <p class="description">
                    <?php
                    echo wp_kses(
                        sprintf(
                            'Глобальные настройки плагина доступны на странице %s.',
                            '<a href="' . esc_url(
                                admin_url('options-general.php?page=' . PluginConstants::PAGE_SLUG_SETTINGS)
                            ) . '">WP Secure</a>'
                        ),
                        ['a' => ['href' => []]]
                    );
                    ?>
                </p>
            <?php endif; ?>

            <?php if ($currentSession === null && $otherSessions === []) : ?>
                <div class="card" style="max-width: 960px; padding: 20px;">
                    <p>Активных сессий не найдено.</p>
                </div>
            <?php else : ?>
                <div class="card" style="max-width: 960px; padding: 20px;">
                    <?php if ($currentSession !== null) : ?>
                        <h2 style="margin-top: 0;">Текущая сессия</h2>
                        <?php $this->renderSessionsTable([$currentSession], false); ?>
                    <?php endif; ?>

                    <?php if ($otherSessions !== []) : ?>
                        <h2<?php echo $currentSession !== null ? '' : ' style="margin-top: 0;"'; ?>>Другие сессии</h2>
                        <?php $this->renderSessionsTable($otherSessions, true); ?>

                        <form method="post" style="margin-top: 20px;">
                            <?php wp_nonce_field(PluginConstants::NONCE_SESSIONS_ACTION); ?>
                            <input type="hidden" name="wp_secure_session_action" value="revoke_other_sessions">
                            <?php submit_button('Выйти на всех устройствах, кроме текущего', 'secondary', 'submit', false); ?>
                        </form>
                    <?php elseif ($currentSession === null) : ?>
                        <p>Активных сессий не найдено.</p>
                    <?php else : ?>
                        <h2>Другие сессии</h2>
                        <p>Других активных входов нет.</p>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * Render a sessions table with optional revoke actions.
     *
     * @param list<array<string, mixed>> $sessions Session rows.
     * @param bool $showRevokeButtons Whether to render per-row revoke buttons.
     *
     * @return void
     */
    private function renderSessionsTable(array $sessions, bool $showRevokeButtons): void
    {
        ?>
        <table class="widefat striped" style="max-width: 100%;">
            <thead>
                <tr>
                    <th>Устройство</th>
                    <th>Браузер</th>
                    <th>Город</th>
                    <th>Время входа</th>
                    <th>Последняя активность</th>
                    <th>IP-адрес</th>
                    <th>Действие</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($sessions as $sessionIndex => $session) : ?>
                    <tr>
                        <td><?php echo esc_html((string) $session['device']); ?></td>
                        <td><?php echo esc_html((string) $session['browser']); ?></td>
                        <td><?php echo esc_html((string) $session['city']); ?></td>
                        <td><?php echo esc_html($this->formatTimestamp((int) $session['login_at'])); ?></td>
                        <td><?php echo esc_html($this->formatTimestamp((int) $session['last_seen'])); ?></td>
                        <td><code><?php echo esc_html((string) $session['masked_ip']); ?></code></td>
                        <td>
                            <?php if ($showRevokeButtons) : ?>
                                <form method="post" style="display: inline;">
                                    <?php wp_nonce_field(PluginConstants::NONCE_SESSIONS_ACTION); ?>
                                    <input type="hidden" name="wp_secure_session_action" value="revoke_session">
                                    <input
                                        type="hidden"
                                        name="session_index"
                                        value="<?php echo esc_attr((string) $sessionIndex); ?>"
                                    >
                                    <?php submit_button('Выйти', 'delete', 'submit', false); ?>
                                </form>
                            <?php else : ?>
                                —
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php
    }

    /**
     * Check whether the current user may access the sessions page.
     *
     * @return bool
     */
    private function canAccessPage(): bool
    {
        if (!is_user_logged_in()) {
            return false;
        }

        $user = wp_get_current_user();

        if (!$user instanceof \WP_User) {
            return false;
        }

        return $this->roleSettingsService->isTwoFactorRequired($user);
    }

    /**
     * @param int $timestamp Unix timestamp.
     *
     * @return string
     */
    private function formatTimestamp(int $timestamp): string
    {
        if ($timestamp <= 0) {
            return '—';
        }

        return wp_date('Y-m-d H:i:s', $timestamp);
    }

    /**
     * @return bool
     */
    private function isSessionActionRateLimited(): bool
    {
        $key = PluginConstants::RATE_LIMIT_TRANSIENT_PREFIX
            . 'session_action_'
            . hash('sha256', (string) get_current_user_id());
        $count = (int) get_transient($key);

        return $count >= PluginConstants::SESSION_ACTION_RATE_LIMIT;
    }

    /**
     * @return void
     */
    private function recordSessionAction(): void
    {
        $key = PluginConstants::RATE_LIMIT_TRANSIENT_PREFIX
            . 'session_action_'
            . hash('sha256', (string) get_current_user_id());
        $count = (int) get_transient($key);
        set_transient(
            $key,
            $count + 1,
            PluginConstants::SESSION_ACTION_RATE_WINDOW_SECONDS
        );
    }
}
