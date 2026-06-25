<?php

declare(strict_types=1);

namespace WpSecure\Admin;

use WpSecure\Constants\PluginConstants;
use WpSecure\Services\Settings\PrimaryAdminService;
use WpSecure\Services\Settings\RoleSettingsService;

/**
 * Renders the dedicated OTP / authenticator setup page for users with 2FA enabled.
 */
final class AuthenticatorPage
{
    private PrimaryAdminService $primaryAdminService;

    private RoleSettingsService $roleSettingsService;

    private TotpSetupSection $totpSetupSection;

    /**
     * @param PrimaryAdminService|null $primaryAdminService Primary admin service dependency.
     * @param RoleSettingsService|null $roleSettingsService Role settings dependency.
     * @param TotpSetupSection|null $totpSetupSection OTP setup section dependency.
     */
    public function __construct(
        ?PrimaryAdminService $primaryAdminService = null,
        ?RoleSettingsService $roleSettingsService = null,
        ?TotpSetupSection $totpSetupSection = null
    ) {
        $this->primaryAdminService = $primaryAdminService ?? new PrimaryAdminService();
        $this->roleSettingsService = $roleSettingsService ?? new RoleSettingsService();
        $this->totpSetupSection = $totpSetupSection ?? new TotpSetupSection();
    }

    /**
     * Register the authenticator submenu page for users with 2FA enabled.
     *
     * @return void
     */
    public function registerMenu(): void
    {
        if (!$this->canAccessPage()) {
            return;
        }

        add_options_page(
            'WP Secure — OTP / Authenticator',
            'WP Secure OTP',
            'read',
            PluginConstants::PAGE_SLUG_AUTHENTICATOR,
            [$this, 'renderPage']
        );
    }

    /**
     * Handle OTP form submissions on the authenticator page.
     *
     * @return void
     */
    public function handleFormSubmission(): void
    {
        if (!isset($_POST['wp_secure_action'])) {
            return;
        }

        if (!$this->canAccessPage()) {
            return;
        }

        check_admin_referer('wp_secure_settings');

        $action = sanitize_text_field(wp_unslash((string) $_POST['wp_secure_action']));
        $this->totpSetupSection->handleAction(get_current_user_id(), $action);
    }

    /**
     * Render the authenticator setup page markup.
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
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <p>
                <?php esc_html_e(
                    'Set up an authenticator app for two-factor sign-in. Available only if 2FA is enabled for your role.',
                    'wp-secure'
                ); ?>
                <a href="<?php echo esc_url(
                    admin_url('options-general.php?page=' . PluginConstants::PAGE_SLUG_SESSIONS)
                ); ?>"><?php esc_html_e('Manage active sessions', 'wp-secure'); ?></a>.
            </p>

            <?php if ($this->primaryAdminService->isPrimaryAdmin()) : ?>
                <p class="description">
                    <?php
                    echo wp_kses(
                        sprintf(
                            /* translators: %s: link to WP Secure settings page */
                            __('Global plugin settings are available only to the primary administrator on the %s page.', 'wp-secure'),
                            '<a href="' . esc_url(
                                admin_url('options-general.php?page=' . PluginConstants::PAGE_SLUG_SETTINGS)
                            ) . '">WP Secure</a>'
                        ),
                        ['a' => ['href' => []]]
                    );
                    ?>
                </p>
            <?php endif; ?>

            <div class="card" style="max-width: 720px; padding: 20px;">
                <h2><?php esc_html_e('OTP / Authenticator', 'wp-secure'); ?></h2>
                <?php $this->totpSetupSection->render($userId); ?>
            </div>
        </div>
        <?php
    }

    /**
     * Check whether the current user may access the authenticator page.
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
}
