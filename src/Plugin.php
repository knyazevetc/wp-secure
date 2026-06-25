<?php

declare(strict_types=1);

namespace WpSecure;

use WpSecure\Admin\AuthenticatorPage;
use WpSecure\Admin\SessionsPage;
use WpSecure\Admin\SettingsPage;
use WpSecure\Login\AuthenticationInterceptor;
use WpSecure\Login\LoginFormHandler;

/**
 * Main plugin bootstrap class.
 *
 * Registers hooks and wires together plugin components.
 */
final class Plugin
{
    private static ?self $instance = null;

    /**
     * Get the singleton plugin instance.
     *
     * @return self
     */
    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Register WordPress hooks for the plugin.
     *
     * @return void
     */
    public function boot(): void
    {
        $authenticationInterceptor = new AuthenticationInterceptor();
        $loginFormHandler = new LoginFormHandler();
        $settingsPage = new SettingsPage();
        $authenticatorPage = new AuthenticatorPage();
        $sessionsPage = new SessionsPage();

        add_filter('authenticate', [$authenticationInterceptor, 'intercept'], 30, 3);
        add_action('login_form', [$loginFormHandler, 'renderTwoFactorFields']);
        add_action('login_form', [$loginFormHandler, 'handleResendCode']);
        add_action('login_enqueue_scripts', [$loginFormHandler, 'enqueueAssets']);
        add_action('wp_logout', [$authenticationInterceptor, 'clearSession']);
        add_action('admin_menu', [$settingsPage, 'registerMenu']);
        add_action('admin_menu', [$authenticatorPage, 'registerMenu']);
        add_action('admin_menu', [$sessionsPage, 'registerMenu']);
        add_action('admin_init', [$settingsPage, 'handleFormSubmission']);
        add_action('admin_init', [$authenticatorPage, 'handleFormSubmission']);
        add_action('admin_init', [$sessionsPage, 'handleFormSubmission']);
        add_action('admin_init', [$sessionsPage, 'touchCurrentSession'], 5);
        add_action('set_auth_cookie', [$sessionsPage, 'onAuthCookieSet'], 10, 6);
    }
}
