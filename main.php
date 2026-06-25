<?php

/**
 * Plugin Name: WP Secure
 * Plugin URI: https://github.com/knyazevetc/wp-secure
 * Description: Two-factor authentication for WordPress login: email code or authenticator app (TOTP). Role selection, configurable security limits, and QR code for OTP setup.
 * Version: 2.0.0
 * Requires at least: 5.0
 * Requires PHP: 7.4
 * Author: knyazevetc
 * Author URI: https://github.com/knyazevetc
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-secure
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

define('WP_SECURE_VERSION', '2.0.0');
define('WP_SECURE_PLUGIN_FILE', __FILE__);
define('WP_SECURE_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('WP_SECURE_PLUGIN_URL', plugin_dir_url(__FILE__));

/**
 * PSR-4 autoloader for WpSecure namespace classes.
 *
 * @param string $class Fully qualified class name.
 *
 * @return void
 */
function wpSecureAutoload(string $class): void
{
    $prefix = 'WpSecure\\';
    $baseDir = WP_SECURE_PLUGIN_DIR . 'src/';

    if (strncmp($prefix, $class, strlen($prefix)) !== 0) {
        return;
    }

    $relativeClass = substr($class, strlen($prefix));
    $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

    if (file_exists($file)) {
        require $file;
    }
}

spl_autoload_register('wpSecureAutoload');

/**
 * Initialize the WP Secure plugin after WordPress loads.
 *
 * @return void
 */
function wpSecureInit(): void
{
    WpSecure\Plugin::getInstance()->boot();
}

add_action('plugins_loaded', 'wpSecureInit');
