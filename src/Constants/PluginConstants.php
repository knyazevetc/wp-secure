<?php

declare(strict_types=1);

namespace WpSecure\Constants;

/**
 * Shared constants for the WP Secure plugin.
 */
final class PluginConstants
{
    public const CODE_LENGTH = 6;

    /**
     * Characters used for email verification codes (digits, letters, symbols).
     *
     * Excludes ambiguous characters: 0, O, 1, l, I.
     */
    public const CODE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz!@#$%&*+-=?';

    public const TOTP_PERIOD = 30;

    public const TOTP_DIGITS = 6;

    public const TOTP_DISCREPANCY = 1;

    public const DEFAULT_MAX_VERIFY_ATTEMPTS = 5;

    public const DEFAULT_MAX_RESEND_ATTEMPTS = 3;

    public const DEFAULT_RESEND_COOLDOWN_SECONDS = 60;

    public const DEFAULT_MAX_CHALLENGES_PER_IP = 10;

    public const DEFAULT_IP_RATE_WINDOW_SECONDS = 900;

    public const DEFAULT_CODE_EXPIRY_SECONDS = 600;

    public const CHALLENGE_COOKIE_NAME = 'wp_secure_ch';

    public const CHALLENGE_TRANSIENT_PREFIX = 'wp_secure_ch_';

    public const RATE_LIMIT_TRANSIENT_PREFIX = 'wp_secure_rl_';

    public const NONCE_VERIFY_ACTION = 'wp_secure_verify';

    public const NONCE_RESEND_ACTION = 'wp_secure_resend';

    public const USER_META_TOTP_SECRET = 'wp_secure_totp_secret';

    public const USER_META_TOTP_ENABLED = 'wp_secure_totp_enabled';

    public const AUTH_METHOD_EMAIL = 'email';

    public const AUTH_METHOD_TOTP = 'totp';

    public const OPTION_ENABLED_ROLES = 'wp_secure_enabled_roles';

    public const OPTION_SECURITY_SETTINGS = 'wp_secure_security_settings';

    public const ENCRYPTED_VALUE_PREFIX = 'enc:';

    /**
     * Default roles that require two-factor authentication on login.
     *
     * @var list<string>
     */
    public const DEFAULT_ENABLED_ROLES = ['administrator'];

    public const PRIMARY_ADMIN_USER_ID = 1;

    public const PAGE_SLUG_SETTINGS = 'wp-secure';

    public const PAGE_SLUG_AUTHENTICATOR = 'wp-secure-authenticator';

    public const PAGE_SLUG_SESSIONS = 'wp-secure-sessions';

    public const USER_META_SESSIONS = 'wp_secure_sessions';

    public const NONCE_SESSIONS_ACTION = 'wp_secure_sessions';

    public const SESSION_ACTION_RATE_LIMIT = 20;

    public const SESSION_ACTION_RATE_WINDOW_SECONDS = 300;

    public const GEO_TRANSIENT_PREFIX = 'wp_secure_geo_';

    public const GEO_CACHE_SECONDS = 86400;
}
