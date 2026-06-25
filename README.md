
<div align="center">

# WP Secure

![WordPress](https://img.shields.io/badge/WordPress-5.0+-21759B?style=for-the-badge&logo=wordpress&logoColor=white)
![PHP](https://img.shields.io/badge/PHP-7.4+-777BB4?style=for-the-badge&logo=php&logoColor=white)
![Version](https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-GPL%20v2-blue?style=for-the-badge)

**Two-factor authentication for WordPress login — email code or authenticator app**

[Features](#features) • [Installation](#installation) • [How It Works](#how-it-works) • [Admin Pages](#admin-pages) • [Configuration](#configuration) • [Security](#security) • [Changelog](#what-changed-since-v10)

**Repository:** [github.com/knyazevetc/wp-secure](https://github.com/knyazevetc/wp-secure) · **Author:** [knyazevetc](https://github.com/knyazevetc)

</div>

---

## Description

**WP Secure** is a two-factor authentication (2FA) plugin for the WordPress login page. After entering a username and password, the user must confirm sign-in with an email code or an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, etc.).

Global settings are managed by the primary site administrator (user ID 1). OTP setup lives on a separate admin page for users whose roles require 2FA.

---

## Features

- **Email code** — 6-character code (letters, digits, symbols) sent via `wp_mail()`
- **TOTP / authenticator** — QR code setup on a dedicated admin page
- **Role selection** — enable 2FA for administrator, editor, author, and any other role
- **"Sign in another way"** — switch between email and authenticator on the login page
- **Configurable security limits** — code attempts, resend limits, IP challenges, code expiry (admin UI)
- **Brute-force protection** — rate limiting, nonces, session binding to IP and User-Agent
- **Encrypted TOTP secrets** — AES-256-CBC using WordPress salts
- **Secure challenges** — cryptographic tokens in HttpOnly cookies; password is never stored
- **Session management** — encrypted login session registry with remote logout (Settings → WP Secure Sessions)
- **Login branding** — "Защищено wp-secure" label placed directly under the login form

---

## Requirements

| Component | Version |
|-----------|---------|
| WordPress | **5.0+** |
| PHP | **7.4+** (OpenSSL extension) |
| Mail | Configured `wp_mail()` for email-based 2FA |

---

## Installation

1. Upload the `wp-secure-main` folder to `wp-content/plugins/`
2. Ensure the entry point is: `wp-content/plugins/wp-secure-main/main.php`
3. Go to **Plugins → Installed Plugins**
4. Activate **WP Secure**

When upgrading from v1.0, deactivate the old plugin first.

---

## How It Works

1. The user enters a username and password
2. If their role is enabled in settings, a challenge is created and a code is sent by email
3. On the login screen, the user enters the **email code** (case-sensitive, includes symbols) or clicks **"Sign in another way"** to use TOTP
4. After successful verification, the user is signed in and the challenge is cleared

### Email codes

- Length: **6 characters**
- Charset: letters, digits, and symbols (`!@#$%&*+-=?`)
- Ambiguous characters excluded: `0`, `O`, `1`, `l`, `I`
- Example: `K7m@#P`

### TOTP codes

- Standard 6-digit codes from an authenticator app (RFC 6238)
- 30-second time window with ±1 step drift tolerance

---

## Admin Pages

The plugin adds three separate pages under **Settings**:

### Settings → WP Secure

`options-general.php?page=wp-secure`

**Access:** primary site administrator only (**user ID 1**)

| Section | Description |
|---------|-------------|
| Roles with 2FA | Select which WordPress roles require two-factor sign-in |
| Security and Limits | Configure rate limits, resend rules, code expiry, IP restrictions |

Other administrators cannot see this menu item. Direct URL access returns **403 Access denied**.

### Settings → WP Secure OTP

`options-general.php?page=wp-secure-authenticator`

**Access:** users whose **role requires 2FA** (as configured on the WP Secure page)

| Action | Description |
|--------|-------------|
| Create OTP | Generate a TOTP secret |
| Scan QR code | Add the account to Google Authenticator, Authy, etc. |
| Confirm | Enter a code from the app to activate |
| Disable | Remove the authenticator |

Users without 2FA enabled for their role do not see this menu item.

### Settings → WP Secure Sessions

`options-general.php?page=wp-secure-sessions`

**Access:** users whose **role requires 2FA** (same as WP Secure OTP)

| Column / Action | Description |
|-----------------|-------------|
| **Current device** | Shown separately: device type, OS, browser, approximate city, masked IP |
| Login time | When the session was created |
| Last activity | Last admin request from that session |
| Device / Browser | Parsed from User-Agent (e.g. `Компьютер · Windows 10/11`, `Chrome 125`) |
| City | Approximate location from IP (cached, Russian labels via ip-api.com) |
| IP address | Partially masked (e.g. `192.168.1.***`); stored encrypted at rest |
| **Sign out** | End a single remote session — that device is logged out on the next request |
| **Sign out everywhere except here** | Revoke all other WordPress sessions; current browser stays signed in |

Session metadata is stored in user meta as **AES-256-CBC encrypted JSON**. Raw WordPress session tokens are never exposed in the UI — only opaque HMAC identifiers. Revocation uses the native WordPress `WP_Session_Tokens` API, so destroyed sessions cannot access the admin area.

---

## Configuration

### Roles with 2FA

**Settings → WP Secure** (user ID 1 only)

Select roles that require two-factor sign-in. Default: **administrator**.

### Security and Limits

**Settings → WP Secure** (user ID 1 only)

| Setting | Default | Description |
|---------|---------|-------------|
| Code entry attempts | 5 | Max failed attempts per login challenge |
| Email resend attempts | 3 | Max code resends per challenge |
| Resend cooldown | 60 sec | Minimum delay between resends |
| Challenges per IP | 10 | Max login challenges from one IP |
| IP rate window | 900 sec (15 min) | Time window for IP limits |
| Code expiry | 600 sec (10 min) | Email code and 2FA session lifetime |

### OTP / Authenticator

**Settings → WP Secure OTP** (users with 2FA-enabled roles)

1. Click **Create OTP**
2. Scan the QR code or enter the secret key manually
3. Enter the 6-digit code from the app to confirm
4. At login, use **"Sign in another way"** to enter a TOTP code instead of waiting for email

### Active sessions

**Settings → WP Secure Sessions** (users with 2FA-enabled roles)

1. Review active sign-ins (login time, last activity, partially masked IP)
2. Click **Sign out** to revoke a single remote session
3. Click **Sign out everywhere except here** to end all other sessions

Revoked devices lose admin access on their next request.

### Email delivery

```php
wp_mail('test@example.com', 'Test', 'Mail delivery test');
```

---

## Project Structure

```
wp-secure-main/
├── main.php                          # Plugin bootstrap
├── README.md
├── assets/css/login.css
└── src/
    ├── Plugin.php
    ├── Actions/
    │   ├── InitiateEmailChallengeAction.php
    │   ├── VerifyEmailCodeAction.php
    │   └── VerifyTotpAction.php
    ├── Admin/
    │   ├── AuthenticatorPage.php     # OTP setup (2FA roles)
    │   ├── SessionsPage.php          # Encrypted session management (2FA roles)
    │   ├── SettingsPage.php          # Global settings (user ID 1)
    │   └── TotpSetupSection.php
    ├── Constants/
    │   └── PluginConstants.php
    ├── Login/
    │   ├── AuthenticationInterceptor.php
    │   └── LoginFormHandler.php
    └── Services/
        ├── Auth/
        │   ├── ChallengeService.php
        │   ├── EmailCodeService.php
        │   ├── SessionRegistryService.php
        │   ├── TotpService.php
        │   └── UserTwoFactorService.php
        ├── Security/
        │   ├── CryptoService.php
        │   ├── GeoLocationService.php
        │   ├── RateLimitService.php
        │   └── UserAgentParserService.php
        └── Settings/
            ├── PrimaryAdminService.php
            ├── RoleSettingsService.php
            └── SecuritySettingsService.php
```

---

## Security

| Mechanism | Description |
|-----------|-------------|
| Challenge tokens | HttpOnly cookie + WordPress transients; password is never stored |
| Hashed email codes | Stored with `wp_hash_password()` |
| Alphanumeric codes | CSPRNG via `random_int()` / `random_bytes()` |
| Fingerprint | Challenge bound to IP and User-Agent |
| CSRF | WordPress nonces on 2FA form and resend links |
| Rate limiting | Configurable limits in admin (attempts, resend, IP) |
| TOTP encryption | Secrets encrypted with AES-256-CBC |
| Encrypted session registry | Login metadata (IP, device, browser, city, timestamps) stored as AES-256-CBC JSON |
| Geolocation cache | City lookups cached per IP hash for 24 hours (no raw IP in transients) |
| Session revocation | Native `WP_Session_Tokens`; opaque HMAC session IDs in forms (no raw tokens) |
| Session action rate limit | 20 revocations per 5 minutes per user |
| Primary admin lock | Global settings restricted to user ID 1 |
| Role-based OTP access | Authenticator page visible only to 2FA-enabled roles |

---

## License

Licensed under the **GNU General Public License v2.0 or later** (GPL v2+).

---

## What Changed Since v1.0

The first version (**WP 2FA Email Authentication**, v1.0.0) was a single `wp-secure.php` file with the `WP_2FA_Email` class.  
The current version (**WP Secure**, v2.0.0) is a full rewrite.

### Architecture

| v1.0 | v2.0 |
|------|------|
| Single PHP file (~350 lines) | Modular structure: `main.php` + `src/` (Actions, Admin, Login, Services) |
| One `WP_2FA_Email` class | PSR-4 autoload, `WpSecure\` namespace, `declare(strict_types=1)` |
| PHP sessions (`$_SESSION`) | Challenge tokens via WordPress transients + HttpOnly cookie |
| Password stored in session and passed in hidden HTML fields | Password is never stored; cryptographic token is used instead |

### Authentication

| v1.0 | v2.0 |
|------|------|
| Numeric email code only | Alphanumeric email code (letters, digits, symbols) |
| Email code only | Email **or** TOTP (Google Authenticator, Authy, etc.) |
| Administrators only | Any role — configurable under **Settings → WP Secure** |
| No settings page | Three admin pages: global settings, OTP setup, session management |
| No TOTP | Dedicated **Settings → WP Secure OTP** page with QR code |
| — | **"Sign in another way"** link on the login page |
| — | **"Защищено wp-secure"** label under `#loginform` |
| — | **Settings → WP Secure Sessions** — encrypted session list, remote logout |

### Admin access (new in v2.0)

| Page | Who can access |
|------|----------------|
| **Settings → WP Secure** | Primary administrator only (user ID 1) |
| **Settings → WP Secure OTP** | Users whose role has 2FA enabled |
| **Settings → WP Secure Sessions** | Users whose role has 2FA enabled |

### Security

| v1.0 | v2.0 |
|------|------|
| Plaintext codes in `$_SESSION` | Email codes hashed with `wp_hash_password()` |
| `mt_rand()` for code generation | `random_int()` / `random_bytes()` (CSPRNG) |
| Hardcoded limits | Configurable limits in admin UI |
| No nonce on 2FA form | CSRF protection via WordPress nonces |
| No IP / User-Agent binding | Session fingerprint (IP + User-Agent) |
| No TOTP | TOTP secrets encrypted with AES-256-CBC |
| Unprotected GET resend | Resend with nonce and cooldown |

### Settings (new in v2.0)

Under **Settings → WP Secure → Security and Limits** (user ID 1):

- Code entry attempts (default: 5)
- Email resend attempts (default: 3)
- Resend cooldown in seconds (default: 60)
- Challenges per IP (default: 10 per 15 min)
- IP rate window in seconds (default: 900)
- Code expiry in seconds (default: 600)

In v1.0, all of these values were hardcoded in source code.

### Files and Installation

| v1.0 | v2.0 |
|------|------|
| `wp-secure.php` (or `wp-2fa-email.php`) | `main.php` — plugin entry point |
| Plugin: "WP 2FA Email Authentication" | Plugin: **WP Secure** v2.0.0 |

> **Migration:** Deactivate the old plugin, upload the `wp-secure-main` folder, and activate **WP Secure**. Configure roles and security limits on **Settings → WP Secure** (user ID 1). Users with 2FA-enabled roles set up OTP on **Settings → WP Secure OTP**.
