

<div align="center">

# 🔐 WP 2FA Email Authentication

![WordPress](https://img.shields.io/badge/WordPress-21759B?style=for-the-badge&logo=wordpress&logoColor=white)
![PHP](https://img.shields.io/badge/PHP-777BB4?style=for-the-badge&logo=php&logoColor=white)
![Security](https://img.shields.io/badge/Security-2FA-green?style=for-the-badge&logo=shield&logoColor=white)
![License](https://img.shields.io/badge/License-GPL%20v2-blue?style=for-the-badge)

**A lightweight and secure Two-Factor Authentication plugin for WordPress administrators**

[Features](#features) • [Installation](#installation) • [How It Works](#how-it-works) • [Configuration](#configuration) • [Security Features](#security-features)

</div>

---

## Features

- **Two-Factor Authentication** - Adds an extra layer of security with email-based verification codes
- **Admin-Only Protection** - Applies 2FA only to users with administrator privileges
- **Email Integration** - Uses WordPress native `wp_mail()` function for sending codes
- **Time-Limited Codes** - Verification codes expire after 10 minutes

---

## Requirements

| Requirement | Version |
|------------|---------|
| ![WordPress](https://img.shields.io/badge/WordPress-5.0+-21759B?logo=wordpress&logoColor=white) | **5.0 or higher** |
| ![PHP](https://img.shields.io/badge/PHP-7.4+-777BB4?logo=php&logoColor=white) | **7.4 or higher** |
| ![Mail Server](https://img.shields.io/badge/Mail_Server-Configured-orange?logo=gmail&logoColor=white) | **Properly configured** |

---

## Installation

### Method 1: Manual Installation

1. **Download** the plugin file `wp-2fa-email.php`

2. **Upload** to your WordPress plugins directory:
   ```bash
   wp-content/plugins/wp-2fa-email/
   ```

3. **Activate** the plugin:
   - Navigate to **WordPress Admin → Plugins**
   - Find "WP 2FA Email Authentication"
   - Click **Activate**

### Method 2: FTP Upload

1. Connect to your server via FTP
2. Upload `wp-2fa-email.php` to `/wp-content/plugins/`
3. Activate via WordPress dashboard

---

## How It Works
### Step-by-Step Process

1. **Login Attempt**
   - User enters username and password
   - System validates credentials

2. **Code Generation**
   - If user is an administrator, a 6-digit code is generated
   - Code format: `123456`

3. **Email Delivery**
   - Verification code is sent to user's email
   - Email includes username and expiration time

4. **Code Verification**
   - User enters the code from email
   - Code is validated (must be used within 10 minutes)

5. **Access Granted**
   - Upon successful verification, user gains access
   - Session data is cleared

---

## Configuration

### Email Settings

The plugin uses WordPress's built-in `wp_mail()` function. Ensure your mail server is properly configured:

```php
// Test email functionality
wp_mail('test@example.com', 'Test', 'This is a test email');
```

### Code Expiration Time

Default: **10 minutes**

To change the expiration time, modify line 120:

```php
return (time() - $_SESSION[$this->session_time]) < 600; // 600 seconds = 10 minutes
```

### User Role Customization

By default, 2FA applies only to administrators. To change this, modify line 157:

```php
// Current: Only administrators
if ($user instanceof WP_User && !user_can($user, 'manage_options')) {
    return $user;
}

// Example: Apply to editors and administrators
if ($user instanceof WP_User && !user_can($user, 'edit_others_posts')) {
    return $user;
}
```

---

## Security Features

| Feature | Description |
|---------|-------------|
| **Random Codes** | 6-digit codes generated using `mt_rand()` |
| **Time Expiration** | Codes valid for 10 minutes only |
| **Email Masking** | Email addresses partially hidden (`us***@domain.com`) |
| **Session Cleanup** | Automatic session clearing after login/logout |
| **CSRF Protection** | WordPress nonce validation integrated |
| **Sanitization** | All inputs sanitized using `sanitize_text_field()` |
