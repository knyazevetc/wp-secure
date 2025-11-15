<?php
/**
 * Plugin Name: WP 2FA Email Authentication
 * Plugin URI: https://example.com
 * Description: Two-factor authentication via email for wp-admin login
 * Version: 1.0.0
 * Author: Your Name
 * Author URI: https://example.com
 * License: GPL v2 or later
 * Text Domain: wp-2fa-email
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_2FA_Email {
    
    private static $instance = null;
    private $session_key = 'wp_2fa_code';
    private $session_user = 'wp_2fa_user';
    private $session_time = 'wp_2fa_time';
    private $session_username = 'wp_2fa_username';
    private $session_password = 'wp_2fa_password';
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        // Intercept authentication process
        add_filter('authenticate', array($this, 'intercept_authentication'), 30, 3);
        
        // Add verification code field to login form
        add_action('login_form', array($this, 'add_verification_field'));
        
        // Add custom styles
        add_action('login_enqueue_scripts', array($this, 'add_login_styles'));
        
        // Handle resend code request
        add_action('login_form', array($this, 'handle_resend_code'));
        
        // Clear session on logout
        add_action('wp_logout', array($this, 'clear_session'));
    }
    
    /**
     * Generate 6-digit code
     */
    private function generate_code() {
        return sprintf('%06d', mt_rand(0, 999999));
    }
    
    /**
     * Send verification code via email
     */
    private function send_verification_code($user_email, $code, $username) {
        $subject = 'Код подтверждения для входа в ' . get_bloginfo('name');
        
        $message = "Здравствуйте!\n\n";
        $message .= "Кто-то пытается войти в панель администрирования с вашими учетными данными.\n\n";
        $message .= "Имя пользователя: " . $username . "\n";
        $message .= "Ваш код подтверждения: " . $code . "\n\n";
        $message .= "Код действителен в течение 10 минут.\n\n";
        $message .= "Если это были не вы, проигнорируйте это письмо.\n\n";
        $message .= "С уважением,\n";
        $message .= get_bloginfo('name');
        
        $headers = array('Content-Type: text/plain; charset=UTF-8');
        
        return wp_mail($user_email, $subject, $message, $headers);
    }
    
    /**
     * Save code to session
     */
    private function save_code_to_session($code, $user_id, $username = '', $password = '') {
        if (!session_id()) {
            session_start();
        }
        $_SESSION[$this->session_key] = $code;
        $_SESSION[$this->session_user] = $user_id;
        $_SESSION[$this->session_time] = time();
        $_SESSION[$this->session_username] = $username;
        $_SESSION[$this->session_password] = $password;
    }
    
    /**
     * Get code from session
     */
    private function get_code_from_session() {
        if (!session_id()) {
            session_start();
        }
        return isset($_SESSION[$this->session_key]) ? $_SESSION[$this->session_key] : null;
    }
    
    /**
     * Get user ID from session
     */
    private function get_user_from_session() {
        if (!session_id()) {
            session_start();
        }
        return isset($_SESSION[$this->session_user]) ? $_SESSION[$this->session_user] : null;
    }
    
    /**
     * Check if code is valid (10 minutes)
     */
    private function is_code_valid() {
        if (!session_id()) {
            session_start();
        }
        if (!isset($_SESSION[$this->session_time])) {
            return false;
        }
        return (time() - $_SESSION[$this->session_time]) < 600; // 10 minutes
    }
    
    /**
     * Clear session data
     */
    public function clear_session() {
        if (!session_id()) {
            session_start();
        }
        unset($_SESSION[$this->session_key]);
        unset($_SESSION[$this->session_user]);
        unset($_SESSION[$this->session_time]);
        unset($_SESSION[$this->session_username]);
        unset($_SESSION[$this->session_password]);
    }
    
    /**
     * Intercept authentication process
     */
    public function intercept_authentication($user, $username, $password) {
        // Skip if there's already an error
        if (is_wp_error($user)) {
            return $user;
        }
        
        // Skip if not a POST request
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            return $user;
        }
        
        // Check if user is administrator
        // If user is valid but not administrator - skip 2FA
        if ($user instanceof WP_User && !user_can($user, 'manage_options')) {
            return $user; // Skip 2FA for non-administrators
        }
        
        // Check if verification code is present in request
        $verification_code = isset($_POST['verification_code']) ? sanitize_text_field($_POST['verification_code']) : '';
        
        if (!empty($verification_code)) {
            // Verify the entered code
            return $this->verify_code($verification_code);
        }
        
        // If user is valid and entered correct login/password
        if ($user instanceof WP_User) {
            // Generate and send code
            $code = $this->generate_code();
            $this->save_code_to_session($code, $user->ID, $username, $password);
            
            $sent = $this->send_verification_code($user->user_email, $code, $user->user_login);
            
            if ($sent) {
                // Return error to stop login and show code field
                return new WP_Error(
                    'verification_required',
                    sprintf(
                        '<strong>Код подтверждения отправлен на email:</strong> %s<br>Введите код ниже.',
                        esc_html($this->mask_email($user->user_email))
                    )
                );
            } else {
                return new WP_Error(
                    'email_send_failed',
                    '<strong>Ошибка:</strong> Не удалось отправить код подтверждения. Проверьте настройки почты.'
                );
            }
        }
        
        return $user;
    }
    
    /**
     * Verify entered code
     */
    private function verify_code($entered_code) {
        $stored_code = $this->get_code_from_session();
        $user_id = $this->get_user_from_session();
        
        if (!$stored_code || !$user_id) {
            return new WP_Error(
                'no_code',
                '<strong>Ошибка:</strong> Сессия истекла. Попробуйте войти снова.'
            );
        }
        
        if (!$this->is_code_valid()) {
            $this->clear_session();
            return new WP_Error(
                'code_expired',
                '<strong>Ошибка:</strong> Код подтверждения истек (действителен 10 минут). Попробуйте войти снова.'
            );
        }
        
        if ($entered_code === $stored_code) {
            // Code is correct - clear session and allow login
            $this->clear_session();
            $user = get_user_by('id', $user_id);
            return $user;
        } else {
            return new WP_Error(
                'invalid_code',
                '<strong>Ошибка:</strong> Неверный код подтверждения. Попробуйте еще раз.'
            );
        }
    }
    
    /**
     * Mask email for security
     */
    private function mask_email($email) {
        $parts = explode('@', $email);
        if (count($parts) !== 2) {
            return $email;
        }
        
        $name = $parts[0];
        $domain = $parts[1];
        
        $name_length = strlen($name);
        if ($name_length > 2) {
            $name = substr($name, 0, 2) . str_repeat('*', $name_length - 2);
        }
        
        return $name . '@' . $domain;
    }
    
    /**
     * Add verification code field to login form
     */
    public function add_verification_field() {
        $stored_code = $this->get_code_from_session();
        
        if ($stored_code && $this->is_code_valid()) {
            if (!session_id()) {
                session_start();
            }
            $username = isset($_SESSION[$this->session_username]) ? $_SESSION[$this->session_username] : '';
            $password = isset($_SESSION[$this->session_password]) ? $_SESSION[$this->session_password] : '';
            ?>
            <!-- Hidden fields to pass login and password -->
            <input type="hidden" name="log" value="<?php echo esc_attr($username); ?>">
            <input type="hidden" name="pwd" value="<?php echo esc_attr($password); ?>">
            
            <p>
                <label for="verification_code">Код подтверждения<br>
                <input type="text" name="verification_code" id="verification_code" class="input" value="" size="20" autocomplete="off" required="required" pattern="[0-9]{6}" maxlength="6" placeholder="000000" autofocus></label>
            </p>
            <p class="verification-info" style="font-size: 12px; color: #50575e;">
                Код отправлен на вашу почту и действителен 10 минут.
            </p>
            <style>
                #user_login, #user_pass, .user-pass-wrap, .forgetmenot {
                    display: none !important;
                }
            </style>
            <script type="text/javascript">
                // Remove required attribute from original fields to avoid validation error
                (function() {
                    var userLogin = document.getElementById('user_login');
                    var userPass = document.getElementById('user_pass');
                    if (userLogin) userLogin.removeAttribute('required');
                    if (userPass) userPass.removeAttribute('required');
                })();
            </script>
            <?php
        }
    }
    
    /**
     * Handle resend code request
     */
    public function handle_resend_code() {
        if (isset($_GET['resend_code']) && $_GET['resend_code'] === '1') {
            $user_id = $this->get_user_from_session();
            if ($user_id) {
                $user = get_user_by('id', $user_id);
                if ($user) {
                    if (!session_id()) {
                        session_start();
                    }
                    $username = isset($_SESSION[$this->session_username]) ? $_SESSION[$this->session_username] : '';
                    $password = isset($_SESSION[$this->session_password]) ? $_SESSION[$this->session_password] : '';
                    
                    $code = $this->generate_code();
                    $this->save_code_to_session($code, $user->ID, $username, $password);
                    $this->send_verification_code($user->user_email, $code, $user->user_login);
                    
                    add_filter('login_message', function($message) {
                        return '<div id="login_error">Новый код отправлен на вашу почту.</div>';
                    });
                }
            }
        }
    }
    
    /**
     * Add custom styles to login page
     */
    public function add_login_styles() {
        ?>
        <style type="text/css">
            #verification_code {
                font-size: 24px;
                text-align: center;
                letter-spacing: 5px;
                font-family: monospace;
            }
            .verification-info {
                background: #f0f6fc;
                border-left: 4px solid #0071a1;
                padding: 10px;
                margin: 10px 0;
            }
        </style>
        <?php
    }
}

// Initialize plugin
function wp_2fa_email_init() {
    WP_2FA_Email::get_instance();
}
add_action('plugins_loaded', 'wp_2fa_email_init');
