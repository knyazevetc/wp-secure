<?php

declare(strict_types=1);

namespace WpSecure\Services\Auth;

use WpSecure\Constants\PluginConstants;
use WpSecure\Services\Settings\SecuritySettingsService;

/**
 * Generates and sends email-based verification codes.
 */
final class EmailCodeService
{
    private SecuritySettingsService $securitySettingsService;

    /**
     * @param SecuritySettingsService|null $securitySettingsService Security settings dependency.
     */
    public function __construct(?SecuritySettingsService $securitySettingsService = null)
    {
        $this->securitySettingsService = $securitySettingsService ?? new SecuritySettingsService();
    }

    /**
     * Generate a random verification code from letters, digits, and symbols.
     *
     * @return string
     */
    public function generateCode(): string
    {
        $alphabet = PluginConstants::CODE_ALPHABET;
        $maxIndex = strlen($alphabet) - 1;
        $code = '';

        for ($index = 0; $index < PluginConstants::CODE_LENGTH; $index++) {
            $code .= $alphabet[random_int(0, $maxIndex)];
        }

        return $code;
    }

    /**
     * Validate the format of a user-submitted email verification code.
     *
     * @param string $code Code entered by the user.
     *
     * @return bool
     */
    public function isValidFormat(string $code): bool
    {
        if (strlen($code) !== PluginConstants::CODE_LENGTH) {
            return false;
        }

        $alphabet = PluginConstants::CODE_ALPHABET;

        for ($index = 0, $length = strlen($code); $index < $length; $index++) {
            if (strpos($alphabet, $code[$index]) === false) {
                return false;
            }
        }

        return true;
    }

    /**
     * Send a verification code to the user's email address.
     *
     * @param string $userEmail Recipient email address.
     * @param string $code Verification code.
     * @param string $username WordPress username.
     *
     * @return bool
     */
    public function sendVerificationCode(string $userEmail, string $code, string $username): bool
    {
        $siteName = get_bloginfo('name');
        $subject = sprintf('Код подтверждения для входа в %s', $siteName);
        $expiryMinutes = $this->securitySettingsService->getCodeExpiryMinutes();

        $message = "Здравствуйте!\n\n";
        $message .= "Кто-то пытается войти в панель администрирования с вашими учетными данными.\n\n";
        $message .= sprintf("Имя пользователя: %s\n", $username);
        $message .= sprintf("Ваш код подтверждения: %s\n\n", $code);
        $message .= sprintf("Код действителен в течение %d мин.\n\n", $expiryMinutes);
        $message .= "Скопируйте код точно — учитываются регистр букв и символы.\n\n";
        $message .= "Если это были не вы, проигнорируйте это письмо.\n\n";
        $message .= sprintf("С уважением,\n%s", $siteName);

        $headers = ['Content-Type: text/plain; charset=UTF-8'];

        return wp_mail($userEmail, $subject, $message, $headers);
    }

    /**
     * Mask an email address for display on the login screen.
     *
     * @param string $email Raw email address.
     *
     * @return string
     */
    public function maskEmail(string $email): string
    {
        $parts = explode('@', $email);

        if (count($parts) !== 2) {
            return $email;
        }

        $name = $parts[0];
        $domain = $parts[1];
        $nameLength = strlen($name);

        if ($nameLength > 2) {
            $name = substr($name, 0, 2) . str_repeat('*', $nameLength - 2);
        }

        return $name . '@' . $domain;
    }
}
