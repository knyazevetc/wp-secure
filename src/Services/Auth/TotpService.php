<?php

declare(strict_types=1);

namespace WpSecure\Services\Auth;

use WpSecure\Constants\PluginConstants;

/**
 * Implements RFC 6238 TOTP generation and verification for authenticator apps.
 */
final class TotpService
{
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Generate a random Base32 secret for TOTP enrollment.
     *
     * @param int $length Secret length in characters.
     *
     * @return string
     */
    public function generateSecret(int $length = 16): string
    {
        $secret = '';
        $maxIndex = strlen(self::BASE32_ALPHABET) - 1;

        for ($index = 0; $index < $length; $index++) {
            $secret .= self::BASE32_ALPHABET[random_int(0, $maxIndex)];
        }

        return $secret;
    }

    /**
     * Build an otpauth URI for QR code enrollment.
     *
     * @param string $secret Base32-encoded secret.
     * @param string $accountName Account label shown in the authenticator app.
     * @param string $issuer Application or site name.
     *
     * @return string
     */
    public function buildProvisioningUri(string $secret, string $accountName, string $issuer): string
    {
        $label = rawurlencode($issuer . ':' . $accountName);

        return sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s&digits=%d&period=%d',
            $label,
            $secret,
            rawurlencode($issuer),
            PluginConstants::TOTP_DIGITS,
            PluginConstants::TOTP_PERIOD
        );
    }

    /**
     * Build a QR code image URL for the given provisioning URI.
     *
     * @param string $provisioningUri otpauth URI.
     *
     * @return string
     */
    public function buildQrCodeUrl(string $provisioningUri): string
    {
        return 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data='
            . rawurlencode($provisioningUri);
    }

    /**
     * Generate the current TOTP code for a secret.
     *
     * @param string $secret Base32-encoded secret.
     * @param int|null $timeSlice Optional time slice override.
     *
     * @return string
     */
    public function getCurrentCode(string $secret, ?int $timeSlice = null): string
    {
        if ($timeSlice === null) {
            $timeSlice = (int) floor(time() / PluginConstants::TOTP_PERIOD);
        }

        $secretKey = $this->base32Decode($secret);
        $time = pack('N*', 0, $timeSlice);
        $hash = hash_hmac('sha1', $time, $secretKey, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $truncatedHash = substr($hash, $offset, 4);
        $value = unpack('N', $truncatedHash)[1] & 0x7FFFFFFF;
        $modulo = 10 ** PluginConstants::TOTP_DIGITS;

        return str_pad((string) ($value % $modulo), PluginConstants::TOTP_DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * Verify a TOTP code against a secret with clock drift tolerance.
     *
     * @param string $secret Base32-encoded secret.
     * @param string $code User-provided code.
     *
     * @return bool
     */
    public function verifyCode(string $secret, string $code): bool
    {
        $code = preg_replace('/\s+/', '', $code) ?? '';

        if (!preg_match('/^\d{' . PluginConstants::TOTP_DIGITS . '}$/', $code)) {
            return false;
        }

        $timeSlice = (int) floor(time() / PluginConstants::TOTP_PERIOD);

        for (
            $offset = -PluginConstants::TOTP_DISCREPANCY;
            $offset <= PluginConstants::TOTP_DISCREPANCY;
            $offset++
        ) {
            if (hash_equals($this->getCurrentCode($secret, $timeSlice + $offset), $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Decode a Base32-encoded string into binary data.
     *
     * @param string $secret Base32-encoded secret.
     *
     * @return string
     */
    private function base32Decode(string $secret): string
    {
        $secret = strtoupper($secret);
        $secret = rtrim($secret, '=');
        $binaryString = '';
        $buffer = 0;
        $bitsLeft = 0;

        for ($index = 0, $length = strlen($secret); $index < $length; $index++) {
            $value = strpos(self::BASE32_ALPHABET, $secret[$index]);

            if ($value === false) {
                continue;
            }

            $buffer = ($buffer << 5) | $value;
            $bitsLeft += 5;

            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $binaryString .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }

        return $binaryString;
    }
}
