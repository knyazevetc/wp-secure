<?php

declare(strict_types=1);

namespace WpSecure\Services\Security;

use WpSecure\Constants\PluginConstants;

/**
 * Resolves approximate city-level geolocation from a public IP address.
 */
final class GeoLocationService
{
    /**
     * Resolve an approximate city label for an IP address.
     *
     * @param string $ip IP address.
     *
     * @return string|null Returns null when lookup fails.
     */
    public function resolveCity(string $ip): ?string
    {
        if (!$this->isPublicIp($ip)) {
            return 'Локальная сеть';
        }

        $cacheKey = PluginConstants::GEO_TRANSIENT_PREFIX . hash('sha256', $ip);
        $cached = get_transient($cacheKey);

        if (is_string($cached) && $cached !== '') {
            return $cached;
        }

        $response = wp_remote_get(
            'http://ip-api.com/json/' . rawurlencode($ip) . '?fields=status,city,country&lang=ru',
            [
                'timeout' => 3,
                'redirection' => 0,
            ]
        );

        if (is_wp_error($response)) {
            return null;
        }

        $statusCode = (int) wp_remote_retrieve_response_code($response);

        if ($statusCode !== 200) {
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $payload = json_decode($body, true);

        if (!is_array($payload) || ($payload['status'] ?? '') !== 'success') {
            return null;
        }

        $city = isset($payload['city']) ? trim((string) $payload['city']) : '';
        $country = isset($payload['country']) ? trim((string) $payload['country']) : '';

        if ($city === '' && $country === '') {
            return null;
        }

        $label = $city !== '' && $country !== ''
            ? $city . ', ' . $country
            : ($city !== '' ? $city : $country);

        set_transient($cacheKey, $label, PluginConstants::GEO_CACHE_SECONDS);

        return $label;
    }

    /**
     * @param string $ip IP address.
     *
     * @return bool
     */
    private function isPublicIp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) !== false;
    }
}
