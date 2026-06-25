<?php

declare(strict_types=1);

namespace WpSecure\Services\Security;

/**
 * Derives human-readable device and browser labels from a User-Agent string.
 */
final class UserAgentParserService
{
    /**
     * @param string $userAgent Raw HTTP User-Agent header.
     *
     * @return array{device: string, browser: string}
     */
    public function parse(string $userAgent): array
    {
        $userAgent = trim($userAgent);

        if ($userAgent === '') {
            return [
                'device' => 'Неизвестное устройство',
                'browser' => 'Неизвестный браузер',
            ];
        }

        return [
            'device' => $this->detectDevice($userAgent),
            'browser' => $this->detectBrowser($userAgent),
        ];
    }

    /**
     * @param string $userAgent Raw HTTP User-Agent header.
     *
     * @return string
     */
    private function detectDevice(string $userAgent): string
    {
        $os = $this->detectOperatingSystem($userAgent);
        $formFactor = $this->detectFormFactor($userAgent);

        if ($os === '') {
            return $formFactor !== '' ? $formFactor : 'Неизвестное устройство';
        }

        if ($formFactor === '') {
            return $os;
        }

        return $formFactor . ' · ' . $os;
    }

    /**
     * @param string $userAgent Raw HTTP User-Agent header.
     *
     * @return string
     */
    private function detectFormFactor(string $userAgent): string
    {
        if (preg_match('/iPad|Tablet|Kindle|Silk\/|PlayBook/i', $userAgent)) {
            return 'Планшет';
        }

        if (preg_match('/Mobile|iPhone|iPod|Android.*Mobile|Windows Phone|webOS|BlackBerry/i', $userAgent)) {
            return 'Телефон';
        }

        return 'Компьютер';
    }

    /**
     * @param string $userAgent Raw HTTP User-Agent header.
     *
     * @return string
     */
    private function detectOperatingSystem(string $userAgent): string
    {
        $patterns = [
            '/Windows NT 10/i' => 'Windows 10/11',
            '/Windows NT 6\.3/i' => 'Windows 8.1',
            '/Windows NT 6\.2/i' => 'Windows 8',
            '/Windows NT 6\.1/i' => 'Windows 7',
            '/Windows/i' => 'Windows',
            '/Mac OS X ([0-9_\.]+)/i' => 'macOS',
            '/iPhone OS ([0-9_]+)/i' => 'iOS',
            '/iPad.*OS ([0-9_]+)/i' => 'iPadOS',
            '/Android ([0-9\.]+)/i' => 'Android',
            '/CrOS/i' => 'ChromeOS',
            '/Linux/i' => 'Linux',
        ];

        foreach ($patterns as $pattern => $label) {
            if (preg_match($pattern, $userAgent)) {
                return $label;
            }
        }

        return '';
    }

    /**
     * @param string $userAgent Raw HTTP User-Agent header.
     *
     * @return string
     */
    private function detectBrowser(string $userAgent): string
    {
        if (preg_match('/EdgA?\/([0-9\.]+)/i', $userAgent, $matches)) {
            return 'Microsoft Edge ' . $matches[1];
        }

        if (preg_match('/OPR\/([0-9\.]+)/i', $userAgent, $matches)) {
            return 'Opera ' . $matches[1];
        }

        if (preg_match('/YaBrowser\/([0-9\.]+)/i', $userAgent, $matches)) {
            return 'Yandex Browser ' . $matches[1];
        }

        if (preg_match('/SamsungBrowser\/([0-9\.]+)/i', $userAgent, $matches)) {
            return 'Samsung Internet ' . $matches[1];
        }

        if (preg_match('/Firefox\/([0-9\.]+)/i', $userAgent, $matches)) {
            return 'Firefox ' . $matches[1];
        }

        if (preg_match('/Chrome\/([0-9\.]+)/i', $userAgent, $matches)) {
            return 'Chrome ' . $matches[1];
        }

        if (preg_match('/Version\/([0-9\.]+).*Safari/i', $userAgent, $matches)) {
            return 'Safari ' . $matches[1];
        }

        if (preg_match('/MSIE ([0-9\.]+)/i', $userAgent, $matches)) {
            return 'Internet Explorer ' . $matches[1];
        }

        if (preg_match('/Trident\/.*rv:([0-9\.]+)/i', $userAgent, $matches)) {
            return 'Internet Explorer ' . $matches[1];
        }

        return 'Неизвестный браузер';
    }
}
