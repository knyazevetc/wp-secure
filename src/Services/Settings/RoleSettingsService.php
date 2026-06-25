<?php

declare(strict_types=1);

namespace WpSecure\Services\Settings;

use WP_User;
use WpSecure\Constants\PluginConstants;

/**
 * Manages which WordPress roles require two-factor authentication.
 */
final class RoleSettingsService
{
    /**
     * Get role slugs that require two-factor authentication.
     *
     * @return list<string>
     */
    public function getEnabledRoles(): array
    {
        $roles = get_option(PluginConstants::OPTION_ENABLED_ROLES);

        if (!is_array($roles) || $roles === []) {
            return PluginConstants::DEFAULT_ENABLED_ROLES;
        }

        return array_values(array_filter(
            array_map('strval', $roles),
            [$this, 'isValidRole']
        ));
    }

    /**
     * Save the list of roles that require two-factor authentication.
     *
     * @param list<string> $roles WordPress role slugs.
     *
     * @return void
     */
    public function saveEnabledRoles(array $roles): void
    {
        $validRoles = array_values(array_filter(
            array_map('strval', $roles),
            [$this, 'isValidRole']
        ));

        update_option(PluginConstants::OPTION_ENABLED_ROLES, $validRoles);
    }

    /**
     * Get all editable WordPress roles for the settings UI.
     *
     * @return array<string, string> Role slug => translated role name.
     */
    public function getAvailableRoles(): array
    {
        if (!function_exists('get_editable_roles')) {
            require_once ABSPATH . 'wp-admin/includes/user.php';
        }

        $editableRoles = get_editable_roles();
        $roles = [];

        foreach ($editableRoles as $roleSlug => $roleData) {
            $roles[$roleSlug] = translate_user_role($roleData['name']);
        }

        return $roles;
    }

    /**
     * Check whether two-factor authentication is required for the given user.
     *
     * @param WP_User $user WordPress user instance.
     *
     * @return bool
     */
    public function isTwoFactorRequired(WP_User $user): bool
    {
        $enabledRoles = $this->getEnabledRoles();

        foreach ($enabledRoles as $role) {
            if (in_array($role, $user->roles, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validate that a role slug exists in WordPress.
     *
     * @param string $role Role slug.
     *
     * @return bool
     */
    private function isValidRole(string $role): bool
    {
        if ($role === '') {
            return false;
        }

        return wp_roles()->is_role($role);
    }
}
