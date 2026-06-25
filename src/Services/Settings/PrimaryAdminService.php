<?php

declare(strict_types=1);

namespace WpSecure\Services\Settings;

use WpSecure\Constants\PluginConstants;

/**
 * Determines access to primary plugin administration screens.
 */
final class PrimaryAdminService
{
    /**
     * Check whether the given user is the primary site administrator (user ID 1).
     *
     * @param int|null $userId WordPress user ID. Defaults to the current user.
     *
     * @return bool
     */
    public function isPrimaryAdmin(?int $userId = null): bool
    {
        $userId = $userId ?? get_current_user_id();

        return $userId === PluginConstants::PRIMARY_ADMIN_USER_ID;
    }
}
