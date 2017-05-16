<?php

namespace App\Permissions;

use App\Role;
use App\Permission;

/**
 *
 */
trait HasPermissionsTrait
{
    public function roles()
    {
        return $this->belongsToMany(Role::class, 'users_roles');
    }

    public function permissions()
    {
        return $this->belongsToMany(Permission::class, 'users_permissions');
    }
}
