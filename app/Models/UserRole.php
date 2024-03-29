<?php /** @noinspection PhpMissingFieldTypeInspection */

namespace App\Models;

use Egal\Model\Model;

/**
 * @property $id {@primary-key} {@property-type field}
 * @property $user_id {@property-type field} {@validation-rules required|numeric|exists:users}
 * @property $role_id {@property-type field} {@validation-rules required|string|exists:roles}
 * @property $created_at {@property-type field}
 * @property $updated_at {@property-type field}
 *
 * @action getItem {@roles-access admin,developer}
 * @action getItems {@roles-access admin,developer}
 * @action create {@roles-access admin,developer}
 * @action update {@roles-access admin,developer}
 * @action delete {@roles-access admin,developer}
 */
class UserRole extends Model
{

    protected $fillable = [
        'user_id',
        'role_id',
    ];

    protected $hidden = [
        'created_at',
        'updated_at',
    ];

}
