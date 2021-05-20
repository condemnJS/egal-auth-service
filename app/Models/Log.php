<?php

namespace App\Models;

use Egal\Model\Model as EgalModel;
use Illuminate\Support\Facades\Request;

/**
 * @property $id
 * @property $ip_address {@property-type field}
 * @property $user_id {@property-type field} {@validation-rules required}
 * @property $created_at {@property-type field}
 * @property $updated_at {@property-type field}
 *
 * @action getMetadata {@statuses-access guest,logged}
 * @action getItem {@statuses-access guest,logged}
 * @action getItems {@statuses-access guest}
 * @action create {@statuses-access guest}
 * @action update {@statuses-access logged} {@permissions-access super_permission}
 * @action delete {@statuses-access logged} {@permissions-access super_permission}
 */
class Log extends EgalModel
{
    public static function createLog($attr = [])
    {
        $log = new static();
        $log->ip_address = $attr['ip_address'];
        $log->user_id = $attr['user_id'];

        $log->save();
    }
}
