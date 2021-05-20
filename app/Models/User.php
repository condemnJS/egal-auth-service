<?php /** @noinspection PhpMissingFieldTypeInspection */

namespace App\Models;

use App\Exceptions\PasswordHashException;
use Egal\Auth\Tokens\UserMasterToken;
use Egal\Auth\Tokens\UserServiceToken;
use Egal\Auth\Traits\Authenticatable;
use Egal\Exception\LoginAuthException;
use Egal\Exception\TokenExpiredAuthException;
use Egal\Exception\UserNotFoundAuthException;
use Egal\Exception\ValidateException;
use Egal\Model\Model;
use Egal\Model\Traits\UsesUuid;
use Egal\Core\Session;
use Exception;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Request;
use Illuminate\Support\Facades\Validator;
use Staudenmeir\EloquentHasManyDeep\HasManyDeep;
use Staudenmeir\EloquentHasManyDeep\HasRelationships;

/**
 * @property $id {@primary-key} {@property-type field}
 * @property $name {@property-type field} {@validation-rules required|string}
 * @property $surname {@property-type field} {@validation-rules required|string}
 * @property $patronymic {@property-type field} {@validation-rules required|string}
 * @property $email {@property-type field} {@validation-rules required|string|email|unique:users,email|min:5|max:55}
 * @property $phone {@property-type field} {@validation-rules required|numeric}
 * @property $password {@property-type field} {@validation-rules required|string}
 * @property $created_at {@property-type field}
 * @property $updated_at {@property-type field}
 *
 * @property Collection $roles {@property-type relation}
 * @property Collection $permissions {@property-type relation}
 *
 * @action register {@statuses-access guest}
 * @action registerByEmailAndPassword {@statuses-access guest}
 * @action login {@statuses-access guest}
 * @action loginByEmailAndPassword {@statuses-access guest}
 * @action actionLoginToService {@statuses-access guest}
 * @action logout {@statuses-access logged}
 */
class User extends Model
{

    use Authenticatable,
        UsesUuid,
        HasFactory,
        HasRelationships;

    protected $hidden = [
        'created_at',
        'updated_at',
    ];

    protected $guarder = [
        'created_at',
        'updated_at',
    ];

    protected $fillable = [
        'phone',
        'email',
        'password',
        'password_confirmation'
    ];

    private static $messages = [
        'login.required' => 'Введите логин',
        'login.min' => 'Поле логин должен содержать от 3 до 55 символов',
        'login.unique' => 'Данный логин уже занят',
        'password.required' => 'Введите пароль',
        'password_confirmation.required' => 'Введите пароль еще раз',
        'phone.required' => 'Введите телефон',
        'phone.numeric' => 'Поле может содержать только цифры',
        'phone.digits' => 'Поле должно содержать ровно 11 символов',
        'password.min' => 'Ваш пароль должен содержать от 6 до 16 символов',
        'password.max' => 'Ваш пароль должен содержать от 6 до 16 символов',
        'password.confirmed' => 'Пароли не совпадают',
        'email.min' => 'Поле должно содержать не менее 5 и не более 50 символов',
        'email.max' => 'Поле должно содержать не менее 5 и не более 50 символов',
        'email.email' => 'Введите действительный Email',
        'email.required' => 'Введите email',
        "email.unique" => 'Пользователь с данным e-mail уже существует'
    ];

    #region actions

    /**
     * @param string $name
     * @param string $surname
     * @param string $patronymic
     * @param string $email
     * @param string $phone
     * @param string $password_confirmation
     * @param string $password
     */
    public static function actionRegister(string $name, string $surname, string $patronymic, string $email, string $password, string $phone, string $password_confirmation)
    {
        $fields = [
            'name' => $name,
            'surname' => $surname,
            'patronymic' => $patronymic,
            'email' => $email,
            'password' => $password,
            'phone' => $phone,
            'password_confirmation' => $password_confirmation
        ];

        $rules = [
            'name' => 'required|string',
            'surname' => 'required|string',
            'patronymic' => 'required|string',
            'email' => 'required|email|unique:users,email|min:5|max:55',
            'password' => 'required|confirmed|min:6|max:16',
            'password_confirmation' => 'required',
            'phone' => ['required', 'numeric', 'digits:11']
        ];

        $validator = Validator::make($fields, $rules, self::$messages);

        if ($validator->fails()) {
            $validatorException = new ValidateException();
            $validatorException->setMessageBag($validator->errors());
            throw $validatorException;
        }

        $user = new static();
        $user->name = $name;
        $user->surname = $surname;
        $user->patronymic = $patronymic;
        $user->email = $email;
        $user->phone = $phone;
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

        if (!$hashedPassword) {
            throw new PasswordHashException('Password hash error!');
        }

        $user->password = $hashedPassword;
        $user->save();
        return $user;
    }

    /**
     * @param string $email
     * @param string $password
     * @return string
     * @throws LoginAuthException
     * @noinspection PhpUnused
     */
    public static function actionLoginByEmailAndPassword(string $email, string $password): string
    {
        $fields = [
            'email' => $email,
            'password' => $password
        ];

        $rules = [
            'email' => 'required|email',
            'password' => 'required'
        ];

        $validator = Validator::make($fields, $rules, self::$messages);

        if ($validator->fails()) {
            $validatorException = new ValidateException();
            $validatorException->setMessageBag($validator->errors());
            throw $validatorException;
        }

        /** @var User $user */
        $user = self::query()
            ->where('email', '=', $email)
            ->first();

        if (!$user || !password_verify($password, $user->password)) {
            throw new LoginAuthException('Неправильный Email или пароль');
        }

        $umt = new UserMasterToken();
        $umt->setSigningKey(config('app.service_key'));
        $umt->setAuthIdentification($user->getAuthIdentifier());

        Log::createLog(['user_id' => $user->id, 'ip_address' => Request::ip()]);

        return $umt->generateJWT();
    }

    public static function actionLogout()
    {
        return 'татар';
    }

    /**
     * @param string $token
     * @param string $serviceName
     * @return string
     * @throws LoginAuthException
     * @throws TokenExpiredAuthException
     * @throws UserNotFoundAuthException
     * @noinspection PhpUnused
     */
    final public static function actionLoginToService(string $token, string $serviceName): string
    {
        /** @var UserMasterToken $umt */
        $umt = UserMasterToken::fromJWT($token, config('app.service_key'));
        $umt->isAliveOrFail();

        /** @var User $user */
        $user = static::query()->find($umt->getAuthIdentification());
        /** @var Service $service */
        $service = Service::query()->find($serviceName);
        if (!$user) {
            throw new UserNotFoundAuthException();
        }
        if (!$service) {
            $thisServiceName = config('app.service_name');
            if ($serviceName === $thisServiceName) {
                $service = new Service();
                $service->id = $thisServiceName;
                $service->name = $thisServiceName;
                $service->key = config('app.service_key');
                $service->save();
            } else {
                throw new LoginAuthException('Service not found!');
            }
        }

        $ust = new UserServiceToken();
        $ust->setSigningKey($service->key);
        $ust->setAuthInformation($user->generateAuthInformation());

        return $ust->generateJWT();
    }

    #endregion actions

    #region relations

    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(Role::class, 'user_roles');
    }

    public function permissions(): HasManyDeep
    {
        return $this->hasManyDeep(
            Permission::class,
            [UserRole::class, Role::class, RolePermission::class],
            ['user_id', 'id', 'role_id', 'id'],
            ['id', 'role_id', 'id', 'permission_id']
        );
    }

    #endregion relations

    protected static function boot()
    {
        parent::boot();
        static::created(function (User $user) {
            $defaultRoles = Role::query()
                ->where('is_default', true)
                ->get();
            $user->roles()
                ->attach($defaultRoles->pluck('id'));
        });
    }

    protected function generateAuthInformation(): array
    {
        $result = $this->fresh()->toArray();
        $result['auth_identification'] = $this->{$this->getKeyName()};
        $rolesNames = $this->roles->pluck('id')->toArray();
        $permissionNames = $this->permissions->pluck('id')->toArray();
        $result = Arr::add($result, 'roles', array_unique($rolesNames));
        $result = Arr::add($result, 'permissions', array_unique($permissionNames));
        return $result;
    }

}

