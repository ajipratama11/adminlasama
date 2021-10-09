<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;

class UserController extends Controller
{
    //
    public function register(Request $request)
    {
        try {
            $request->validate([
                'name' => ['required', 'string', 'max:255'],
                'username' => ['required', 'string', 'max:255', 'unique:users'],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
                'phone' => ['required', 'string', 'max:255'],
                'password' => ['required', 'string', new Password]
            ]);

            User::create([
                'name' => $request->name,
                'username' => $request->username,
                'email' => $request->email,
                'phone' => $request->phone,
                'password' => Hash::make($request->password),
            ]);

            $user = User::where('email', $request->email)->first();
            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'typeToken' => 'Bearer',
                'user' => $user
            ], 'Berhasil Register');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Gagal Register',
                'error' => $error,
            ], 'Authorized Failled', 500);
        }
    }

    public function login(Request $request)
    {
        try {
            $request->validate([
                'email' => 'required|email',
                'password' => 'required'
            ]);

            $field_login = request(['email', 'password']);
            if (!Auth::attempt($field_login)) {
                return ResponseFormatter::error([
                    'message' => 'Gagal Login',
                ], 'Authentication Failed', 500);
            }

            $user = User::where('email', $request->email)->first();

            if (!Hash::check($request->password, $user->password, [])) {
                throw new \Exception('Invalid Login');
            }

            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return ResponseFormatter::success([
                'message' => 'Berhasil Login',
                'access_token' => $tokenResult,
                'type_token' => 'Bearer',
                'user' => $user
            ], 'Authorized');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Mungkin ada yang salah',
            ], 'Authentication Failed', 500);
        }
    }

    public function fetch(Request $request)
    {
        return ResponseFormatter::success($request->user(), 'Data User berhasil diambil');
    }

    public function updateProfil(Request $request)
    {
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'username' => ['required', 'string', 'max:255', 'unique:users'],
            'phone' => ['required', 'string', 'max:255'],
        ]);
         $data = $request->all();
         $user = Auth::user();
         $user->update($data);

         return ResponseFormatter::success($user, 'Profil TerUpdate');
    }
    public function logout(Request $request)
    {
        $accessToken = $request->user()->currentAccessToken()->delete();
        return ResponseFormatter::success($accessToken, 'Berhasil Logout');
    }
}
