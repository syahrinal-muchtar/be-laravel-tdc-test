<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        //set validation
        $validator = Validator::make($request->all(), [
            'name'      => 'required',
            'email'     => 'required|email|unique:users',
            'password'  => 'required|min:8'
        ]);

        //if validation fails
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        //create user
        $user = User::create([
            'name'      => $request->name,
            'email'     => $request->email,
            'password'  => bcrypt($request->password)
        ]);

        //return response JSON user is created
        if ($user) {
            return response()->json([
                'success' => true,
                'user'    => $user,
            ], 201);
        }

        //return JSON process insert failed 
        return response()->json([
            'success' => false,
        ], 409);
    }
    public function login(Request $request)
    {
        //set validation
        $validator = Validator::make($request->all(), [
            'email'     => 'required',
            'password'  => 'required'
        ]);

        //if validation fails
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        //get credentials from request
        $credentials = $request->only('email', 'password');

        //if auth failed
        if (!$token = auth()->guard('api')->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Email atau Password Anda salah'
            ], 401);
        }

        //if auth success
        return response()->json([
            'success' => true,
            'user'    => auth()->guard('api')->user(),
            'token'   => $token
        ], 200);
    }
    public function logout()
    {
        //remove token
        $removeToken = JWTAuth::invalidate(JWTAuth::getToken());

        if ($removeToken) {
            //return response JSON
            return response()->json([
                'success' => true,
                'message' => 'Logout Berhasil!',
            ]);
        }
    }
}
