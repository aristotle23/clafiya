<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $reqest){
        $input = $this->validate($reqest,[
            'email' => "required|email|unique:users,email",
            'phone' => "bail|unique:users,phone|numeric|digits_between:10,13",
            'name' => "required",
            'password' => "required"
        ]);
        $input['password'] = Hash::make($input['password']);
        $user = User::create($input);
        $token = $user->createToken('UserToken')->accessToken;
        return response(['data' => $user, "token" => $token]);
    }
    public function login(Request $reqest)
    {
        $input = $this->validate($reqest,[
            "username" => "required",
            "password" => "required"
        ]);
        $fieldType = filter_var($input['username'],FILTER_VALIDATE_EMAIL) ? 'email' : "phone";
        if( !Auth::attempt([$fieldType => $input['username'], 'password' => $input['password']]) ){
            return response(["message" => "Provided credentials are incorrect"]);
        }
        $user = Auth::user();
        $user->tokens()->delete();
        $token = $user->createToken('UserToken')->accessToken;
        return response(['data' => $user, "token" => $token]);
    }
}
