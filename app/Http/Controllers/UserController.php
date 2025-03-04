<?php

namespace App\Http\Controllers;

use App\Http\Requests\UserLoginRequest;
use App\Http\Requests\UserRegisterRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;
class UserController extends Controller
{
    public function register(UserRegisterRequest $request): UserResource{
        $data = $request->validated();
        if(User::where('username', $data['username'])->exists()){
            //jika user ini sudah ada di database
            throw new HttpResponseException(response([
                "errors" => [
                    "username" => "Username already exists"
                ]
            ],400));
        }

        $user = new User($data);
        $user->password  = Hash::make($data['password']);
        $user->save();
        return new UserResource($user);
    }

    public function login(UserLoginRequest $request){
        if(!Auth::attempt($request->only('email', 'password'))){
            return response([
                'message' => 'Invalid Credentials'
            ], Response::HTTP_UNAUTHORIZED);
        }

        $user = Auth::user();
        $token = $user->createToken('token')->plainTextToken;

        return response([
            'message' => 'Login Successful',
            'user' => new UserResource($user),
        ])->withCookie($token);
    }
}
