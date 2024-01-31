<?php



use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Authcontroller;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->group(function() {
    Route::post('/logout', [Authcontroller::class, 'logout']);
    Route::get('/me', [Authcontroller::class, 'me']);

   
});

Route::post('/signup', [Authcontroller::class, 'signup' ]);
Route::post('/login', [Authcontroller::class, 'login' ]);

