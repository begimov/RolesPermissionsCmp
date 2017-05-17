<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function (\Illuminate\Http\Request $req) {
    $user = $req->user();
    // $user->givePermissionTo('edit posts', 'delete posts');
    // $user->updatePermissions('delete posts');
    // $user->withdrawPermissionTo('edit posts', 'delete posts');
    return view('welcome');
});

Auth::routes();

Route::get('/home', 'HomeController@index')->name('home');

Route::group(['middleware' => 'role:admin'], function () {
  Route::group(['middleware' => 'role:admin,delete users'], function () {
      Route::get('/admin/users', function () {
          return 'Delete users';
      });
  });
    Route::get('/admin', function () {
        return 'Admin panel';
    });
});
