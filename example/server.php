<?php
/*
 * This file is part of the Hawk package.
 *
 * (c) Unit6 <team@unit6websites.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

require dirname(__FILE__) . '/../autoload.php';

use Unit6\Hawk;

// declare credentials (usually stored in a database)
$credentials = [
    '1' => [
        'id' => '1', // Required by Hawk\Client::header
        'key' => 'secret',
        'algorithm' => 'sha256',
        'user' => 'john'
    ]
];

// credentials lookup function
$credentialsFunc = function ($id, $callback) use ($credentials) {
    // usually you're going to want to lookup these credentials from
    // a database using the $id:
    return $callback(null, $credentials[$id]);
};

// build the request.
$request = [
    'method' => 'GET',
    'url' => '/users/1/',
    'host' => 'www.example.com',
    'port' => 80,
    'authorization' => 'Hawk id="1", ts="1454097545", nonce="56abc49c419c1", hash="PUk+U4tj/ssBHHLygBeFGY35uc+UJQCFHpk1cfwRn5w=", ext="user", mac="WU7NKoqJ22iBY2lb261jPOwmTuIRHKKzJzScYKGp+pc="'
];

$options = [
    'localtime_offset_msec' => (1454097545 * 1000) - Hawk\Utils::getTimeNowMs()
];

// authenticate the request.
Hawk\Server::authenticate($request, $credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
    if ($err) {
        // handle the error.
        var_dump($err); exit;
    }

    // do something with the validated request.
    var_dump($credentials);
});