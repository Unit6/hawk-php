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

// send authenticated request
$credentialsFunc('1', function ($err, $credentials) use ($credentialsFunc) {
    if ($err) {
        // handle the error.
        var_dump($err); exit;
    }

    $options = [
        'credentials' => $credentials,
        'content_type' => 'application/json',
        'payload' => json_encode(['foo' => 'bar']),
        'timestamp' => 1454097545,
        'nonce' => '56abc49c419c1',
        'ext' => 'user'
    ];

    $header = Hawk\Client::header('http://www.example.com/users/1/', 'GET', $options);

    // use this for your Authorization header in your request.
    // $header['field'];
    // Hawk id="1", ts="1454097545", nonce="56abc49c419c1", hash="PUk+U4tj/ssBHHLygBeFGY35uc+UJQCFHpk1cfwRn5w=", ext="user", mac="WU7NKoqJ22iBY2lb261jPOwmTuIRHKKzJzScYKGp+pc="
    var_dump($header);
});