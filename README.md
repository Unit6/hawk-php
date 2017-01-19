# unit6/hawk 

A PHP Implementation of Hawk.

> Hawk is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial HTTP request cryptographic verification. — [Hawk][0]

## Implementation

Effort has been made to following the original Node.js package at [hueniverse/hawk][0]. This implementation should be compatibile with Hawk v4.x using protocol 1.0. As best as possible, considering the technical differences between JavaScript and PHP, the tests closely follow those of the original package.

## Requirements

- PHP 5.6.x

## Usage Example

Client code:

```php
// load the library.
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
```

Server code:

```php
// load the library.
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
```

## TODO

- Write tests for Utils, Crypto.
- Improve error messages with exceptions.
- Add better Crypto tools for improved PRNG.
- Publish to [Packagist][3] so you can install using [Composer][1].

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## License

MIT, see LICENSE.


[0]: https://github.com/hueniverse/hawk
[1]: https://getcomposer.org/
[2]: https://packagist.org/packages/unit6/hawk
[3]: https://packagist.org/
