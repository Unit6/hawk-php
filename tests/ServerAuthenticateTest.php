<?php
/*
 * This file is part of the Hawk package.
 *
 * (c) Unit6 <team@unit6websites.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Unit6\Hawk;

/**
 * Tests for validating a Client athenticate request by the Server.
 *
 * @author Unit6 <team@unit6websites.com>
 */
class ServerAuthenticateTest extends \PHPUnit_Framework_TestCase
{
    protected $credentialsFunc;

    protected function setUp()
    {
        $this->credentialsFunc = function ($id, callable $callback)
        {
            $credentials = [
                'id' => $id,
                'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                'algorithm' => ($id === '1' ? 'sha1' : 'sha256'),
                'user' => 'steve'
            ];

            return $callback(null, $credentials);
        };
    }

    protected function tearDown()
    {
        unset($this->credentialsFunc);
    }


    /**
     * parses a valid authentication header (sha1)
     */
    public function testParseValidAuthenticationHeaderWithSHA1()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="1", ts="1353788437", nonce="k3j4h2", mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNull($err);
            $this->assertEquals('steve', $credentials['user']);
        });
    }

    /**
     * parses a valid authentication header (sha256)
     */
    public function testParseValidAuthenticationHeaderWithSHA256()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/1?b=1&a=2',
            'host' => 'example.com',
            'port' => 8000,
            'authorization' => 'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", mac="m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=", ext="some-app-data"'
        ];

        $options = [
            'localtime_offset_msec' => 1353832234000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNull($err);
            $this->assertEquals('steve', $credentials['user']);
        });
    }

    /**
     * parses a valid authentication header (host override)
     */
    public function testParseValidAuthenticationHeaderWithHostOverride()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'headers' => [
                'host' => 'example1.com:8080',
                'authorization' => 'Hawk id="1", ts="1353788437", nonce="k3j4h2", mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
            ]
        ];

        $options = [
            'host' => 'example.com',
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNull($err);
            $this->assertEquals('steve', $credentials['user']);
        });
    }

    /**
     * parses a valid authentication header (host port override)
     */
    public function testParseValidAuthenticationHeaderWithHostPortOverride()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'headers' => [
                'host' => 'example1.com:80',
                'authorization' => 'Hawk id="1", ts="1353788437", nonce="k3j4h2", mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
            ]
        ];

        $options = [
            'host' => 'example.com',
            'port' => '8080',
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNull($err);
            $this->assertEquals('steve', $credentials['user']);
        });
    }

    /**
     * parses a valid authentication header (POST with payload)
     */
    public function testParseValidAuthenticationHeaderPayloadWithPOST()
    {
        $request = [
            'method' => 'POST',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => '8080',
            'authorization' => 'Hawk id="123456", ts="1357926341", nonce="1AwuJD", hash="qAiXIVv+yjDATneWxZP2YCTa9aHRgQdnH9b3Wc+o3dg=", ext="some-app-data", mac="UeYcj5UoTVaAWXNvJfLVia7kU3VabxCqrccXP8sUGC4="'
        ];

        $options = [
            'localtime_offset_msec' => 1357926341000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNull($err);
            $this->assertEquals('steve', $credentials['user']);
        });
    }

    /**
     * errors on missing hash
     */
    public function testErrorOnMissingHash()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/1?b=1&a=2',
            'host' => 'example.com',
            'port' => '8000',
            'authorization' => 'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", mac="m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=", ext="some-app-data"'
        ];

        $options = [
            'payload' => 'body',
            'localtime_offset_msec' => 1353832234000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Missing required payload hash', $err->getMessage());
        });
    }

    /**
     * errors on a stale timestamp
     */
    public function testErrorOnStaleTimestamp()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => '8080',
            'authorization' => 'Hawk id="123456", ts="1362337299", nonce="UzmxSs", ext="some-app-data", mac="wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w="'
        ];

        Server::authenticate($request, $this->credentialsFunc, [], function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Stale timestamp', $err->getMessage());
            $this->assertArrayHasKey('WWW-Authenticate', $err->getHeaders());

            $header = $err->getHeader('WWW-Authenticate');

            $pattern = '/^Hawk ts\=\"(\d+)\"\, tsm\=\"([^\"]+)\"\, error=\"Stale timestamp\"$/';
            preg_match($pattern, $header, $ts);

            $this->assertNotEmpty($ts);

            $now = Utils::getTimeNowMs();

            $expected = (integer) $ts[1] * 1000;
            $min = $now - 1000;
            $max = $now + 1000;

            $this->assertTrue(($min <= $expected) && ($expected <= $max));

            $response = [
                'headers' => [
                    'www-authenticate' => $header
                ]
            ];

            $result = Client::authenticate($response, $credentials, $artifacts);

            $this->assertTrue($result);
        });
    }

    /**
     * errors on a replay
     */
    public function testErrorOnReplay()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=", ext="hello"'
        ];

        $memoryCache = [];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs(),
            'nonce_func' => function ($key, $nonce, $ts, $callback) use (&$memoryCache) {
                $i = $key . $nonce;

                if (isset($memoryCache[$i])) {
                    return $callback(new Error());
                }

                $memoryCache[$i] = true;
                return $callback();
            }
        ];

        $credentialsFunc = $this->credentialsFunc;

        $second = function ($err, $credentials = null, $artifacts = null) use ($request, $credentialsFunc, $options) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid nonce', $err->getMessage());
        };

        $first = function ($err, $credentials = null, $artifacts = null) use ($request, $credentialsFunc, $options, $second) {
            $this->assertNull($err);
            $this->assertEquals('steve', $credentials['user']);

            Server::authenticate($request, $credentialsFunc, $options, $second);
        };

        Server::authenticate($request, $credentialsFunc, $options, $first);
    }

    /**
     * does not error on nonce collision if keys differ
     */
    public function testNoErrorOnNONCECollisionIfKeysDiffer()
    {
        $reqSteve = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=", ext="hello"'
        ];

        $reqBob = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="456", ts="1353788437", nonce="k3j4h2", mac="LXfmTnRzrLd9TD7yfH+4se46Bx6AHyhpM94hLCiNia4=", ext="hello"'
        ];

        $credentialsFunc = function ($id, callable $callback)
        {
            $credentials = [
                '123' => [
                    'id' => $id,
                    'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    'algorithm' => ($id === '1' ? 'sha1' : 'sha256'),
                    'user' => 'steve'
                ],
                '456' => [
                    'id' => $id,
                    'key' => 'xrunpaw3489ruxnpa98w4rxnwerxhqb98rpaxn39848',
                    'algorithm' => ($id === '1' ? 'sha1' : 'sha256'),
                    'user' => 'bob'
                ]
            ];

            return $callback(null, $credentials[$id]);
        };

        $memoryCache = [];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs(),
            'nonce_func' => function ($key, $nonce, $ts, $callback) use (&$memoryCache) {
                $i = $key . $nonce;

                if (isset($memoryCache[$i])) {
                    return $callback(new Error());
                }

                $memoryCache[$i] = true;
                return $callback();
            }
        ];

        $cbBob = function ($err, $credentials = null, $artifacts = null) {
            $this->assertNull($err);
            $this->assertEquals('bob', $credentials['user']);
        };

        $cbSteve = function ($err, $credentials = null, $artifacts = null) use ($reqBob, $credentialsFunc, $options, $cbBob) {
            $this->assertNull($err);
            $this->assertEquals('steve', $credentials['user']);

            Server::authenticate($reqBob, $credentialsFunc, $options, $cbBob);
        };

        Server::authenticate($reqSteve, $credentialsFunc, $options, $cbSteve);
    }

    /**
     * errors on an invalid authentication header: wrong scheme
     */
    public function testErrorOnInvalidAuthenticationHeaderWithWrongScheme()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Basic asdasdasdasd'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertNull($err->getMessage());
        });
    }

    /**
     * errors on an invalid authentication header: no scheme
     */
    public function testErrorOnInvalidAuthenticationHeaderWithNoScheme()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => '!@#'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid header syntax', $err->getMessage());
        });
    }

    /**
     * errors on an missing authorization header
     */
    public function testErrorOnMissingAuthorizationHeader()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080
        ];

        Server::authenticate($request, $this->credentialsFunc, [], function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertNull($err->getMessage());
        });
    }

    /**
     * errors on an missing host header
     */
    public function testErrorOnMissingHostHeader()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'headers' => [
                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            ]
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid Host header', $err->getMessage());
        });
    }

    /**
     * @group attr
     * errors on an missing authorization attribute (id)
     */
    public function testErrorOnMissingAuthorizationAttributeID()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Missing attributes', $err->getMessage());
        });
    }

    /**
     * @group attr
     * errors on an missing authorization attribute (ts)
     */
    public function testErrorOnMissingAuthorizationAttributeTimestamp()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Missing attributes', $err->getMessage());
        });
    }

    /**
     * @group attr
     * errors on an missing authorization attribute (nonce)
     */
    public function testErrorOnMissingAuthorizationAttributeNONCE()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", ts="1353788437", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Missing attributes', $err->getMessage());
        });
    }

    /**
     * @group attr
     * errors on an missing authorization attribute (mac)
     */
    public function testErrorOnMissingAuthorizationAttributeMAC()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", ext="hello"'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Missing attributes', $err->getMessage());
        });
    }

    /**
     * @group attr
     * errors on an unknown authorization attribute
     */
    public function testErrorOnUnknownAuthorizationAttribute()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", x="3", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Unknown attribute: x', $err->getMessage());
        });
    }

    /**
     * @group attr
     * errors on an bad authorization header format
     */
    public function testErrorOnBadAuthorizationHeaderFormat()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => "Hawk id=\"123\\\", " . 'ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Bad header format', $err->getMessage());
        });
    }

    /**
     * @group attr
     * errors on an bad authorization attribute value
     */
    public function testErrorOnBadAuthorizationAttributeValue()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => "Hawk id=\"\t\", " . 'ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Bad attribute value: id', $err->getMessage());
        });
    }

    /**
     * @group attr
     * errors on an empty authorization attribute value
     */
    public function testErrorOnEmptyAuthorizationAttributeValue()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Bad attribute value: id', $err->getMessage());
        });
    }

    /**
     * @group attr
     * errors on duplicated authorization attribute key
     */
    public function testErrorOnDuplicatedAuthorizationAttributeKey()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", id="456", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Duplicate attribute: id', $err->getMessage());
        });
    }

    /**
     * @group attr
     * errors on an invalid authorization header format
     */
    public function testErrorOnInvalidAuthorizationHeaderFormat()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk'
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid header syntax', $err->getMessage());
        });
    }

    /**
     * errors on an bad host header (missing host)
     */
    public function testErrorOnBadHostHeaderWithMissingHost()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'headers' => [
                'host' => ':8080',
                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            ]
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid Host header', $err->getMessage());
        });
    }

    /**
     * errors on an bad host header (pad port)
     */
    public function testErrorOnBadHostHeaderWithPadPort()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'headers' => [
                'host' => 'example.com:something',
                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            ]
        ];

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $this->credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid Host header', $err->getMessage());
        });
    }

    /**
     * errors on credentialsFunc error
     */
    public function testErrorOnCredentialsFuncError()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $credentialsFunc = function ($id, $callback) {
            return $callback(new Error('Unknown user'));
        };

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Unknown user', $err->getMessage());
        });
    }

    /**
     * errors on credentialsFunc error (with credentials)
     */
    public function testErrorOnCredentialsFuncErrorWithCredentials()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $credentialsFunc = function ($id, $callback) {
            $item = [ 'some' => 'value' ];
            return $callback(new Error('Unknown user'), $item);
        };

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Unknown user', $err->getMessage());
            $this->assertEquals('value', $credentials['some']);
        });
    }

    /**
     * errors on missing credentials
     */
    public function testErrorOnMissingCredentials()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $credentialsFunc = function ($id, $callback) {
            return $callback(null, null);
        };

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Unknown credentials', $err->getMessage());
        });
    }

    /**
     * errors on invalid credentials (id)
     */
    public function testErrorOnInvalidCredentialsWithoutID()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $credentialsFunc = function ($id, $callback) {
            $credentials = [
                'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                'user' => 'steve'
            ];
            return $callback(null, $credentials);
        };

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid credentials', $err->getMessage());
            $this->assertEquals('HTTP/1.1 500 Internal Server Error', $err->getHeader(0));
        });
    }

    /**
     * errors on invalid credentials (key)
     */
    public function testErrorOnInvalidCredentialsWithoutKey()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $credentialsFunc = function ($id, $callback) {
            $credentials = [
                'key' => '23434d3q4d5345d',
                'user' => 'steve'
            ];
            return $callback(null, $credentials);
        };

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid credentials', $err->getMessage());
            $this->assertEquals('HTTP/1.1 500 Internal Server Error', $err->getHeader(0));
        });
    }

    /**
     * errors on unknown credentials algorithm
     */
    public function testErrorOnUnknownCredentialsAlgorithm()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $credentialsFunc = function ($id, $callback) {
            $credentials = [
                'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                'algorithm' => 'hmac-sha-0',
                'user' => 'steve'
            ];
            return $callback(null, $credentials);
        };

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Unknown algorithm', $err->getMessage());
            $this->assertEquals('HTTP/1.1 500 Internal Server Error', $err->getHeader(0));
        });
    }

    /**
     * errors on unknown bad mac
     */
    public function testErrorOnUnknownBadMAC()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?filter=a',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcU4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
        ];

        $credentialsFunc = function ($id, $callback) {
            $credentials = [
                'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                'algorithm' => 'sha256',
                'user' => 'steve'
            ];
            return $callback(null, $credentials);
        };

        $options = [
            'localtime_offset_msec' => 1353788437000 - Utils::getTimeNowMs()
        ];

        Server::authenticate($request, $credentialsFunc, $options, function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Bad mac', $err->getMessage());
        });
    }
}