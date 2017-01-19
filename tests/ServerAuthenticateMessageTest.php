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
 * Tests for validating a message received by the Server from the Client.
 *
 * @author Unit6 <team@unit6websites.com>
 */
class ServerAuthenticateMessageTest extends \PHPUnit_Framework_TestCase
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
     * errors on invalid authorization (ts)
     */
    public function testErrorOnInvalidAuthorizationTimestamp()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $message = 'some message';

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, $message, $options);
            unset($auth['ts']);

            Server::authenticateMessage('example.com', 8080, $message, $auth, $credentialsFunc, [], function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Invalid authorization', $err->getMessage());
            });
        });
    }

    /**
     * errors on invalid authorization (nonce)
     */
    public function testErrorOnInvalidAuthorizationNonce()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $message = 'some message';

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, $message, $options);
            unset($auth['nonce']);

            Server::authenticateMessage('example.com', 8080, $message, $auth, $credentialsFunc, [], function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Invalid authorization', $err->getMessage());
            });
        });
    }

    /**
     * errors on invalid authorization (hash)
     */
    public function testErrorOnInvalidAuthorization()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $message = 'some message';

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, $message, $options);
            unset($auth['hash']);

            Server::authenticateMessage('example.com', 8080, $message, $auth, $credentialsFunc, [], function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Invalid authorization', $err->getMessage());
            });
        });
    }

    /**
     * errors with credentials
     */
    public function testErrorWithCredentials()
    {
        $credentialsFunc1 = $this->credentialsFunc;

        $credentialsFunc1('123456', function ($err = null, $credentials1 = null) {
            $this->assertNull($err);

            $message = 'some message';

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, $message, $options);

            $credentialsFunc2 = function ($id, $callback) {
                $callback(new Error('something'), [ 'some' => 'value' ]);
            };

            Server::authenticateMessage('example.com', 8080, $message, $auth, $credentialsFunc2, [], function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('something', $err->getMessage());
                $this->assertEquals('value', $credentials2['some']);
            });
        });
    }

    /**
     * errors on nonce collision
     */
    public function testErrorOnNonceCollision()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $message = 'some message';

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, $message, $options);

            $options = [
                'nonce_func' => function ($key, $nonce, $ts, $nonceCallback) {
                    $nonceCallback(true);
                }
            ];

            Server::authenticateMessage('example.com', 8080, $message, $auth, $credentialsFunc, $options, function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Invalid nonce', $err->getMessage());
            });

        });
    }

    /**
     * should generate an authorization then successfully parse it
     */
    public function testGenerateAuthorizationThenSuccessfullyParseIt()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $message = 'some message';

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, $message, $options);
            $this->assertNotEmpty($auth);

            Server::authenticateMessage('example.com', 8080, $message, $auth, $credentialsFunc, [], function ($err = null, $credentials2 = null) {
                $this->assertNull($err);
                $this->assertEquals('steve', $credentials2['user']);
            });
        });
    }

    /**
     * should fail authorization on mismatching host
     */
    public function testFailAuthorizationOnMismatchingHost()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $message = 'some message';

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, $message, $options);
            $this->assertNotEmpty($auth);

            Server::authenticateMessage('example1.com', 8080, $message, $auth, $credentialsFunc, [], function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Bad mac', $err->getMessage());
            });
        });
    }

    /**
     * should fail authorization on stale timestamp
     */
    public function testFailAuthorizationOnStaleTimestamp()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $message = 'some message';

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, $message, $options);
            $this->assertNotEmpty($auth);

            $options = [
                'localtime_offset_msec' => 100000
            ];

            Server::authenticateMessage('example.com', 8080, $message, $auth, $credentialsFunc, $options, function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Stale timestamp', $err->getMessage());
            });
        });
    }

    /**
     * overrides timestampSkewSec
     */
    public function testOverridesTimestampSkewInSeconds()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $message = 'some message';

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, $message, $options);
            $this->assertNotEmpty($auth);

            $options = [
                'timestamp_skew_sec: ' => 500
            ];

            Server::authenticateMessage('example.com', 8080, $message, $auth, $credentialsFunc, $options, function ($err = null, $credentials2 = null) {
                $this->assertNull($err);
            });
        });
    }

    /**
     * should fail authorization on invalid authorization
     */
    public function testFailAuthorizationOnInvalidAuthorization()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $message = 'some message';

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, $message, $options);
            $this->assertNotEmpty($auth);

            unset($auth['id']);

            Server::authenticateMessage('example.com', 8080, $message, $auth, $credentialsFunc, [], function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Invalid authorization', $err->getMessage());
            });
        });
    }

    /**
     * should fail authorization on bad hash
     */
    public function testFailAuthorizationOnBadHash()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, 'some message', $options);
            $this->assertNotEmpty($auth);

            Server::authenticateMessage('example.com', 8080, 'some message1', $auth, $credentialsFunc, [], function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Bad message hash', $err->getMessage());
            });
        });
    }

    /**
     * should fail authorization on nonce error
     */
    public function testFailAuthorizationOnNonceError()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, 'some message', $options);
            $this->assertNotEmpty($auth);

            $options = [
                'nonce_func' => function ($key, $nonce, $ts, $callback) {
                    $callback(new Error('kaboom'));
                }
            ];

            Server::authenticateMessage('example.com', 8080, 'some message', $auth, $credentialsFunc, $options, function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Invalid nonce', $err->getMessage());
            });
        });
    }

    /**
     * should fail authorization on credentials error
     */
    public function testFailAuthorizationOnCredentialsError()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, 'some message', $options);
            $this->assertNotEmpty($auth);

            $errFunc = function ($id, $callback) {
                $callback(new Error('kablooey'));
            };

            Server::authenticateMessage('example.com', 8080, 'some message', $auth, $errFunc, [], function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('kablooey', $err->getMessage());
            });
        });
    }

    /**
     * should fail authorization on missing credentials
     */
    public function testFailAuthorizationOnMissingCredentials()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, 'some message', $options);
            $this->assertNotEmpty($auth);

            $errFunc = function ($id, $callback) {
                $callback();
            };

            Server::authenticateMessage('example.com', 8080, 'some message', $auth, $errFunc, [], function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Unknown credentials', $err->getMessage());
            });
        });
    }

    /**
     * should fail authorization on invalid credentials
     */
    public function testFailAuthorizationOnInvalidCredentials()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, 'some message', $options);
            $this->assertNotEmpty($auth);

            $errFunc = function ($id, $callback) {
                $callback(null, []);
            };

            Server::authenticateMessage('example.com', 8080, 'some message', $auth, $errFunc, [], function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Invalid credentials', $err->getMessage());
            });
        });
    }

    /**
     * should fail authorization on invalid credentials algorithm
     */
    public function testFailAuthorizationOnInvalidCredentialsAlgorithm()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials1 = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $options = [
                'credentials' => $credentials1
            ];

            $auth = Client::message('example.com', 8080, 'some message', $options);
            $this->assertNotEmpty($auth);

            $errFunc = function ($id, $callback) {
                $callback(null, ['key' => '123', 'algorithm' => '456']);
            };

            Server::authenticateMessage('example.com', 8080, 'some message', $auth, $errFunc, [], function ($err = null, $credentials2 = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Unknown algorithm', $err->getMessage());
            });
        });
    }

    /**
     * should fail on missing host
     */
    public function testFailOnMissingHost()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials = null) use ($credentialsFunc) {
            $this->assertNull($err);

            $options = [
                'credentials' => $credentials
            ];

            $auth = Client::message(null, 8080, 'some message', $options);
            $this->assertNull($auth);
        });
    }

    /**
     * should fail on missing credentials
     */
    public function testFailOnMissingCredentials()
    {
        $auth = Client::message('example.com', 8080, 'some message', []);
        $this->assertNull($auth);
    }

    /**
     * should fail on invalid algorithm
     */
    public function testFailOnInvalidAlgorithm()
    {
        $auth = Client::message('example.com', 8080, 'some message', []);
        $this->assertNull($auth);

        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err = null, $credentials = null) {
            $this->assertNull($err);

            $creds = $credentials;
            $creds['algorithm'] = 'blah';

            $options = [
                'credentials' => $creds
            ];

            $auth = Client::message('example.com', 8080, 'some message', $options);
            $this->assertNull($auth);
        });
    }
}