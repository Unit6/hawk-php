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
 * Tests for using a Bewit to secure a given URI.
 *
 * @author Unit6 <team@unit6websites.com>
 */
class BewitTest extends \PHPUnit_Framework_TestCase
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
     * should generate a bewit then successfully authenticate it
     */
    public function testGenerateBewitThenSuccessfullyAuthenticateIt()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?a=1&b=2',
            'host' => 'example.com',
            'port' => 80
        ];

        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err, $credentials1) use ($request, $credentialsFunc) {
            $this->assertNull($err);

            $uri = 'http://example.com/resource/4?a=1&b=2';

            $options = [
                'credentials' => $credentials1,
                'ttl_sec' => 60 * 60 * 24 * 365 * 100,
                'ext' => 'some-app-data'
            ];

            $bewit = Bewit::generate($uri, $options);

            $request['url'] .= '&bewit=' . $bewit;

            Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials2 = null, $attributes = null) {
                $this->assertNull($err);
                $this->assertEquals('steve', $credentials2['user']);
                $this->assertEquals('some-app-data', $attributes['ext']);
            });
        });
    }

    /**
     * should generate a bewit then successfully authenticate it (no ext)
     */
    public function testGenerateBewitWithSuccessfullyAuthenticateItNoExt()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?a=1&b=2',
            'host' => 'example.com',
            'port' => 80
        ];

        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err, $credentials1) use ($request, $credentialsFunc) {
            $this->assertNull($err);

            $uri = 'http://example.com/resource/4?a=1&b=2';

            $options = [
                'credentials' => $credentials1,
                'ttl_sec' => 60 * 60 * 24 * 365 * 100
            ];

            $bewit = Bewit::generate($uri, $options);

            $request['url'] .= '&bewit=' . $bewit;

            Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials2 = null, $attributes = null) {
                $this->assertNull($err);
                $this->assertEquals('steve', $credentials2['user']);
            });
        });
    }

    /**
     * should successfully authenticate a request (last param)
     */
    public function testSuccessfullyAuthenticateRequestWithLastParam()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = $this->credentialsFunc;

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNull($err);
            $this->assertEquals('steve', $credentials['user']);
            $this->assertEquals('some-app-data', $attributes['ext']);
        });
    }

    /**
     * should successfully authenticate a request (first param)
     */
    public function testSuccessfullyAuthenticateRequestWithFirstParam()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ&a=1&b=2',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = $this->credentialsFunc;

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNull($err);
            $this->assertEquals('steve', $credentials['user']);
            $this->assertEquals('some-app-data', $attributes['ext']);
        });
    }

    /**
     * should successfully authenticate a request (only param)
     */
    public function testSuccessfullyAuthenticateRequestWithOnlyParam()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2NDFcZm1CdkNWT3MvcElOTUUxSTIwbWhrejQ3UnBwTmo4Y1VrSHpQd3Q5OXJ1cz1cc29tZS1hcHAtZGF0YQ',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = $this->credentialsFunc;

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNull($err);
            $this->assertEquals('steve', $credentials['user']);
            $this->assertEquals('some-app-data', $attributes['ext']);
        });
    }

    /**
     * should fail on multiple authentication
     */
    public function testFailOnMultipleAuthentication()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2NDFcZm1CdkNWT3MvcElOTUUxSTIwbWhrejQ3UnBwTmo4Y1VrSHpQd3Q5OXJ1cz1cc29tZS1hcHAtZGF0YQ',
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Basic asdasdasdasd'
        ];

        $credentialsFunc = $this->credentialsFunc;

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Multiple authentications', $err->getMessage());
        });
    }

    /**
     * should fail on method other than GET
     */
    public function testFailOnMethodOtherThanGET()
    {
        $credentialsFunc = $this->credentialsFunc;

        $credentialsFunc('123456', function ($err, $credentials1) use ($credentialsFunc) {
            $this->assertNull($err);

            $request = [
                'method' => 'POST',
                'url' => '/resource/4?filter=a',
                'host' => 'example.com',
                'port' => 8080
            ];

            $exp = floor(Utils::getTimeNowMs() / 1000) + 60;
            $ext = 'some-app-data';

            $artifacts = [
                'ts' => $exp,
                'nonce' => '',
                'method' => $request['method'],
                'resource' => $request['url'],
                'host' => $request['host'],
                'port' => $request['port'],
                'ext' => $ext
            ];

            $mac = Crypto::getArtifactsMac('bewit', $credentials1, $artifacts);

            $bewit = $credentials1['id'] . '\\' . $exp . '\\' . $mac . '\\' . $ext;

            $request['url'] .= '&bewit=' . Utils::getBase64Encode($bewit);

            Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials2 = null, $attributes = null) {
                $this->assertNotNull($err);
                $this->assertEquals('Invalid method', $err->getMessage());
            });
        });
    }

    /**
     * should fail on invalid host header
     */
    public function testFailOnInvalidHostHeader()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            'headers' => [
                'host' => 'example.com:something'
            ]
        ];

        $credentialsFunc = $this->credentialsFunc;

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid Host header', $err->getMessage());
        });
    }

    /**
     * should fail on empty bewit
     */
    public function testFailOnEmptyBewit()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = $this->credentialsFunc;

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Empty bewit', $err->getMessage());
        });
    }

    /**
     * should fail on invalid bewit
     */
    public function testFailOnInvalidBewit()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=*',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = $this->credentialsFunc;

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid bewit encoding', $err->getMessage());
        });
    }

    /**
     * should fail on missing bewit
     */
    public function testFailOnMissingBewit()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = $this->credentialsFunc;

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertNull($err->getMessage());
        });
    }

    /**
     * should fail on invalid bewit structure
     */
    public function testFailOnInvalidBewitStructure()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=abc',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = $this->credentialsFunc;

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid bewit structure', $err->getMessage());
        });
    }

    /**
     * should fail on empty bewit attribute
     */
    public function testFailOnEmptyBewitAttribute()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=YVxcY1xk',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = $this->credentialsFunc;

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Missing bewit attributes', $err->getMessage());
        });
    }

    /**
     * should fail on missing bewit id attribute
     */
    public function testFailOnMissingBewitIDAttribute()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=XDQ1NTIxNDc2MjJcK0JFbFhQMXhuWjcvd1Nrbm1ldGhlZm5vUTNHVjZNSlFVRHk4NWpTZVJ4VT1cc29tZS1hcHAtZGF0YQ',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = $this->credentialsFunc;

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Missing bewit attributes', $err->getMessage());
        });
    }

    /**
     * should fail on expired access
     */
    public function testFailOnExpiredAccess()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?a=1&b=2&bewit=MTIzNDU2XDEzNTY0MTg1ODNcWk1wZlMwWU5KNHV0WHpOMmRucTRydEk3NXNXTjFjeWVITTcrL0tNZFdVQT1cc29tZS1hcHAtZGF0YQ',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = $this->credentialsFunc;

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Access expired', $err->getMessage());
        });
    }

    /**
     * should fail on credentials function error
     */
    public function testFailOnCredentialsFunctionError()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = function ($id, $callback) {
            $callback(Error::badRequest('Boom'));
        };

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Boom', $err->getMessage());
        });
    }

    /**
     * should fail on credentials function error with credentials
     */
    public function testFailOnCredentialsFunctionErrorWithCredentials()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = function ($id, $callback) {
            $callback(Error::badRequest('Boom'), ['some' => 'value']);
        };

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Boom', $err->getMessage());
            $this->assertEquals('value', $credentials['some']);
        });
    }

    /**
     * should fail on null credentials function response
     */
    public function testFailOnNullCredentialsFunctionResponse()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = function ($id, $callback) {
            $callback(null, null);
        };

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Unknown credentials', $err->getMessage());
        });
    }

    /**
     * should fail on invalid credentials function response
     */
    public function testFailOnInvalidCredentialsFunctionResponse()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = function ($id, $callback) {
            $callback(null, []);
        };

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid credentials', $err->getMessage());
        });
    }

    /**
     * should fail on invalid credentials function response (unknown algorithm
     */
    public function testFailOnInvalidCredentialsFunctionResponseUnknownAlgorithm()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = function ($id, $callback) {
            $callback(null, ['key' => 'xxx', 'algorithm' => 'xxx']);
        };

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Unknown algorithm', $err->getMessage());
        });
    }

    /**
     * should fail on expired access
     */
    public function testFailWithBadMac()
    {
        $request = [
            'method' => 'GET',
            'url' => '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            'host' => 'example.com',
            'port' => 8080
        ];

        $credentialsFunc = function ($id, $callback) {
            $callback(null, ['key' => 'xxx', 'algorithm' => 'sha256']);
        };

        Bewit::authenticate($request, $credentialsFunc, [], function ($err = null, $credentials = null, $attributes = null) {
            $this->assertNotNull($err);
            $this->assertEquals('Bad mac', $err->getMessage());
        });
    }
}