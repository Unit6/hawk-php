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
 * Tests for validating a Client athenticate request using a Bewit.
 *
 * @author Unit6 <team@unit6websites.com>
 */
class ServerAuthenticateBewitTest extends \PHPUnit_Framework_TestCase
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
     * errors on uri too long
     */
    public function testErrorOnUriTooLong()
    {
        $long_url = '/';
        for ($i = 0; $i < 5000; $i++) {
            $long_url .= 'x';
        }

        $request = [
            'method' => 'GET',
            'url' => $long_url,
            'host' => 'example.com',
            'port' => 8080,
            'authorization' => 'Hawk id="1", ts="1353788437", nonce="k3j4h2", mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
        ];

        Server::authenticateBewit($request, $this->credentialsFunc, [], function ($err, $credentials = null, $artifacts = null) {
            $this->assertNotNull($err);
            $this->assertEquals(400, $err->getStatusCode());
            $this->assertEquals('Resource path exceeds max length', $err->getMessage());
        });
    }
}