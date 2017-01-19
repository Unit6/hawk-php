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
 * Tests for building the Client authorization header.
 *
 * @author Unit6 <team@unit6websites.com>
 */
class ClientHeaderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * returns a valid authorization header (sha1)
     */
    public function testValidAuthorizationHeaderWithSHA1()
    {
        $credentials = [
            'id' => '123456',
            'key'=> '2983d45yun89q',
            'algorithm' => 'sha1'
        ];

        $options = [
            'credentials' => $credentials,
            'ext' => 'Bazinga!',
            'timestamp' => 1353809207,
            'nonce' => 'Ygvqdz',
            'payload' => 'something to write about',
        ];

        $uri = 'http://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, 'POST', $options);

        $this->assertArrayHasKey('field', $header);

        $field = 'Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="bsvY3IfUllw6V5rvk4tStEvpBhE=", ext="Bazinga!", mac="qbf1ZPG/r/e06F4ht+T77LXi5vw="';

        $this->assertEquals($field, $header['field']);
    }

    /**
     * returns a valid authorization header (sha256)
     */
    public function testValidAuthorizationHeaderWithSHA256()
    {
        $credentials = [
            'id' => '123456',
            'key'=> '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $options = [
            'credentials' => $credentials,
            'ext' => 'Bazinga!',
            'timestamp' => 1353809207,
            'nonce' => 'Ygvqdz',
            'payload' => 'something to write about',
            'content_type' => 'text/plain'
        ];

        $uri = 'https://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, 'POST', $options);

        $this->assertArrayHasKey('field', $header);

        $field = 'Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", ext="Bazinga!", mac="q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8="';

        $this->assertEquals($field, $header['field']);
    }

    /**
     * returns a valid authorization header (no ext)
     */
    public function testValidAuthorizationHeaderWithNoExt()
    {
        $credentials = [
            'id' => '123456',
            'key'=> '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'Ygvqdz',
            'payload' => 'something to write about',
            'content_type' => 'text/plain'
        ];

        $uri = 'https://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, 'POST', $options);

        $this->assertArrayHasKey('field', $header);

        $field = 'Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="';

        $this->assertEquals($field, $header['field']);
    }

    /**
     * returns a valid authorization header (null ext)
     */
    public function testValidAuthorizationHeaderWithNullExt()
    {
        $credentials = [
            'id' => '123456',
            'key'=> '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'Ygvqdz',
            'payload' => 'something to write about',
            'content_type' => 'text/plain',
            'ext' => null
        ];

        $uri = 'https://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, 'POST', $options);

        $this->assertArrayHasKey('field', $header);

        $field = 'Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="';

        $this->assertEquals($field, $header['field']);
    }

    /**
     * returns a valid authorization header (empty payload)
     */
    public function testValidAuthorizationHeaderWithEmptyPayload()
    {
        $credentials = [
            'id' => '123456',
            'key'=> '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'Ygvqdz',
            'payload' => '',
            'content_type' => 'text/plain',
            'ext' => null
        ];

        $uri = 'https://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, 'POST', $options);

        $this->assertArrayHasKey('field', $header);

        $field = 'Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=", mac="U5k16YEzn3UnBHKeBzsDXn067Gu3R4YaY6xOt9PYRZM="';

        $this->assertEquals($field, $header['field']);
    }

    /**
     * returns a valid authorization header (pre hashed payload)
     */
    public function testValidAuthorizationHeaderWithPreHashedPayload()
    {
        $credentials = [
            'id' => '123456',
            'key'=> '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'Ygvqdz',
            'payload' => 'something to write about',
            'content_type' => 'text/plain',
            'ext' => null
        ];

        $options['hash'] = Crypto::getPayloadHash(
            $options['payload'],
            $credentials['algorithm'],
            $options['content_type']
        );

        $uri = 'https://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, 'POST', $options);

        $this->assertArrayHasKey('field', $header);

        $field = 'Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="';

        $this->assertEquals($field, $header['field']);
    }

    /**
     * errors on missing uri
     */
    public function testErrorsOnMissingURI()
    {
        $header = Client::header('', 'POST');

        $this->assertArrayHasKey('err', $header);

        $this->assertEquals('', $header['field']);
        $this->assertEquals('Invalid argument type', $header['err']);
    }

    /**
     * errors on invalid uri
     */
    public function testErrorsOnInvalidURI()
    {
        $header = Client::header(4, 'POST');

        $this->assertArrayHasKey('err', $header);

        $this->assertEquals('', $header['field']);
        $this->assertEquals('Invalid argument type', $header['err']);
    }

    /**
     * errors on missing method
     */
    public function testErrorsOnMissingMethod()
    {
        $uri = 'https://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, '');

        $this->assertArrayHasKey('err', $header);

        $this->assertEquals('', $header['field']);
        $this->assertEquals('Invalid argument type', $header['err']);
    }

    /**
     * errors on invalid method
     */
    public function testErrorsOnInvalidMethod()
    {
        $uri = 'https://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, 5);

        $this->assertArrayHasKey('err', $header);

        $this->assertEquals('', $header['field']);
        $this->assertEquals('Invalid argument type', $header['err']);
    }

    /**
     * errors on missing options
     */
    public function testErrorsOnMissingOptions()
    {
        $uri = 'https://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, 'POST');

        $this->assertArrayHasKey('err', $header);

        $this->assertEquals('', $header['field']);
        $this->assertEquals('Invalid argument type', $header['err']);
    }

    /**
     * errors on invalid credentials (id)
     */
    public function testErrorsOnInvalidCredentialsID()
    {
        $credentials = [
            'key'=> '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $options = [
            'credentials' => $credentials,
            'ext' => 'Bazinga',
            'timestamp' => 1353809207
        ];

        $uri = 'https://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, 'POST', $options);

        $this->assertArrayHasKey('err', $header);

        $this->assertEquals('', $header['field']);
        $this->assertEquals('Invalid credential object', $header['err']);
    }

    /**
     * errors on missing credentials
     */
    public function testErrorsOnMissingCredentials()
    {
        $options = [
            'ext' => 'Bazinga',
            'timestamp' => 1353809207
        ];

        $uri = 'https://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, 'POST', $options);

        $this->assertArrayHasKey('err', $header);

        $this->assertEquals('', $header['field']);
        $this->assertEquals('Invalid credential object', $header['err']);
    }

    /**
     * errors on invalid credentials
     */
    public function testErrorsOnInvalidCredentials()
    {
        $credentials = [
            'id'=> '123456',
            'algorithm' => 'sha256'
        ];

        $options = [
            'credentials' => $credentials,
            'ext' => 'Bazinga',
            'timestamp' => 1353809207
        ];

        $uri = 'https://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, 'POST', $options);

        $this->assertArrayHasKey('err', $header);

        $this->assertEquals('', $header['field']);
        $this->assertEquals('Invalid credential object', $header['err']);
    }

    /**
     * errors on invalid algorithm
     */
    public function testErrorsOnInvalidAlgorithm()
    {
        $credentials = [
            'id'=> '123456',
            'key'=> '2983d45yun89q',
            'algorithm' => 'hmac-sha-0'
        ];

        $options = [
            'credentials' => $credentials,
            'payload' => 'something, anything!',
            'ext' => 'Bazinga',
            'timestamp' => 1353809207
        ];

        $uri = 'https://example.net/somewhere/over/the/rainbow';

        $header = Client::header($uri, 'POST', $options);

        $this->assertArrayHasKey('err', $header);

        $this->assertEquals('', $header['field']);
        $this->assertEquals('Unknown algorithm', $header['err']);
    }
}