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
 * Tests for building the Client authorization message.
 *
 * @author Unit6 <team@unit6websites.com>
 */
class ClientMessageTest extends \PHPUnit_Framework_TestCase
{
    /**
     * generates authorization
     */
    public function testGeneratesAuthorization()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha1'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'abc123'
        ];

        $auth = Client::message('example.com', 80, 'I am the boodyman', $options);
        $this->assertFalse(empty($auth));
        $this->assertEquals(1353809207, $auth['ts']);
        $this->assertEquals('abc123', $auth['nonce']);
    }

    /**
     * errors on invalid host
     */
    public function testErrorOnInvalidHost()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha1'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'abc123'
        ];

        $auth = Client::message(5, 80, 'I am the boodyman', $options);
        $this->assertNull($auth);
    }

    /**
     * errors on invalid port
     */
    public function testErrorOnInvalidPort()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha1'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'abc123'
        ];

        $auth = Client::message('example.com', '80', 'I am the boodyman', $options);
        $this->assertNull($auth);
    }

    /**
     * errors on missing host
     */
    public function testErrorOnMissingHost()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha1'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'abc123'
        ];

        $auth = Client::message(null, 0, 'I am the boodyman', $options);
        $this->assertNull($auth);
    }

    /**
     * errors on null message
     */
    public function testErrorOnNullMessage()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha1'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'abc123'
        ];

        $auth = Client::message('example.com', 80, null, $options);
        $this->assertNull($auth);
    }

    /**
     * errors on missing message (undefined)
     */
    public function testErrorOnMissingMessage()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha1'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'abc123'
        ];

        $auth = Client::message('example.com', 80, '', $options);
        $this->assertNull($auth);
    }

    /**
     * errors on invalid message
     */
    public function testErrorOnInvalidMessage()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha1'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'abc123'
        ];

        $auth = Client::message('example.com', 80, 5, $options);
        $this->assertNull($auth);
    }

    /**
     * errors on missing options
     */
    public function testErrorOnMissingOptions()
    {
        $auth = Client::message('example.com', 80, 'I am the boodyman', []);
        $this->assertNull($auth);
    }

    /**
     * errors on invalid credentials (id)
     */
    public function testErrorOnInvalidCredentialsWithNoID()
    {
        $credentials = [
            'key' => '2983d45yun89q',
            'algorithm' => 'sha1'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'abc123'
        ];

        $auth = Client::message('example.com', 80, 'I am the boodyman', $options);
        $this->assertNull($auth);
    }

    /**
     * errors on invalid credentials (key)
     */
    public function testErrorOnInvalidCredentialsWithNoKey()
    {
        $credentials = [
            'id' => '123456',
            'algorithm' => 'sha1'
        ];

        $options = [
            'credentials' => $credentials,
            'timestamp' => 1353809207,
            'nonce' => 'abc123'
        ];

        $auth = Client::message('example.com', 80, 'I am the boodyman', $options);
        $this->assertNull($auth);
    }
}