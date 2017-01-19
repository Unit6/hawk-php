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
 * Tests for generating a Bewit token.
 *
 * @author Unit6 <team@unit6websites.com>
 */
class BewitGenerateTest extends \PHPUnit_Framework_TestCase
{
    /**
     * returns a valid bewit value
     */
    public function testValidBewitValue()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $uri = 'https://example.com/somewhere/over/the/rainbow';

        $options = [
            'credentials' => $credentials,
            'ttl_sec' => 300,
            'localtime_offset_msec' => 1356420407232 - Utils::getTimeNowMs(),
            'ext' => 'xandyandz'
        ];

        $bewit = Bewit::generate($uri, $options);

        $expected = 'MTIzNDU2XDEzNTY0MjA3MDdca3NjeHdOUjJ0SnBQMVQxekRMTlBiQjVVaUtJVTl0T1NKWFRVZEc3WDloOD1ceGFuZHlhbmR6';

        $this->assertEquals($expected, $bewit);
    }

    /**
     * returns a valid bewit value (explicit port)
     */
    public function testValidBewitValueWithExplicitPort()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $uri = 'https://example.com:8080/somewhere/over/the/rainbow';

        $options = [
            'credentials' => $credentials,
            'ttl_sec' => 300,
            'localtime_offset_msec' => 1356420407232 - Utils::getTimeNowMs(),
            'ext' => 'xandyandz'
        ];

        $bewit = Bewit::generate($uri, $options);

        $expected = 'MTIzNDU2XDEzNTY0MjA3MDdcaFpiSjNQMmNLRW80a3kwQzhqa1pBa1J5Q1p1ZWc0V1NOYnhWN3ZxM3hIVT1ceGFuZHlhbmR6';

        $this->assertEquals($expected, $bewit);
    }

    /**
     * returns a valid bewit value (null ext)
     */
    public function testValidBewitValueWithNullExt()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $uri = 'https://example.com/somewhere/over/the/rainbow';

        $options = [
            'credentials' => $credentials,
            'ttl_sec' => 300,
            'localtime_offset_msec' => 1356420407232 - Utils::getTimeNowMs(),
            'ext' => null
        ];

        $bewit = Bewit::generate($uri, $options);

        $expected = 'MTIzNDU2XDEzNTY0MjA3MDdcSUdZbUxnSXFMckNlOEN4dktQczRKbFdJQStValdKSm91d2dBUmlWaENBZz1c';

        $this->assertEquals($expected, $bewit);
    }

    /**
     * returns a valid bewit value (parsed uri)
     */
    public function testValidBewitValueParsedURI()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $uri = 'https://example.com/somewhere/over/the/rainbow';
        $uri = Utils::getParsedUrl($uri);

        $options = [
            'credentials' => $credentials,
            'ttl_sec' => 300,
            'localtime_offset_msec' => 1356420407232 - Utils::getTimeNowMs(),
            'ext' => 'xandyandz'
        ];

        $bewit = Bewit::generate($uri, $options);

        $expected = 'MTIzNDU2XDEzNTY0MjA3MDdca3NjeHdOUjJ0SnBQMVQxekRMTlBiQjVVaUtJVTl0T1NKWFRVZEc3WDloOD1ceGFuZHlhbmR6';

        $this->assertEquals($expected, $bewit);
    }

    /**
     * errors on invalid options
     *//*
    public function testErrorOnInvalidOptions()
    {
        $this->markTestSkipped(
          'This test is not required due to PHP type hinting.'
        );

        $bewit = Bewit::generate('https://example.com/somewhere/over/the/rainbow', 4);
        $this->assertEquals('', $bewit);
    }
    */

    /**
     * errors on missing uri
     */
    public function testErrorOnMissingURI()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $options = [
            'credentials' => $credentials,
            'ttl_sec' => 300,
            'localtime_offset_msec' => 1356420407232 - Utils::getTimeNowMs(),
            'ext' => 'xandyandz'
        ];

        $bewit = Bewit::generate('', $options);

        $this->assertEquals('', $bewit);
    }

    /**
     * errors on invalid uri
     */
    public function testErrorOnInvalidURI()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $options = [
            'credentials' => $credentials,
            'ttl_sec' => 300,
            'localtime_offset_msec' => 1356420407232 - Utils::getTimeNowMs(),
            'ext' => 'xandyandz'
        ];

        $bewit = Bewit::generate(5, $options);

        $this->assertEquals('', $bewit);
    }

    /**
     * errors on invalid credentials (id)
     */
    public function testErrorOnInvalidCredentialsNoID()
    {
        $credentials = [
            'key' => '2983d45yun89q',
            'algorithm' => 'sha256'
        ];

        $uri = 'https://example.com/somewhere/over/the/rainbow';

        $options = [
            'credentials' => $credentials,
            'ttl_sec' => 300,
            'localtime_offset_msec' => 1356420407232 - Utils::getTimeNowMs(),
            'ext' => 'xandyandz'
        ];

        $bewit = Bewit::generate($uri, $options);

        $this->assertEquals('', $bewit);
    }

    /**
     * errors on missing credentials
     */
    public function testErrorOnMissingCredentials()
    {
        $uri = 'https://example.com/somewhere/over/the/rainbow';

        $options = [
            'ttl_sec' => 300,
            'ext' => 'xandyandz'
        ];

        $bewit = Bewit::generate($uri, $options);

        $this->assertEquals('', $bewit);
    }

    /**
     * errors on invalid credentials (key)
     */
    public function testErrorOnInvalidCredentialsNoKey()
    {
        $credentials = [
            'id' => '123456',
            'algorithm' => 'sha256'
        ];

        $uri = 'https://example.com/somewhere/over/the/rainbow';

        $options = [
            'credentials' => $credentials,
            'ttl_sec' => 300,
            'ext' => 'xandyandz'
        ];

        $bewit = Bewit::generate($uri, $options);

        $this->assertEquals('', $bewit);
    }

    /**
     * errors on invalid algorithm
     */
    public function testErrorOnInvalidAlgorithm()
    {
        $credentials = [
            'id' => '123456',
            'key' => '2983d45yun89q',
            'algorithm' => 'hmac-sha-0'
        ];

        $uri = 'https://example.com/somewhere/over/the/rainbow';

        $options = [
            'credentials' => $credentials,
            'ttl_sec' => 300,
            'ext' => 'xandyandz'
        ];

        $bewit = Bewit::generate($uri, $options);

        $this->assertEquals('', $bewit);
    }

    /**
     * errors on missing options
     */
    public function testErrorOnMissingOptions()
    {
        $bewit = Bewit::generate('https://example.com/somewhere/over/the/rainbow');

        $this->assertEquals('', $bewit);
    }
}