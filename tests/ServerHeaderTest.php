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
 * Tests Server generating a response header for Client.
 *
 * @author Unit6 <team@unit6websites.com>
 */
class ServerHeaderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * generates header
     */
    public function testGenerateHeader()
    {
        $credentials = [
            'id' => '123456',
            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            'algorithm' => 'sha256',
            'user' => 'steve'
        ];

        $artifacts = [
            'method' => 'POST',
            'host' => 'example.com',
            'port' => '8080',
            'resource' => '/resource/4?filter=a',
            'ts' => '1398546787',
            'nonce' => 'xUwusx',
            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
            'ext' => 'some-app-data',
            'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
            'id' => '123456'
        ];

        $options = [
            'payload' => 'some reply',
            'content_type' => 'text/plain',
            'ext' => 'response-specific'
        ];

        $header = Server::header($credentials, $artifacts, $options);

        $expected = 'Hawk mac="n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"';

        $this->assertEquals($expected, $header);
    }

    /**
     * generates header (empty payload)
     */
    public function testGenerateHeaderWithEmptyPayload()
    {
        $credentials = [
            'id' => '123456',
            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            'algorithm' => 'sha256',
            'user' => 'steve'
        ];

        $artifacts = [
            'method' => 'POST',
            'host' => 'example.com',
            'port' => '8080',
            'resource' => '/resource/4?filter=a',
            'ts' => '1398546787',
            'nonce' => 'xUwusx',
            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
            'ext' => 'some-app-data',
            'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
            'id' => '123456'
        ];

        $options = [
            'payload' => '',
            'content_type' => 'text/plain',
            'ext' => 'response-specific'
        ];

        $header = Server::header($credentials, $artifacts, $options);

        $expected = 'Hawk mac="i8/kUBDx0QF+PpCtW860kkV/fa9dbwEoe/FpGUXowf0=", hash="q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=", ext="response-specific"';

        $this->assertEquals($expected, $header);
    }

    /**
     * generates header (pre calculated hash)
     */
    public function testGenerateHeaderWithPreCalculatedHash()
    {
        $credentials = [
            'id' => '123456',
            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            'algorithm' => 'sha256',
            'user' => 'steve'
        ];

        $artifacts = [
            'method' => 'POST',
            'host' => 'example.com',
            'port' => '8080',
            'resource' => '/resource/4?filter=a',
            'ts' => '1398546787',
            'nonce' => 'xUwusx',
            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
            'ext' => 'some-app-data',
            'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
            'id' => '123456'
        ];

        $options = [
            'payload' => 'some reply',
            'content_type' => 'text/plain',
            'ext' => 'response-specific'
        ];

        $options['hash'] = Crypto::getPayloadHash($options['payload'], $credentials['algorithm'], $options['content_type']);

        $header = Server::header($credentials, $artifacts, $options);

        $expected = 'Hawk mac="n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"';

        $this->assertEquals($expected, $header);
    }

    /**
     * generates header (null ext)
     */
    public function testGenerateHeaderWithNullExt()
    {
        $credentials = [
            'id' => '123456',
            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            'algorithm' => 'sha256',
            'user' => 'steve'
        ];

        $artifacts = [
            'method' => 'POST',
            'host' => 'example.com',
            'port' => '8080',
            'resource' => '/resource/4?filter=a',
            'ts' => '1398546787',
            'nonce' => 'xUwusx',
            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
            'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
            'id' => '123456'
        ];

        $options = [
            'payload' => 'some reply',
            'content_type' => 'text/plain',
            'ext' => null
        ];

        $header = Server::header($credentials, $artifacts, $options);

        $expected = 'Hawk mac="6PrybJTJs20jsgBw5eilXpcytD8kUbaIKNYXL+6g0ns=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM="';

        $this->assertEquals($expected, $header);
    }

    /**
     * errors on missing artifacts
     *//*
    public function testErrorOnMissingArtifacts()
    {
        $this->markTestSkipped(
          'This test is not required due to PHP type hinting.'
        );

        $credentials = [
            'id' => '123456',
            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            'algorithm' => 'sha256',
            'user' => 'steve'
        ];

        $options = [
            'payload' => 'some reply',
            'content_type' => 'text/plain',
            'ext' => 'response-specific'
        ];

        $header = Server::header($credentials, null, $options);

        $expected = '';

        $this->assertEquals($expected, $header);
    }
    */

    /**
     * errors on invalid artifacts
     *//*
    public function testErrorOnInvalidArtifacts()
    {
        $this->markTestSkipped(
          'This test is not required due to PHP type hinting.'
        );

        $credentials = [
            'id' => '123456',
            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            'algorithm' => 'sha256',
            'user' => 'steve'
        ];

        $options = [
            'payload' => 'some reply',
            'content_type' => 'text/plain',
            'ext' => 'response-specific'
        ];

        $header = Server::header($credentials, 5, $options);

        $expected = '';

        $this->assertEquals($expected, $header);
    }
    */

    /**
     * errors on missing credentials
     *//*
    public function testErrorOnMissingCredentials()
    {
        $this->markTestSkipped(
          'This test is not required due to PHP type hinting.'
        );

        $artifacts = [
            'method' => 'POST',
            'host' => 'example.com',
            'port' => '8080',
            'resource' => '/resource/4?filter=a',
            'ts' => '1398546787',
            'nonce' => 'xUwusx',
            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
            'ext' => 'some-app-data',
            'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
            'id' => '123456'
        ];

        $options = [
            'payload' => 'some reply',
            'content_type' => 'text/plain',
            'ext' => 'response-specific'
        ];

        $header = Server::header(null, $artifacts, $options);

        $expected = '';

        $this->assertEquals($expected, $header);
    }
    */

    /**
     * errors on invalid credentials (key)
     */
    public function testErrorOnInvalidCredentials()
    {
        $credentials = [
            'id' => '123456',
            'algorithm' => 'sha256',
            'user' => 'steve'
        ];

        $artifacts = [
            'method' => 'POST',
            'host' => 'example.com',
            'port' => '8080',
            'resource' => '/resource/4?filter=a',
            'ts' => '1398546787',
            'nonce' => 'xUwusx',
            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
            'ext' => 'some-app-data',
            'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
            'id' => '123456'
        ];

        $options = [
            'payload' => 'some reply',
            'content_type' => 'text/plain',
            'ext' => 'response-specific'
        ];

        $header = Server::header($credentials, $artifacts, $options);

        $expected = '';

        $this->assertEquals($expected, $header);
    }

    /**
     * errors on invalid algorithm
     */
    public function testErrorOnInvalidAlgorithm()
    {
        $credentials = [
            'id' => '123456',
            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            'algorithm' => 'x',
            'user' => 'steve'
        ];

        $artifacts = [
            'method' => 'POST',
            'host' => 'example.com',
            'port' => '8080',
            'resource' => '/resource/4?filter=a',
            'ts' => '1398546787',
            'nonce' => 'xUwusx',
            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
            'ext' => 'some-app-data',
            'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
            'id' => '123456'
        ];

        $options = [
            'payload' => 'some reply',
            'content_type' => 'text/plain',
            'ext' => 'response-specific'
        ];

        $header = Server::header($credentials, $artifacts, $options);

        $expected = '';

        $this->assertEquals($expected, $header);
    }
}