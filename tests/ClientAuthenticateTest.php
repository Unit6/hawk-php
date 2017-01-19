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
 * Tests for Client validating the server-authorization header.
 *
 * @author Unit6 <team@unit6websites.com>
 */
class ClientAuthenticateTest extends \PHPUnit_Framework_TestCase
{
    /**
     * returns false on invalid header
     */
    public function testReturnFalseOnInvalidHeader()
    {
        $response = [
            'headers' => [
                'server-authorization' => 'Hawk mac="abc", bad="xyz"'
            ]
        ];

        $result = Client::authenticate($response, []);

        $this->assertFalse($result);
    }

    /**
     * returns false on invalid header (callback)
     */
    public function testReturnFalseOnInvalidHeaderWithCallback()
    {
        $response = [
            'headers' => [
                'server-authorization' => 'Hawk mac="abc", bad="xyz"'
            ]
        ];

        Client::authenticate($response, [], null, null, function ($err) {
            $this->assertNotNull($err);
            $this->assertEquals('Invalid Server-Authorization header', $err->getMessage());
        });
    }

    /**
     * returns false on invalid mac
     */
    public function testReturnFalseOnInvalidMAC()
    {
        $response = [
            'headers' => [
                'content-type' => 'text/plain',
                'server-authorization' => 'Hawk mac="_IJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'
            ]
        ];

        $artifacts = [
            'method' => 'POST',
            'host' => 'example.com',
            'port' => '8080',
            'resource' => '/resource/4?filter=a',
            'ts' => '1362336900',
            'nonce' => 'eb5S_L',
            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
            'ext' => 'some-app-data',
            'app' => null,
            'dlg' => null,
            'mac' => 'BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk=',
            'id' => '123456'
        ];

        $credentials = [
            'id' => '123456',
            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            'algorithm' => 'sha256',
            'user' => 'steve'
        ];

        $result = Client::authenticate($response, $credentials, $artifacts);

        $this->assertFalse($result);
    }

    /**
     * returns true on ignoring hash
     */
    public function testReturnTrueOnIngoredHash()
    {
        $response = [
            'headers' => [
                'content-type' => 'text/plain',
                'server-authorization' => 'Hawk mac="XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'
            ]
        ];

        $artifacts = [
            'method' => 'POST',
            'host' => 'example.com',
            'port' => '8080',
            'resource' => '/resource/4?filter=a',
            'ts' => '1362336900',
            'nonce' => 'eb5S_L',
            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
            'ext' => 'some-app-data',
            'app' => null,
            'dlg' => null,
            'mac' => 'BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk=',
            'id' => '123456'
        ];

        $credentials = [
            'id' => '123456',
            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            'algorithm' => 'sha256',
            'user' => 'steve'
        ];

        $result = Client::authenticate($response, $credentials, $artifacts);

        $this->assertTrue($result);
    }

    /**
     * validates response payload
     */
    public function testValidationOfResponsePayload()
    {
        $payload = 'some reply';

        $response = [
            'headers' => [
                'content-type' => 'text/plain',
                'server-authorization' => 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'
            ]
        ];

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
            'ts' => '1453070933',
            'nonce' => '3hOHpR',
            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
            'ext' => 'some-app-data',
            'app' => null,
            'dlg' => null,
            'mac' => 'BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk=',
            'id' => '123456'
        ];

        $options = [
            'payload' => $payload
        ];

        $result = Client::authenticate($response, $credentials, $artifacts, $options);

        $this->assertTrue($result);
    }

    /**
     * validates response payload (callback)
     */
    public function testValdiationOfResponsePayloadWithCallback()
    {
        $payload = 'some reply';

        $response = [
            'headers' => [
                'content-type' => 'text/plain',
                'server-authorization' => 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'
            ]
        ];

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
            'ts' => '1453070933',
            'nonce' => '3hOHpR',
            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
            'ext' => 'some-app-data',
            'app' => null,
            'dlg' => null,
            'mac' => '/DitzeD66F2f7O535SERbX9p+oh9ZnNLqSNHG+c7/vs=',
            'id' => '123456'
        ];

        $options = [
            'payload' => $payload
        ];

        Client::authenticate($response, $credentials, $artifacts, $options, function ($err, $headers) {
            $this->assertTrue(is_null($err));

            $expected = [
                'www-authenticate' => null,
                'server-authorization' => [
                    'mac' => 'odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=',
                    'hash' => 'f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=',
                    'ext' => 'response-specific'
                ]
            ];

            $this->assertEquals($expected, $headers);
        });
    }

    /**
     * errors on invalid response payload
     */
    public function testErrorsOnInvalidResponsePayload()
    {
        $payload = 'wrong reply';

        $response = [
            'headers' => [
                'content-type' => 'text/plain',
                'server-authorization' => 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'
            ]
        ];

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
            'ts' => '1453070933',
            'nonce' => '3hOHpR',
            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
            'ext' => 'some-app-data',
            'app' => null,
            'dlg' => null,
            'mac' => '/DitzeD66F2f7O535SERbX9p+oh9ZnNLqSNHG+c7/vs=',
            'id' => '123456'
        ];

        $options = [
            'payload' => $payload
        ];

        $result = Client::authenticate($response, $credentials, $artifacts, $options);

        $this->assertFalse($result);
    }

    /**
     * fails on invalid WWW-Authenticate header format
     */
    public function testFailOnInvalidWWWAuthenticateHeaderFormat()
    {
        $response = [
            'headers' => [
                'www-authenticate' => 'Hawk ts="1362346425875", tsm="PhwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", x="Stale timestamp"'
            ]
        ];

        $result = Client::authenticate($response, []);

        $this->assertFalse($result);
    }

    /**
     * fails on invalid WWW-Authenticate header format
     */
    public function testFailOnInvalidWWWAuthenticateHeaderFormatWithUser()
    {
        $credentials = [
            'id' => '123456',
            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            'algorithm' => 'sha256',
            'user' => 'steve'
        ];

        $response = [
            'headers' => [
                'www-authenticate' => 'Hawk ts="1362346425875", tsm="hwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", error="Stale timestamp"'
            ]
        ];

        $result = Client::authenticate($response, $credentials);

        $this->assertFalse($result);
    }

    /**
     * skips tsm validation when missing ts
     */
    public function testSkipTSMValidationWhenMissingTimestamp()
    {
        $response = [
            'headers' => [
                'www-authenticate' => 'Hawk error="Stale timestamp"'
            ]
        ];

        $result = Client::authenticate($response, []);

        $this->assertTrue($result);
    }
}