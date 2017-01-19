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
 * Client class for sending and receiving Hawk headers.
 *
 * @author Unit6 <team@unit6websites.com>
 */
class Client implements ClientInterface
{
    /**
     * Generate an Authorization header for a given request
     *
     *
     *  uri: 'http://example.com/resource?a=b' or object from Url.parse()
     *  method: HTTP verb (e.g. 'GET', 'POST')
     *  options: {
     *      // Required
     *      credentials: {
     *          id: 'dh37fgj492je',
     *          key: 'aoijedoaijsdlaksjdl',
     *          algorithm: 'sha256'             // 'sha1', 'sha256'
     *      },
     *      // Optional
     *      ext: 'application-specific',        // Application specific data sent via the ext attribute
     *      timestamp: Date.now(),              // A pre-calculated timestamp
     *      nonce: '2334f34f',                  // A pre-generated nonce
     *      localtimeOffsetMsec: 400,           // Time offset to sync with server time (ignored if timestamp provided)
     *      payload: '{"some":"payload"}',      // UTF-8 encoded string for body hash generation (ignored if hash provided)
     *      contentType: 'application/json',    // Payload content-type (ignored if hash provided)
     *      hash: 'U4MKKSmiVxk37JCCrAVIjV=',    // Pre-calculated payload hash
     *      app: '24s23423f34dx',               // Oz application id
     *      dlg: '234sz34tww3sd'                // Oz delegated-by application id
     *  }
     */
    public static function header($uri, $method, array $options = array())
    {
        $result = [
            'field'     => '',
            'artifacts' => [],
            #'err'      => null
        ];

        // validate inputs.
        if (empty($uri) || ( ! is_string($uri) && ! is_array($uri)) ||
            empty($method) || ! is_string($method) ||
            empty($options) || ! is_array($options)) {
            $result['err'] = 'Invalid argument type';
            return $result;
        }

        // set application time.
        $timestamp = (isset($options['timestamp'])
            ? $options['timestamp']
            : Utils::getTimeNowSec(isset($options['localtime_offset_msec']) ? $options['localtime_offset_msec'] : null));

        // validate credentials.
        $credentials = (isset($options['credentials']) ? $options['credentials'] : []);

        if ( ! isset($credentials['id'], $credentials['key'], $credentials['algorithm'])) {
            $result['err'] = 'Invalid credential object';
            return $result;
        }

        if ( ! in_array($credentials['algorithm'], Crypto::$algorithms)) {
            $result['err'] = 'Unknown algorithm';
            return $result;
        }

        // parse uri.
        $uri = Utils::getParsedUrl($uri);

        // calculate signature.
        $artifacts = [
            'ts'       => $timestamp,
            'nonce'    => (isset($options['nonce']) ? $options['nonce'] : Utils::getNonce()),
            'method'   => strtoupper($method),
            'resource' => $uri['resource'],
            'host'     => $uri['host'],
            'port'     => $uri['port'],
            'hash'     => (isset( $options['hash'] ) ? $options['hash'] : null),
            'ext'      => (isset( $options['ext'] ) ? $options['ext'] : null),
            'app'      => (isset( $options['app'] ) ? $options['app'] : null),
            'dlg'      => (isset( $options['dlg'] ) ? $options['dlg'] : null)
        ];

        $result['artifacts'] = $artifacts;

        // calculate payload hash.
        if ( ! $artifacts['hash'] &&
            (isset($options['payload']) || $options['payload'] === '')) {
            $hash = Crypto::getPayloadHash(
                $options['payload'],
                $credentials['algorithm'],
                (isset($options['content_type']) ? $options['content_type'] : null)
            );

            $artifacts['hash'] = $hash;
        }

        // calculate the hmac signature used for the authorization header.
        $mac = Crypto::getArtifactsMac('header', $credentials, $artifacts);

        // construct header.
        $has_ext = ($artifacts['ext'] && $artifacts['ext'] !== '');

        $header = 'Hawk id="' . $credentials['id'] . '"'
            . ', ts="' . $artifacts['ts'] . '"'
            . ', nonce="' . $artifacts['nonce'] . '"'
            . ($artifacts['hash'] ? ', hash="' . $artifacts['hash'] . '"' : '')
            . ($has_ext ? ', ext="' . Utils::getEscapeHeaderAttribute($artifacts['ext']) . '"' : '')
            . ', mac="' . $mac . '"';

        if ($artifacts['app']) {
            $header .= ', app="' . $artifacts['app'] . '"'
                . ($artifacts['dlg'] ? ', dlg="' . $artifacts['dlg'] . '"' : '');
        }

        $result['field'] = $header;

        return $result;
    }

    /**
     * Validate Server Response
     *
     *  res:                // node's response object
     *  artifacts:          // object received from header().artifacts
     *  options: {
     *      payload:        // optional payload received
     *      required:       // specifies if a Server-Authorization header is required. Defaults to 'false'
     *  }
     */
    public static function authenticate(array $response, array $credentials, array $artifacts = null, array $options = null, callable $callback = null)
    {
        $wwwAttributes = null;
        $serverAuthAttributes = null;

        $finalize = function ($err = null) use ($callback, &$wwwAttributes, &$serverAuthAttributes)
        {
            if (is_callable($callback)) {
                $headers = [
                    'www-authenticate' => $wwwAttributes,
                    'server-authorization' => $serverAuthAttributes
                ];

                return $callback($err, $headers);
            }

            return ( ! $err);
        };

        // parse HTTP WWW-Authenticate header.
        if (isset($response['headers']['www-authenticate'])) {
            $filterKeys = ['ts', 'tsm', 'error'];
            $wwwAuthenticate = $response['headers']['www-authenticate'];
            $wwwAttributes = Utils::getParsedAuthorizationHeader($wwwAuthenticate, $filterKeys);

            if ($wwwAttributes instanceof Error) {
                $wwwAttributes = null;
                return $finalize(new Error('Invalid WWW-Authenticate header'));
            }

            // validate server timestamp.
            if (isset( $wwwAttributes['ts'])) {
                $tsm = Crypto::getTimestampHash($wwwAttributes['ts'], $credentials);

                if ($tsm !== $wwwAttributes['tsm']) {
                    return $finalize(new Error('Invalid server timestamp hash'));
                }
            }
        }

        // check if HTTP Server-Authorization header is required.
        if ( ! isset($response['headers']['server-authorization'])) {
            if (isset($options['required']) && $options['required']) {
                return $finalize(new Error('Missing Server-Authorization header'));
            }

            return $finalize();
        }

        // parse HTTP Server-Authorization header.
        $serverAuthorization = $response['headers']['server-authorization'];
        $filterKeys = ['mac', 'ext', 'hash'];
        $serverAuthAttributes = Utils::getParsedAuthorizationHeader($serverAuthorization, $filterKeys);

        if ($serverAuthAttributes instanceof Error) {
            $serverAuthAttributes = null;
            return $finalize(new Error('Invalid Server-Authorization header'));
        }

        $artifacts['ext'] = (isset($serverAuthAttributes['ext']) ? $serverAuthAttributes['ext'] : null);
        $artifacts['hash'] = $serverAuthAttributes['hash'];

        $mac = Crypto::getArtifactsMac('response', $credentials, $artifacts);
        if ($mac !== $serverAuthAttributes['mac']) {
            return $finalize(new Error('Bad response mac'));
        }

        if ( ! isset($options['payload']) && $options['payload'] !== '') {
            return $finalize();
        }

        if ( ! $serverAuthAttributes['hash']) {
            return $finalize(new Error('Missing response hash attribute'));
        }

        $hash = Crypto::getPayloadHash(
            $options['payload'],
            $credentials['algorithm'],
            $response['headers']['content-type']
        );

        if ($hash !== $serverAuthAttributes['hash']) {
            return $finalize(new Error('Bad response payload mac'));
        }

        return $finalize();
    }

    /**
     * Generate a bewit value for a given URI
     *
     * uri: 'http://example.com/resource?a=b' or object from Url.parse()
     * options: {
     *     // Required
     *     credentials: {
     *          id: 'dh37fgj492je',
     *          key: 'aoijedoaijsdlaksjdl',
     *          algorithm: 'sha256'                 // 'sha1', 'sha256'
     *     },
     *     ttlSec: 60 * 60,                         // TTL in seconds
     *     // Optional
     *     ext: 'application-specific',             // Application specific data sent via the ext attribute
     *     localtimeOffsetMsec: 400                 // Time offset to sync with server time
     * };
     */
    public static function getBewit($uri, array $options = null)
    {
        // validate inputs
        if (is_null($uri) || empty($uri) || ( ! is_string($uri) && ! is_array($uri)) ||
            is_null($options) || ! is_array($options) ||
            ! isset($options['ttl_sec'])) {
            return '';
        }

        // accept zero as a valid value.
        $options['ext'] = (isset($options['ext']) ? $options['ext'] : '');

        $options['localtime_offset_msec'] = (isset($options['localtime_offset_msec']) ? $options['localtime_offset_msec'] : null);

        // application time.
        $now = Utils::getTimeNowMs($options['localtime_offset_msec']);  // measure now before any other processing.

        // validate credentials
        if ( ! isset($options['credentials'])) {
            return '';
        }

        $credentials = $options['credentials'];

        // invalid credential object
        if ( ! isset($credentials['id'], $credentials['key'], $credentials['algorithm'])) {
            return '';
        }

        if ( ! in_array($credentials['algorithm'], Crypto::$algorithms)) {
            return '';
        }

        // parse URI
        if (is_string($uri)) {
            $uri = Utils::getParsedUrl($uri);
        }

        // calculate signature.
        $exp = floor($now / 1000) + $options['ttl_sec'];

        $artifacts = [
            'ts'       => $exp,
            'nonce'    => '',
            'method'   => 'GET',
            'resource' => $uri['resource'], // Maintain trailing '?'
            'host'     => $uri['host'],
            'port'     => $uri['port'],
            'ext'      => $options['ext']
        ];

        $mac = Crypto::getArtifactsMac('bewit', $credentials, $artifacts);

        // construct bewit: id\exp\mac\ext
        $bewit = $credentials['id']
            . '\\' . $exp
            . '\\' . $mac
            . '\\' . $options['ext'];

        $encoded = Utils::getBase64Encode($bewit);

        return $encoded;
    }



    /**
     * Generate an authorization string for a message
     *
     * host: 'example.com',
     * port: 8000,
     * message: '{"some":"payload"}',           // UTF-8 encoded string for body hash generation
     * options: {
     *     // Required
     *     credentials: {
     *          id: 'dh37fgj492je',
     *          key: 'aoijedoaijsdlaksjdl',
     *          algorithm: 'sha256'             // 'sha1', 'sha256'
     *     },
     *     // Optional
     *     timestamp: Date.now(),               // A pre-calculated timestamp
     *     nonce: '2334f34f',                   // A pre-generated nonce
     *     localtimeOffsetMsec: 400,            // Time offset to sync with server time (ignored if timestamp provided)
     * }
    */
    public static function message($host, $port, $message, array $options)
    {
        // validate inputs
        if (empty($host) || ! is_string($host) ||
            empty($port) || ! is_integer($port) || // is_numeric: better alternative?
            empty($message) || ! is_string($message) ||
            empty($options) || ! is_array($options)) {
            return null;
        }

        // application time
        $options['localtime_offset_msec'] = (isset($options['localtime_offset_msec']) ? $options['localtime_offset_msec'] : null);
        $timestamp = (isset($options['timestamp']) ? $options['timestamp'] : Utils::getTimeNowSec($options['localtime_offset_msec']));

        // validate credentials
        if ( ! isset($options['credentials'])) {
            return null;
        }

        $credentials = $options['credentials'];

        // invalid credential object
        if ( ! isset($credentials['id'], $credentials['key'], $credentials['algorithm'])) {
            return null;
        }

        if ( ! in_array($credentials['algorithm'], Crypto::$algorithms)) {
            return null;
        }

        if ( ! isset($options['nonce'])) {
            $options['nonce'] = Utils::getNonce(6);
        }

        // calculate signature
        $artifacts = [
            'ts'    => $timestamp,
            'nonce' => $options['nonce'],
            'host'  => $host,
            'port'  => $port,
            'hash'  => Crypto::getPayloadHash($message, $credentials['algorithm'])
        ];

        // construct authorization
        $result = [
            'id'    => $credentials['id'],
            'ts'    => $artifacts['ts'],
            'nonce' => $artifacts['nonce'],
            'hash'  => $artifacts['hash'],
            'mac'   => Crypto::getArtifactsMac('message', $credentials, $artifacts)
        ];

        return $result;
    }
}