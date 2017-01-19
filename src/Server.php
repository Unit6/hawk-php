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
 * Server class for handling Hawk requests.
 *
 * @author Unit6 <team@unit6websites.com>
 */
class Server implements ServerInterface
{
    /**
     * Authenticate Request
     *
     * Validate the incoming request from a client.
     *
     *   req:               node's HTTP request object or an object as follows:
     *
     *                  var request = {
     *                      method: 'GET',
     *                      url: '/resource/4?a=1&b=2',
     *                      host: 'example.com',
     *                      port: 8080,
     *                      authorization: 'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="'
     *                  };
     *
     *  credentialsFunc:    required function to lookup the set of Hawk credentials based on the provided credentials id.
     *                      The credentials include the MAC key, MAC algorithm, and other attributes (such as username)
     *                      needed by the application. This function is the equivalent of verifying the username and
     *                      password in Basic authentication.
     *
     *                  var credentialsFunc = function (id, callback) {
     *
     *                      // Lookup credentials in database
     *                      db.lookup(id, function (err, item) {
     *
     *                          if (err || !item) {
     *                              return callback(err);
     *                          }
     *
     *                          var credentials = {
     *                              // Required
     *                              key: item.key,
     *                              algorithm: item.algorithm,
     *                              // Application specific
     *                              user: item.user
     *                          };
     *
     *                          return callback(null, credentials);
     *                      });
     *                  };
     *
     *  options: {
     *
     *      hostHeaderName:        optional header field name, used to override the default 'Host' header when used
     *                             behind a cache of a proxy. Apache2 changes the value of the 'Host' header while preserving
     *                             the original (which is what the module must verify) in the 'x-forwarded-host' header field.
     *                             Only used when passed a node Http.ServerRequest object.
     *
     *      nonceFunc:             optional nonce validation function. The function signature is function(nonce, ts, callback)
     *                             where 'callback' must be called using the signature function(err).
     *
     *      timestampSkewSec:      optional number of seconds of permitted clock skew for incoming timestamps. Defaults to 60 seconds.
     *                             Provides a +/- skew which means actual allowed window is double the number of seconds.
     *
     *      localtimeOffsetMsec:   optional local clock time offset express in a number of milliseconds (positive or negative).
     *                             Defaults to 0.
     *
     *      payload:               optional payload for validation. The client calculates the hash value and includes it via the 'hash'
     *                             header attribute. The server always ensures the value provided has been included in the request
     *                             MAC. When this option is provided, it validates the hash value itself. Validation is done by calculating
     *                             a hash value over the entire payload (assuming it has already be normalized to the same format and
     *                             encoding used by the client to calculate the hash on request). If the payload is not available at the time
     *                             of authentication, the authenticatePayload() method can be used by passing it the credentials and
     *                             attributes.hash returned in the authenticate callback.
     *
     *      host:                  optional host name override. Only used when passed a node request object.
     *      port:                  optional port override. Only used when passed a node request object.
     *  }
     *
     *  callback: function (err, credentials, artifacts) { }
     */
    public static function authenticate(array $req, callable $credentialsFunc, array $options, callable $callback)
    {
        // default options.
        $options['nonce_func'] = (isset($options['nonce_func']) ? $options['nonce_func'] : null);
        $options['timestamp_skew_sec'] = (isset($options['timestamp_skew_sec']) ? $options['timestamp_skew_sec'] : 60); // 60 seconds
        $options['localtime_offset_msec'] = (isset($options['localtime_offset_msec']) ? $options['localtime_offset_msec'] : null);

        // application time: measure now before any other processing
        $now = Utils::getTimeNowMs($options['localtime_offset_msec']);

        // convert HTTP request parameters to a request configuration object
        $request = Utils::getParsedRequest($req, $options);
        if ($request instanceof Error) {
            return $callback(Error::badRequest($request->getMessage()));
        }

        // parse HTTP Authorization header.
        $authorization = (isset($request['authorization']) ? $request['authorization'] : null);
        $attributes = Utils::getParsedAuthorizationHeader($authorization);
        if ($attributes instanceof Error) {
            return $callback($attributes);
        }

        // reconstruct artifacts container.
        $artifacts = [
            'method'   => $request['method'],
            'host'     => $request['host'],
            'port'     => $request['port'],
            'resource' => $request['url'],
            'ts'       => (isset($attributes['ts']) ? $attributes['ts'] : null),
            'nonce'    => (isset($attributes['nonce']) ? $attributes['nonce'] : null),
            'hash'     => (isset($attributes['hash']) ? $attributes['hash'] : null),
            'ext'      => (isset($attributes['ext']) ? $attributes['ext'] : null),
            'app'      => (isset($attributes['app']) ? $attributes['app'] : null),
            'dlg'      => (isset($attributes['dlg']) ? $attributes['dlg'] : null),
            'mac'      => (isset($attributes['mac']) ? $attributes['mac'] : null),
            'id'       => (isset($attributes['id']) ? $attributes['id'] : null)
        ];

        // verify required header attributes.
        if ( ! isset(
            $attributes['id'],
            $attributes['ts'],
            $attributes['nonce'],
            $attributes['mac'])) {
            return $callback(Error::badRequest('Missing attributes'), null, $artifacts);
        }

        // fetch hawk credentials from application.
        $credentialsFunc($attributes['id'], function ($err, $credentials = null) use ($callback, &$request, &$now, &$options, &$attributes, &$artifacts) {
            if ($err) {
                return $callback($err, $credentials, $artifacts);
            }

            if (is_null($credentials)) {
                return $callback(Error::unauthorized('Unknown credentials'), null, $artifacts);
            }

            if ( ! isset($credentials['key'], $credentials['algorithm'])) {
                return $callback(Error::internal('Invalid credentials'), $credentials, $artifacts);
            }

            if ( ! in_array($credentials['algorithm'], Crypto::$algorithms)) {
                return $callback(Error::internal('Unknown algorithm'), $credentials, $artifacts);
            }

            // calculate MAC.
            $mac = Crypto::getArtifactsMac('header', $credentials, $artifacts);
            if ( ! Utils::getFixedTimeComparison($mac, $attributes['mac'])) {
                return $callback(Error::unauthorized('Bad mac'), $credentials, $artifacts);
            }

            // check payload hash.
            if (isset($options['payload'])) {
                if ( ! isset( $attributes['hash'])) {
                    return $callback(Error::unauthorized('Missing required payload hash'), $credentials, $artifacts);
                }

                $hash = Crypto::getPayloadHash($options['payload'], $credentials['algorithm'], $request['content_type']);

                if ( ! Utils::getFixedTimeComparison($hash, $attributes['hash'])) {
                    return $callback(Error::unauthorized('Bad payload hash'), $credentials, $artifacts);
                }
            }

            // check nonce.
            $nonceFunc = $options['nonce_func'];

            if (is_null($nonceFunc)) {
                $nonceFunc = function ($key, $nonce, $ts, callable $callback)
                {
                    return $callback(); // No validation
                };
            }

            $nonceFunc($credentials['key'], $attributes['nonce'], $attributes['ts'], function ($err = null) use ($callback, &$now, &$options, &$attributes, &$credentials, &$artifacts) {
                if ($err) {
                    return $callback(Error::unauthorized('Invalid nonce'), $credentials, $artifacts);
                }

                // check timestamp staleness.
                if (abs(($attributes['ts'] * 1000) - $now) > ($options['timestamp_skew_sec'] * 1000)) {
                    $tsm = Crypto::getTimestampMessage($credentials, $options['localtime_offset_msec']);
                    return $callback(Error::unauthorized('Stale timestamp', $tsm), $credentials, $artifacts);
                }

                // successful authentication.
                return $callback(null, $credentials, $artifacts);
            });
        });
    }

    /**
     * Signed Server Response
     *
     * Generate a Server-Authorization header for a given response.
     *
     * credentials: {},                     // Object received from authenticate()
     * artifacts: {}                        // Object received from authenticate(); 'mac', 'hash', and 'ext' - ignored
     * options: {
     *     ext: 'application-specific',     // Application specific data sent via the ext attribute
     *     payload: '{"some":"payload"}',   // UTF-8 encoded string for body hash generation (ignored if hash provided)
     *     contentType: 'application/json', // Payload content-type (ignored if hash provided)
     *     hash: 'U4MKKSmiVxk37JCCrAVIjV='  // Pre-calculated payload hash
     * }
     */
    public static function header(array $credentials, array $artifacts, array $options = array())
    {
        // prepare inputs.
        if ( ! is_array($artifacts) || ! is_array($options)){
            return '';
        }

        unset($artifacts['mac']);

        $artifacts['hash'] = (isset($options['hash']) ? $options['hash'] : null);
        $artifacts['ext'] = (isset($options['ext']) ? $options['ext'] : null);

        // validate credentials.
        if ( ! isset($credentials, $credentials['key'], $credentials['algorithm'])) {
            // Invalid Credential Object
            return '';
        }

        if ( ! in_array($credentials['algorithm'], Crypto::$algorithms)) {
            return '';
        }

        // calculate payload hash.
        if ( ! isset($artifacts['hash']) && isset($options['payload'])) {
            $artifacts['hash'] = Crypto::getPayloadHash($options['payload'], $credentials['algorithm'], $options['content_type']);
        }

        $mac = Crypto::getArtifactsMac('response', $credentials, $artifacts);

        // construct header.
        $header = 'Hawk mac="' . $mac . '"'
            . (isset($artifacts['hash']) ? ', hash="' . $artifacts['hash'] . '"' : '')
            . (isset($artifacts['ext']) && $artifacts['ext'] !== '' // Other falsey values allowed.
                ? ', ext="' . Utils::getEscapeHeaderAttribute($artifacts['ext']) . '"' : '');

        return $header;
    }

    /**
     * Bewit Regular Expression
     *
     * Retrieve the parts of the URI to help reconstructing it without the Bewit
     * to validate the original resource request.
     *
     * 1: First portion of the URI.
     * 2: Character before Bewit (?|&).
     * 3: Bewit token.
     * 4: Optional characters after Bewit.
     *
     *                             1     2             3       4
     *                             |¯¯¯¯¯|¯¯¯¯¯|       |¯¯¯¯¯¯¯|¯¯¯¯¯¯¯|
     */
    public static $bewitRegex = '/^(\/.*)([\?&])bewit\=([^&$]*)(?:&(.+))?$/';

    /**
     * Authenticate Bewit Request
     *
     * Arguments and options are the same as authenticate() with the exception
     * that the only supported options are:
     *      - 'hostHeaderName'
     *      - 'localtimeOffsetMsec'
     *      - 'host'
     *      - 'port'
     */
    public static function authenticateBewit(array $req, callable $credentialsFunc, array $options, callable $callback)
    {
        $options['localtime_offset_msec'] = (isset($options['localtime_offset_msec']) ? $options['localtime_offset_msec'] : null);

        // application time.
        $now = Utils::getTimeNowMs($options['localtime_offset_msec']);

        // convert HTTP request parameters to a request configuration object.
        $request = Utils::getParsedRequest($req, $options);
        if ($request instanceof Error) {
            return $callback(Error::badRequest($request->getMessage()));
        }

        // extract bewit.
        if (strlen($request['url']) > Utils::$limits['maxMatchLength']) {
            return $callback(Error::badRequest('Resource path exceeds max length'));
        }

        preg_match(self::$bewitRegex, $request['url'], $resource);

        if ( ! $resource) {
            return $callback(Error::unauthorized());
        }

        // bewit not empty.
        if ( ! isset($resource[3]) || $resource[3] === '') {
            return $callback(Error::unauthorized('Empty bewit'));
        }

        // verify method is GET.
        if ($request['method'] !== 'GET' &&
            $request['method'] !== 'HEAD') {
            return $callback(Error::unauthorized('Invalid method'));
        }

        // no other authentication.
        if (isset($request['authorization'])) {
            return $callback(Error::badRequest('Multiple authentications'));
        }

        // parse bewit
        $bewitStr = Utils::getBase64Decode($resource[3]);
        if ($bewitStr instanceof Error) {
            return $callback(Error::badRequest('Invalid bewit encoding'));
        }

        // bewit format: id\exp\mac\ext ('\' is used because it is a reserved header attribute character)
        $bewitParts = explode('\\', $bewitStr);
        if (count($bewitParts) !== 4) {
            return $callback(Error::badRequest('Invalid bewit structure'));
        }

        $bewit = [
            // A required non-empty value.
            'id'  => (empty($bewitParts[0]) ? null : $bewitParts[0]),
            // A required value which can be zero as permitted by Client.getBewit.
            'exp' => ($bewitParts[1] === '' ? null : (integer ) $bewitParts[1]),
            'mac' => $bewitParts[2],
            'ext' => $bewitParts[3]
        ];

        if ( ! isset($bewit['id'], $bewit['exp'], $bewit['mac'])) {
            return $callback(Error::badRequest('Missing bewit attributes'));
        }

        // construct URL without bewit.
        $url = $resource[1];

        // check for additional query string parameteres.
        if (isset($resource[4]) && ! empty($resource[4])) {
            $url .= $resource[2] . $resource[4];
        }

        // check expiration.
        if ($bewit['exp'] * 1000 <= $now) {
            return $callback(Error::unauthorized('Access expired'), null, $bewit);
        }

        // fetch hawk credentials from application.
        $credentialsFunc($bewit['id'], function ($err = null, $credentials = null) use ($callback, &$request, &$bewit, &$url) {
            if ($err) {
                return $callback($err, $credentials, $bewit['ext']);
            }

            if (is_null($credentials)) {
                return $callback(Error::unauthorized('Unknown credentials'), null, $bewit);
            }

            if ( ! isset($credentials['key'], $credentials['algorithm'])) {
                return $callback(Error::internal('Invalid credentials'), $credentials, $bewit);
            }

            if ( ! in_array($credentials['algorithm'], Crypto::$algorithms)) {
                return $callback(Error::internal('Unknown algorithm'), $credentials, $bewit);
            }

            $artifacts = [
                'ts'       => $bewit['exp'],
                'nonce'    => '',
                'method'   => 'GET',
                'resource' => $url,
                'host'     => $request['host'],
                'port'     => $request['port'],
                'ext'      => $bewit['ext']
            ];

            // calculate MAC
            $mac = Crypto::getArtifactsMac('bewit', $credentials, $artifacts);

            if ( ! Utils::getFixedTimeComparison($mac, $bewit['mac'])) {
                return $callback(Error::unauthorized('Bad mac'), $credentials, $bewit);
            }

            // successful authentication
            return $callback(null, $credentials, $bewit);
        });
    }

    /*
     * Authenticate Message
     *
     * Options are the same as authenticate() with the exception
     * that the only supported options are:
     *      - 'nonceFunc'
     *      - 'timestampSkewSec'
     *      - 'localtimeOffsetMsec'
     */
    public static function authenticateMessage($host, $port, $message, array $authorization, callable $credentialsFunc, array $options, callable $callback)
    {
        // default options.
        $options['nonce_func'] = (isset($options['nonce_func']) ? $options['nonce_func'] : null);
        $options['timestamp_skew_sec'] = (isset($options['timestamp_skew_sec']) ? $options['timestamp_skew_sec'] : 60); // 60 seconds
        $options['localtime_offset_msec'] = (isset($options['localtime_offset_msec']) ? $options['localtime_offset_msec'] : null);

        // application time.
        $now = Utils::getTimeNowMs($options['localtime_offset_msec']);  // measure now before any other processing.

        // validate authorization.
        if ( ! isset($authorization['id'],
            $authorization['ts'],
            $authorization['nonce'],
            $authorization['hash'],
            $authorization['mac'])) {
            return $callback(Error::badRequest('Invalid authorization'));
        }

        // fetch hawk credentials from application.
        $credentialsFunc($authorization['id'], function ($err = null, $credentials = null) use ($callback, &$options, &$now, &$authorization, $message, $host, $port) {
            if ($err) {
                return $callback($err, $credentials);
            }

            if (is_null($credentials)) {
                return $callback(Error::unauthorized('Unknown credentials'));
            }

            if ( ! isset($credentials['key'], $credentials['algorithm'])) {
                return $callback(Error::internal('Invalid credentials'), $credentials);
            }

            if ( ! in_array($credentials['algorithm'], Crypto::$algorithms)) {
                return $callback(Error::internal('Unknown algorithm'), $credentials);
            }

            // construct artifacts container.
            $artifacts = [
                'ts'    => $authorization['ts'],
                'nonce' => $authorization['nonce'],
                'host'  => $host,
                'port'  => $port,
                'hash'  => $authorization['hash']
            ];

            // calculate MAC
            $mac = Crypto::getArtifactsMac('message', $credentials, $artifacts);
            if ( ! Utils::getFixedTimeComparison($mac, $authorization['mac'])) {
                return $callback(Error::unauthorized('Bad mac'), $credentials);
            }

            // check payload hash
            $hash = Crypto::getPayloadHash($message, $credentials['algorithm']);
            if ( ! Utils::getFixedTimeComparison($hash, $authorization['hash'])) {
                return $callback(Error::unauthorized('Bad message hash'), $credentials);
            }

            // check nonce.
            $nonceFunc = $options['nonce_func'];

            if (is_null($nonceFunc)) {
                $nonceFunc = function ($key, $nonce, $ts, callable $callback)
                {
                    return $callback(); // No validation
                };
            }

            $nonceFunc($credentials['key'], $authorization['nonce'], $authorization['ts'], function ($err = null) use ($callback, &$options, &$now, &$authorization, &$credentials) {
                if ($err) {
                    return $callback(Error::unauthorized('Invalid nonce'), $credentials);
                }

                // check timestamp staleness.
                if (abs(($authorization['ts'] * 1000) - $now) > ($options['timestamp_skew_sec'] * 1000)) {
                    return $callback(Error::unauthorized('Stale timestamp'), $credentials);
                }

                // successful authentication.
                return $callback(null, $credentials);
            });
        });
    }
}