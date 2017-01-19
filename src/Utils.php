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
 * Utility methods used throughout Guzzle.
 */
final class Utils
{
    /**
     * Maximum length that will be matched.
     *
     * Limit the length of uris and headers to avoid
     * a DoS attack on string matching
     *
     * @var array
     */
    public static $limits = [
        'maxMatchLength' => 4096
    ];

    /**
     * Keys whitelist
     *
     * @var array
     */
    public static $authorizationKeys = [
        'id', 'ts', 'nonce', 'hash', 'ext', 'mac', 'app', 'dlg'
    ];

    /**
     * Host Header: host[:port]
     *
     * Extract host and port from request (IPv4, hostname)|(IPv6)
     *
     * @var string
     */
    public static $hostHeaderRegex = '/^(?:(?:\r\n)?\s)*((?:[^:]+)|(?:\[[^\]]+\]))(?::(\d+))?(?:(?:\r\n)?\s)*$/';

    /**
     * Authorization Header: scheme[ something]
     *
     * @var string
     */
    public static $authHeaderRegex = '/^(\w+)(?:\s+(.*))?$/';

    /**
     * Attributes key/value pair pattern
     *
     * node regexp: /(\w+)="([^"\\]*)"\s*(?:,\s*|$)/g'
     *
     * Had to be altered to make it PHP-friendly which
     * escapes backslashes differently:
     * http://stackoverflow.com/q/11044136/
     *
     * \x5c = backslash
     *
     * @var string
     */
    public static $attributePartsRegex = '/(\w+)="([^"\x5c]*)"\s*(?:,\s*|$)/U';

    /**
     * Attributes value whitelist
     *
     * node regexp: /^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~]+$/
     *
     * !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9
     *
     * \040 = space
     * \x27 = apostrophe
     * \x5b = square bracket (left)
     * \x5d = square bracket (right)
     *
     * @var string
     */
    #public static $attributeRegex = '/^[ \w\!#\$%&\'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~]+$/';
    public static $attributeRegex = '/^[\040\w\!#\$%&\x27\(\)\*\+,\-\.\/\:;<\=>\?@\x5b\x5d\^`\{\|\}~]+$/';

    /**
     * Parse the Authorization Header
     *
     * @param string $header
     * @param array  $filterKeys List of keys required.
     *
     * @return string|null
     */
    public static function getParsedAuthorizationHeader($header, array $filterKeys = array())
    {
        $keys = (empty($filterKeys) ? self::$authorizationKeys : $filterKeys);

        if ( ! $header) {
            return Error::unauthorized();
        }

        if (strlen($header) > self::$limits['maxMatchLength']) {
            return Error::badRequest('Header length too long');
        }

        // split scheme from rest of string.
        preg_match(self::$authHeaderRegex, $header, $headerParts);

        @list(/* ignored */, $scheme, $attributesStr) = $headerParts;

        if ( ! isset($scheme, $attributesStr)) {
            return Error::badRequest('Invalid header syntax');
        }

        if (strtolower($scheme) !== 'hawk') {
            return Error::unauthorized();
        }

        $attributes = [];
        $errorMessage = '';
        $verify = '';

        $callback = function ($matches) use (&$keys, &$attributes, &$errorMessage) {
            list($str, $key, $val) = $matches;

            // check valid attribute names.
            if ( ! in_array($key, $keys)) {
                $errorMessage = 'Unknown attribute: ' . $key;
                return;
            }

            // check allowed attribute value characters:
            if ( ! preg_match(self::$attributeRegex, $val)) {
                $errorMessage = 'Bad attribute value: ' . $key;
                return;
            }

            // check for duplicate attributes.
            if (isset($attributes[$key])) {
                $errorMessage = 'Duplicate attribute: ' . $key;
                return;
            }

            $attributes[$key] = $val;

            return '';
        };

        $verify = preg_replace_callback(self::$attributePartsRegex, $callback, $attributesStr);

        $verify = trim($verify);

        if ($errorMessage !== '' || $verify !== '') {
            return Error::badRequest($errorMessage ? $errorMessage : 'Bad header format');
        }

        return $attributes;
    }

    /**
     * Set numerous HTTP headers
     *
     * @param array  $list List of headers.
     */
    public static function setHeaders(array $list)
    {
        foreach ($list as $k => $v) {
            // first header is status and has numeric key zero.
            $str = (is_numeric($k) && $k === 0 ? $v : $k . ': ' . $v);
            header($str);
        }
    }

    /**
     * Returns an HTTP status header
     *
     * @param integer $num Status number.
     *
     * @return string HTTP status header.
     */
    public static function getStatusHeader($num)
    {
        $statusCodes = [
            '200' => 'OK',
            '401' => 'Unauthorized',
            '500' => 'Internal Server Error',
        ];

        $str = (isset($statusCodes[$num]) ? $statusCodes[$num] : 'Unknown');

        return sprintf('HTTP/1.1 %d %s', $num, $str);
    }

    /**
     * Set multipart boundary MIME types.
     *
     * @param string $boundary Use the specified boundary delimiter.
     * @param array  $items    List of items to include in payload.
     *
     * @return string $payload Multipart payload.
     */
    public static function setBoundaryData($boundary, array $items)
    {
        /*
        $items = [
            [
                'name'     => 'myJsonString',
                'type'     => 'application/json',
                'data'     => json_encode( array( 'name' => time() ) ),
            ],
            [
                'name'     => 'photo',
                'type'     => 'image/jpeg',
                'data'     => base64_encode( $file ),
                'encoding' => 'base64',
            ]
        ];
        */

        $payload = '';

        foreach ($items as $item) {
            $payload .= '--' . $boundary . PHP_EOL
             . sprintf('Content-Disposition: form-data; name="%s"', $item['name']) . PHP_EOL
             . sprintf('Content-Type: %s', $item['type']) . PHP_EOL . PHP_EOL;

            if (isset($item['encoding'])) {
                $payload .= sprintf('Content-Transfer-Encoding: %s', $item['encoding']) . PHP_EOL . PHP_EOL;
            }

            $payload .= $item['data'] . PHP_EOL;
        }

        $payload .= PHP_EOL . '--' . $boundary . '--';

        return $payload;
    }

    /**
     * Determine If Connection Secure
     *
     * Based on WordPress function is_ssl():
     * http://stackoverflow.com/a/7304239/
     *
     * @return bool True if SSL, false if not used.
     */
    public static function isRequestSecure()
    {
        if (isset($_SERVER['HTTPS']) &&
            in_array(strtolower($_SERVER['HTTPS']), ['on', '1'])) {
            return true;
        } elseif (isset($_SERVER['SERVER_PORT']) &&
             ('443' === $_SERVER['SERVER_PORT'])) {
            return true;
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) &&
             ('https' === $_SERVER['HTTP_X_FORWARDED_PROTO'])) {
            return true;
        }

        return false;
    }

    /**
     * Get client requested URL
     *
     * @param string $url The URL to be parsed.
     *
     * @return array
     */
    public static function getParsedUrl($url)
    {
        $parts = parse_url($url);

        if (isset($parts['port'])) {
            $port = $parts['port'];
        } else { // no port specified; get default port
            if (isset($parts['scheme'])) {
                switch ($parts['scheme']) {
                    case 'http':
                        $port = 80;
                        break;
                    case 'https':
                        $port = 443;
                        break;
                    case 'ftp':
                        $port = 21;
                        break;
                    case 'ftps':
                        $port = 990;
                        break;
                    default:
                        $port = 0;
                        break;
                }
            } else {
                $port = 0; // error; unknown scheme
            }
        }

        $parts['port'] = $port;

        // uri.pathname + (uri.search || ''), // Maintain trailing '?'
        $parts['resource'] = (isset($parts['path']) ? $parts['path'] : '/')
            . (isset($parts['query']) ? '?' . $parts['query'] : '');

        return $parts;
    }

    /**
     * Get requested original URL
     *
     * @return string $url
     */
    public static function getOriginalUrl()
    {
        $secure = self::isRequestSecure();
        $host   = (isset($_SERVER['HTTP_HOST'])   ? $_SERVER['HTTP_HOST']   : '');
        $uri    = (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '');
        $port   = (isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : '');

        // determine a non-standard port.
        $is_standard_port = ($secure ? ($port === '443') : ($port === '80'));
        $port_str = ($is_standard_port ? '' : ':' . $port);

        return 'http' . ($secure ? 's' : '') . '://' .
            $host . $port_str . $uri;
    }

    /**
     * Get the clients request URL.
     *
     * @return string
     */
    public static function getRequestUrl()
    {
        return (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : null);
    }

    /**
     * Get the clients request method.
     *
     * @return string $requestMethod
     */
    public static function getRequestMethod()
    {
        $whitelist = ['PUT', 'DELETE', 'HEAD', 'PATCH', 'OPTIONS'];

        $_method = null;
        $requestMethod = (isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : null);

        // method overrides.
        if (isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {
            $_method = strtoupper( $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] );
        } elseif (isset($_POST['_method'])) {
            $_method = strtoupper( $_POST['_method'] );
        } elseif (isset($_GET['_method'])) {
            $_method = strtoupper( $_GET['_method'] );
        }

        if (isset($_method) && in_array($_method, $whitelist)) {
            $requestMethod = $_method;
        }

        return $requestMethod;
    }

    /**
     * Get request HTTP Authorization header.
     *
     * @return string $authorization
     */
    public static function getRequestAuthorizationHeader()
    {
        $authorization = (isset($_SERVER['AUTHORIZATION']) ? $_SERVER['AUTHORIZATION'] : null);

        // deprecated location and fallback.
        if ($authorization === null && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $authorization = $_SERVER['HTTP_AUTHORIZATION'];
        }

        return $authorization;
    }


    /**
     * Get request HTTP content type.
     *
     * @return string $contentType
     */
    public static function getRequestContentType()
    {
        $contentType = (isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : null);

        // deprecated location and fallback.
        if ($contentType === null && isset($_SERVER['HTTP_CONTENT_TYPE'])) {
            $contentType = $_SERVER['HTTP_CONTENT_TYPE'];
        }

        return $contentType;
    }

    /**
     * Get request headers
     *
     * Works for apache and nginx
     * http://php.net/manual/en/function.getallheaders.php#84262
     *
     * @return array
     */
    public static function getRequestHeaders()
    {
        $headers = [];

        $list = (function_exists('getallheaders') ? getallheaders() : $_SERVER);

        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) === 'HTTP_') {
                $key = strtolower($name);
                $key = str_replace('_', ' ', substr($key, 5));
                $key = str_replace(' ', '-', $key);

                $headers[$key] = $value;
            }
        }

        return $headers;
    }

    /**
     * Get original request
     *
     * Mocks node Request object.
     *
     * @return array
     */
    public static function getRequest()
    {
        $originalUrl = self::getOriginalUrl();

        $url = self::getParsedUrl($originalUrl);

        return [
            'method'  => self::getRequestMethod(),
            'url'     => self::getRequestUrl(),
            'host'    => $url['host'],
            'port'    => $url['port'],
            'headers' => self::getRequestHeaders(),
            'protocol'=> $url['scheme'],
            'secure'  => self::isRequestSecure()
        ];
    }

    /**
     * Parse host header.
     *
     * @return array $request
     */
    public static function getParsedHost(array $req = [], $hostHeaderName)
    {
        $hostHeaderName = $hostHeaderName ?: 'host';

        if ( ! isset($req['headers'][$hostHeaderName])) {
            return null;
        }

        $hostHeader = $req['headers'][$hostHeaderName];

        if (strlen($hostHeader) > self::$limits['maxMatchLength']) {
            return null;
        }

        // split scheme from rest of string.
        preg_match(self::$hostHeaderRegex, $hostHeader, $hostParts);

        if (empty($hostParts)) {
            return null;
        }

        @list(/* ignored */, $host, $port) = $hostParts;

        return [
            'name' => $host,
            'port' => $port ?: ($req['secure'] ? 443 : 80),
        ];
    }

    /**
     * Get details of the clients request.
     *
     * @return array $request
     */
    public static function getParsedRequest(array $req = [], array $options = [])
    {
        if ( ! isset($req['headers'])) {
            return $req;
        }

        // obtain host and port information from header.
        $host = [];
        if ( ! isset($options['host']) ||
            ! isset($options['port'])) {
            $hostHeaderName = (isset($options['host_header_name']) ? $options['host_header_name'] : null);
            $host = self::getParsedHost($req, $hostHeaderName);

            if (empty($host)) {
                return new Error('Invalid Host header');
            }
        }

        return [
            'method'        => $req['method'],
            'url'           => $req['url'],
            'host'          => (isset($options['host']) ? $options['host'] : $host['name']),
            'port'          => (isset($options['port']) ? $options['port'] : $host['port']),
            'authorization' => (isset($req['headers']['authorization']) ? $req['headers']['authorization'] : null),
            'content_type'  => (isset($req['headers']['content-type'])  ? $req['headers']['content-type']  : null)
        ];
    }


    /**
     * Return the local offset in milliseconds. [now()]
     *
     * @param integer $msOffset Local offset in milliseconds.
     *
     * @return integer $msNow
     */
    public static function getTimeNowMs($msOffset = 0)
    {
        $ms = round(microtime($float = true) * 1000);

        $msNow = $ms + $msOffset;

        return $msNow;
    }

    /**
     * Return the local offset in seconds. [nowSecs()]
     *
     * @param integer $msOffset Local offset in milliseconds.
     *
     * @return integer $secNow
     */
    public static function getTimeNowSec($msOffset)
    {
        $secNow = floor(self::getTimeNowMs($msOffset) / 1000);

        return $secNow;
    }

    /**
     * Escape attribute value for use in HTTP header.
     *
     * @param string $attribute Unescaped attribute.
     *
     * @return string $attribute Escaped attribute.
     */
    public static function getEscapeHeaderAttribute($attribute)
    {
        // allowed characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9, \, "
        $pattern = '/^[ \w\!#\$%&\'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~\"\\\\]*$/';
        $invalid = preg_match($pattern, $attribute, $match);
        $error = 'Bad Attribute Value: ' . $attribute;

        // TODO: in Node, this is an assert(value, message).
        //       should an exception simply be thrown here?

        // escape quotes and slash.
        $patterns     = ['/\\\\/', '/\"/'];
        $replacements = ['\\\\', '\\"'];
        $attribute = preg_replace($patterns, $replacements, $attribute);

        return $attribute;
    }

    /**
     * Parse the HTTP Content-Type header.
     *
     * @param string $header Raw header.
     *
     * @return string $type Parsed header with just the type.
     */
    public static function getParsedContentType($header)
    {
        $type = '';

        if ( ! empty($header)) {
            $parts = explode(';', $header);

            $type = strtolower(trim($parts[0]));
        }

        return $type;
    }

    /**
     * Generate a simple Nonce.
     *
     * @param integer $length    Character length for salt to be used.
     * @param string  $algorithm Hashing algorithim to use for nonce.
     *
     * @return string $type Parsed header with just the type.
     */
    public static function getNonce($length = 11, $algorithm = 'sha1')
    {
        // additional entropy with ISO 8601 date format.
        $time = date('c');

        $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $chars .= 'abcdefghijklmnopqrstuvwxyz';
        $chars .= '1234567890';

        $salt = '';

        for ($i = 0; $i < $length; $i++) {
            $salt .= substr($chars, (mt_rand() % (strlen($chars))), 1);
        }

        return hash($algorithm, $time . $salt);
    }

    /**
     * Compare two strings using a fixed-time algorithm.
     *
     * This method prevents time-based analysis of MAC digest
     * matches. (Cryptiles.fixedTimeComparison)
     *
     * @param string $a
     * @param string $b
     *
     * @return bool
     */
    public static function getFixedTimeComparison($a, $b)
    {
        if ( ! is_string($a) || ! is_string($b)) {
            return false;
        }

        $len = strlen($a);

        $mismatch = ($len === strlen($b) ? 0 : 1);

        if ($mismatch) {
            $b = $a;
        }

        for ($i = 0, $j = $len; $i < $j; $i += 1) {
            $ac = ord($a[$i]);
            $bc = ord($b[$i]);

            $mismatch |= ($ac ^ $bc);
        }

        return ($mismatch === 0);
    }

    /**
     * Encode using base64 (RFC 4648).
     *
     * @param string $value
     *
     * @return string
     */
    public static function getBase64Encode($value)
    {
        return strtr(rtrim(base64_encode($value), '='), '+/', '-_');
    }

    /**
     * Decode using base64 (RFC 4648).
     *
     * @param string $value
     *
     * @return string
     */
    public static function getBase64Decode($value)
    {
        if ( ! preg_match('/^[\w\-]*$/', $value)) {
            return new Error('Invalid character');
        }

        return base64_decode(strtr($value, '-_', '+/'), $strict = true);
    }

    /**
     * Get hash encoded with base64 (RFC 4648).
     *
     * @param string      $algorithm      The hash type.
     * @param string      $normalized     The normalized values.
     * @param string|null $key (Optional) Shared secret key used for generating the HMAC variant of the message digest.
     *
     * @return string $hash Base64 encoded hash.
     */
    public static function getBase64Hash($algorithm, $normalized, $key = null)
    {
        $rawOutput = true;

        if (is_null($key)) {
            $raw = hash($algorithm, $normalized, $rawOutput);
        } else {
            $raw = hash_hmac($algorithm, $normalized, $key, $rawOutput);
        }

        $hash = base64_encode($raw);

        return $hash;
    }
}