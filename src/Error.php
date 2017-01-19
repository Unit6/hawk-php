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
 * Hawk Errors
 *
 * Client class for common response types and errors.
 */
class Error
{
    /**
     * Error Message
     *
     * @var string
     */
    protected $message;

    /**
     * Error Message
     *
     * @var integer
     */
    protected $statusCode;

    /**
     * Error Data
     *
     * @var mixed
     */
    protected $data;

    /**
     * Error Headers
     *
     * @var array
     */
    protected $headers;

    /**
     * Create Hawk Error
     *
     * @param string|null $message
     * @param integer|null $statusCode
     * @param mixed|null $data
     */
    public function __construct($message = null, $statusCode = null, $data = null)
    {
        $this->message = $message;
        $this->statusCode = $statusCode;
        $this->data = $data;
        $this->headers = [];

        // first header is the status.
        $this->headers[] = Utils::getStatusHeader($statusCode);
        $this->headers['X-Message'] = $message;
    }

    /**
     * Error Message
     *
     * @return string
     */
    public function getMessage()
    {
        return $this->message;
    }

    /**
     * Error Status Code
     *
     * @return integer
     */
    public function getStatusCode()
    {
        return $this->statusCode;
    }

    /**
     * Error Data
     *
     * @return mixed
     */
    public function getData()
    {
        return $this->data;
    }

    /**
     * Set Error Header
     *
     * @param string $key
     * @param string $value
     *
     * @return void
     */
    public function setHeader($key, $value)
    {
        $this->headers[$key] = $value;
    }

    /**
     * Set Error Headers
     *
     * @param array $headers
     *
     * @return void
     */
    public function setHeaders(array $headers = [])
    {
        $this->headers = $headers;
    }

    /**
     * Error Headers
     *
     * @return array
     */
    public function getHeaders()
    {
        return $this->headers;
    }

    /**
     * Get Header By Key
     *
     * @return string|null
     */
    public function getHeader($key)
    {
        return isset($this->headers[$key]) ? $this->headers[$key] : null;
    }

    /**
     * Set Error Output Headers
     *
     * @return void
     */
    public function output()
    {
        Utils::setHeaders($this->headers);
    }

    /**
     * Bad Request Error (400)
     *
     * @return self
     */
    public static function badRequest($message, $data = null)
    {
        return new self($message, 400, $data);
    }

    /**
     * Unauthorized Error (401)
     *
     * @return self
     */
    public static function unauthorized($message = null, $attributes = null)
    {
        $scheme = 'Hawk';
        #$message = ($message ? $message : 'Hawk authentication required');

        $wwwAuthenticate = $scheme;

        // append attributes to header.
        // it may contain a ts (timestamp) and
        // tsm (timestamp MAC) for adjustments.
        if ($attributes) {
            $keys = array_keys($attributes);
            $len = count($keys);

            for ($i = 0; $i < $len; $i += 1) {
                if ($i) {
                    $wwwAuthenticate .= ',';
                }

                $key = $keys[$i];

                // a value can be zero!
                $value = (isset($attributes[$key]) ? $attributes[$key] : '');
                $value = Utils::getEscapeHeaderAttribute($value);

                $wwwAuthenticate .= ' ' . $key . '="' . $value . '"';
            }
        }

        if ($message) {
            if ($attributes) {
                $wwwAuthenticate .= ',';
            }

            $wwwAuthenticate .= ' error="' . Utils::getEscapeHeaderAttribute($message) . '"';
        }

        $error = new Error($message, 401);
        $error->setHeader('WWW-Authenticate', $wwwAuthenticate);

        return $error;
    }

    /**
     * Server Errors (5xx)
     *
     * @return self
     */
    public static function internal($message, $data = null)
    {
        return new Error($message, 500, $data);
    }
}