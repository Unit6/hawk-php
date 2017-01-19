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
 * Client interface for sending and receiving Hawk headers.
 *
 * @author Unit6 <team@unit6websites.com>
 */
interface ClientInterface
{
    /**
     * Generate a Hawk Authorization header for a given request
     *
     * @param string $uri     URL or URI
     * @param string $method  HTTP method
     * @param array  $options Array of request options to apply.
     *
     * @return array $result header parameters for a request.
     */
    public static function header($uri, $method, array $options);

    /**
     * Authenticate and validate a server response
     *
     * @param array $response    Servers response object.
     * @param array $credentials Users credentials.
     * @param array $artifacts   Extracted artifcats from the response.
     * @param array $options     Additional options including the servers payload.
     *
     * @return bool Outcome of authentication.
     */
    public static function authenticate(array $response, array $credentials, array $artifacts = array(), array $options = array());

    /**
     * Generate an authorization string for a message
     *
     * @param string  $host     Hostname.
     * @param integer $port     Port number.
     * @param string  $message  UTF-8 encoded string for body hash generation
     * @param array   $options  Additional options including credentials.
     *
     * @return array Authorization request.
    */
    public static function message($host, $port, $message, array $options);

    /**
     * Generate a bewit value for a given URI
     *
     * @param string|array  $uri      URI or request parameters.
     * @param array         $options  Additional options including credentials.
     *
     * @return string Bewit.
     */
    public static function getBewit($uri, array $options);
}
