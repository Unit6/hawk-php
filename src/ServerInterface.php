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
 * Server interface for handling Hawk requests.
 *
 * @author Unit6 <team@unit6websites.com>
 */
interface ServerInterface
{
    /**
     * Authenticate and validate a server response
     *
     * @param array    $request           HTTP request object.
     * @param callable $credentialsFunc   Function to lookup a set of Hawk credentials.
     * @param array    $options           Additional options.
     * @param callable $callback          Used to handle outcomes from the authenticate method.
     *
     * @return bool Outcome of authentication.
     */
    public static function authenticate(array $request, callable $credentialsFunc, array $options, callable $callback);

    /**
     * Generate a Hawk Server-Authorization header for a given response.
     *
     * @param array $credentials Users credentials.
     * @param array $artifacts   Extracted artifcats from the response.
     * @param array $options     Request options to apply.
     *
     * @return array $headers headers parameters for a request.
     */
    public static function header(array $credentials, array $artifacts, array $options = array());

    /**
     * Authenticate Bewit Request
     *
     * @param array    $request           HTTP request object.
     * @param callable $credentialsFunc   Function to lookup a set of Hawk credentials.
     * @param array    $options           Additional options.
     * @param callable $callback          Used to handle outcomes from the authenticate method.
     *
     * @return bool Outcome of authentication.
     */
    public static function authenticateBewit(array $request, callable $credentialsFunc, array $options, callable $callback);

    /*
     * Authenticate Message
     *
     * @param string   $host            Host name.
     * @param integer  $port            Port number.
     * @param string   $message         UTF-8 encoded string for body hash generation
     * @param array    $authorization   Authorization request from Client.
     * @param callable $credentialsFunc Function to lookup a set of Hawk credentials.
     * @param array    $options         Additional options including credentials.
     * @param callable $callback        Function to lookup a set of Hawk credentials.
     *
     * @return bool Outcome of authentication.
     */
    public static function authenticateMessage($host, $port, $message, array $authorization, callable $credentialsFunc, array $options, callable $callback);
}
