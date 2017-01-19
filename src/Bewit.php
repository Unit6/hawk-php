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
 * Bewit class for handling Hawk barear tokens.
 *
 * Generate bearer tokens for limited and short-term access to a
 * protected resource. Hawk provides limited support for such URIs
 * in the form of a bewit - a URI query parameter appended to the
 * request URI which contains the necessary credentials to
 * authenticate the request.
 *
 * exports.uri = {
 *     authenticate: exports.server.authenticateBewit,
 *     getBewit: exports.client.getBewit
 * };
 *
 *
 * @author Unit6 <team@unit6websites.com>
 */
class Bewit
{
    /**
     * Authenticate Request (server.authenticateBewit)
     */
    public static function authenticate()
    {
        return call_user_func_array([__NAMESPACE__ .'\Server', 'authenticateBewit'], func_get_args());
    }

    /**
     * Generate a Bewit value for a given URI (client.getBewit)
     */
    public static function generate()
    {
        return call_user_func_array([__NAMESPACE__ .'\Client', 'getBewit'], func_get_args());
    }
}