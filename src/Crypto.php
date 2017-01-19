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
 * Crypto class for calculating signatures.
 *
 * @author Unit6 <team@unit6websites.com>
 */
class Crypto
{
    // supported HMAC algorithms.
    public static $algorithms = ['sha1', 'sha256'];

    /**
     * Get Normalized Prefix
     *
     * @param string $type
     *
     * @return string
     */
    public static function getNormalizedPrefix($type)
    {
        return 'hawk.1.' . $type;
    }

    /**
     * Get Payload Hash (calculatePayloadHash)
     *
     * @param string $payload
     * @param string $algorithm
     * @param string $type
     *
     * @return string
     */
    public static function getPayloadHash($payload, $algorithm, $contentType = '')
    {
        $normalized = self::getNormalizedPrefix('payload') . "\n"
             . Utils::getParsedContentType($contentType) . "\n"
             . ($payload ? $payload : '') . "\n";

        return Utils::getBase64Hash($algorithm, $normalized);
    }

    /**
     * Get Hash MAC (calculateMac)
     *
     * @param string $type
     * @param string $credentials
     * @param array $artifacts
     *
     * @return string
     */
    public static function getArtifactsMac($type, $credentials, array $artifacts = array())
    {
        $normalized = self::getNormalizedPrefix($type) . "\n"
             . $artifacts['ts'] . "\n"
             . $artifacts['nonce'] . "\n"
             . (isset($artifacts['method']) ? strtoupper($artifacts['method']) : '') . "\n"
             . (isset($artifacts['resource']) ? $artifacts['resource'] : '') . "\n"
             . strtolower($artifacts['host']) . "\n"
             . $artifacts['port'] . "\n"
             . (isset($artifacts['hash']) ? $artifacts['hash'] : '') . "\n";

        if (isset($artifacts['ext'])) {
            $ext = $artifacts['ext'];
            $ext = str_replace( '\\', '\\\\', $ext );
            $ext = str_replace( '\n', '\\n', $ext );
            $normalized .= $ext;
        }

        $normalized .= "\n";

        // Web Authorization Protocol (OZ).
        if (isset($artifacts['app'])) {
            $normalized .= $artifacts['app'] . "\n"  // OZ 'Application ID'.
                // Optional 'Delegated By'. Requires 'Application ID'.
                . (isset($artifacts['dlg']) ? $artifacts['dlg'] : '') . "\n";
        }

        $algorithm = $credentials['algorithm'];
        $key = $credentials['key'];

        return Utils::getBase64Hash($algorithm, $normalized, $key);
    }

    /**
     * Get Timestamp Hash MAC
     *
     * @param integer $ts Timestamp
     * @param array $credentials
     *
     * @return string
     */
    public static function getTimestampHash($ts, $credentials)
    {
        $normalized = self::getNormalizedPrefix('ts') . "\n" . $ts . "\n";
        $algorithm = $credentials['algorithm'];
        $key = $credentials['key'];

        return Utils::getBase64Hash($algorithm, $normalized, $key);
    }

    /**
     * Get Timestamp Message
     *
     * @param array $credentials
     * @param integer $localtimeOffsetMs Local timestamp offset in milliseconds.
     *
     * @return array
     */
    public static function getTimestampMessage($credentials, $localtimeOffsetMs)
    {
        $now = Utils::getTimeNowSec($localtimeOffsetMs);
        $tsm = self::getTimestampHash($now, $credentials);

        return ['ts' => $now, 'tsm' => $tsm];
    }
}