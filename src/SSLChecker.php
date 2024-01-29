<?php

namespace ssigwart\SSLChecker;

/** SSL checker */
class SSLChecker
{
	/** Don't allow instantiation */
	private function __construct()
	{}

	/** Stream context */
	private static mixed $streamContext = null;

	/** @var float Timeout (seconds) */
	private static float $timeout = 10.0;

	/**
	 * Get timeout (seconds)
	 *
	 * @return float Timeout (seconds)
	 */
	public static function getTimeout(): float
	{
		return self::$timeout;
	}

	/**
	 * Set timeout (seconds)
	 *
	 * @param float $timeout Timeout (seconds)
	 */
	public static function setTimeout(float $timeout): void
	{
		self::$timeout = $timeout;
	}

	/**
	 * Get SSL information for a domain
	 *
	 * @param string $domain Domain name
	 * @param int $port Port
	 *
	 * @return SSLCheckerResult
	 * @throws SSLCheckerException
	 */
	public static function getSSLInfoForDomain(string $domain, int $port = 443): SSLCheckerResult
	{
		$rtn = null;

		// Set up context
		if (self::$streamContext === null)
		{
			self::$streamContext = stream_context_create(['ssl' => [
				'capture_peer_cert' => true,
				'verify_peer' => false,
				'timeout' => self::$timeout
			]]);
		}

		// Open connection
		$streamSocket = @stream_socket_client('tls://' . $domain . ':' . $port, $errno, $error, self::$timeout, STREAM_CLIENT_CONNECT, self::$streamContext);
		if ($streamSocket === false)
			throw new SSLCheckerException($error, $errno);
		else
		{
			// Get SSL info
			$streamParams = stream_context_get_params($streamSocket);

			// Close connection
			stream_socket_shutdown($streamSocket, STREAM_SHUT_RDWR);

			// Throw exception if there's an error
			if ($errno !== 0)
				throw new SSLCheckerException($error, $errno);
			else
				$rtn = new SSLCheckerResult($streamParams['options']['ssl']['peer_certificate']);
		}

		return $rtn;
	}
}
