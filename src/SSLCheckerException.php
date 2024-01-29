<?php

namespace ssigwart\SSLChecker;

use Exception;
use Throwable;

/** SSL checker exception */
class SSLCheckerException extends Exception
{
	/**
	 * Constructor
	 *
	 * @param string|null $msg Message
	 * @param int|null $code Code
	 * @param Throwable|null $prev Previous exception
	 */
	public function __construct(?string $msg, ?int $code, ?Throwable $prev = null)
	{
		if ($msg === null || $msg === '')
		{
			if ($code === 0)
				$msg = 'Failed to connect to host.';
			else
				$msg = 'Unknown error.';
		}
		parent::__construct($msg, $code, $prev);
	}

	/**
	 * Is this a timeout?
	 *
	 * @return bool True if a timeout
	 */
	public function isTimeout(): bool
	{
		return $this->code == 60 || $this->code == 110;
	}
}
