<?php

namespace ssigwart\SSLChecker;

use OpenSSLCertificate;

/** SSL checker result */
class SSLCheckerResult
{
	/** @var SSLSubjectInfo Subject info */
	private $subjectInfo = null;

	/** @var SSLSubjectInfo Issuer info */
	private $issuerInfo = null;

	/** @var string[] Subject alt names */
	private $sans = [];

	/** @var int|null Issued timestamp */
	private $issuedTs = null;

	/** @var int|null Expiration timestamp */
	private $expirationTs = null;

	/** @var string Serial number */
	private $serialNumber = null;

	/**
	 * Constructor
	 *
	 * @param OpenSSLCertificate $cert SSL certificate resource
	 */
	public function __construct(OpenSSLCertificate $cert)
	{
		openssl_x509_parse($cert);
		$sslInfo = openssl_x509_parse($cert);

		// Subject info
		$this->subjectInfo = new SSLSubjectInfo($sslInfo['subject']);

		// Issuer info
		$this->issuerInfo = new SSLSubjectInfo($sslInfo['issuer']);

		// Get SANS
		if (isset($sslInfo['extensions']['subjectAltName']))
		{
			foreach (preg_split('/,\\s*/', $sslInfo['extensions']['subjectAltName']) as $sanItem)
			{
				if (preg_match('/^DNS:(.*)$/AD', $sanItem, $match))
					$this->sans[] = $match[1];
			}
		}

		// Get dates
		$this->issuedTs = (int)($sslInfo['validFrom_time_t'] ?? 0);
		$this->expirationTs = (int)($sslInfo['validTo_time_t'] ?? 0);

		// Get serial number
		$this->serialNumber = $sslInfo['serialNumber'];
	}

	/**
	 * Get string representation
	 *
	 * @return string
	 */
	public function __toString(): string
	{
		$rtn = $this->subjectInfo . PHP_EOL;
		$rtn .= 'Expires: ' . date('m/d/Y g:i:s T', $this->expirationTs) . PHP_EOL;
		$rtn .= 'SANS: ' . implode(' ', $this->sans);
		return $rtn;
	}

	/**
	 * Get common name
	 *
	 * @return string|null Common name
	 */
	public function getCommonName(): ?string
	{
		return $this->subjectInfo->getCommonName();
	}

	/**
	 * Get subject info
	 *
	 * @return SSLSubjectInfo
	 */
	public function getSubjectInfo(): SSLSubjectInfo
	{
		return $this->subjectInfo;
	}

	/**
	 * Get issuer info
	 *
	 * @return SSLSubjectInfo
	 */
	public function getIssuerInfo(): SSLSubjectInfo
	{
		return $this->issuerInfo;
	}

	/**
	 * Get subject alternative names
	 *
	 * @return string[] Common name
	 */
	public function getSANs(): array
	{
		return $this->sans;
	}

	/**
	 * Is domain included?
	 *
	 * @param string $domain Domain name
	 *
	 * @return bool True if domain is included on certificate
	 */
	public function isDomainIncluded(string $domain): bool
	{
		$wildcardDomain = preg_replace('/^[^.]+\\./A', '*.', $domain);
		$allCertDomains = $this->sans;
		array_unshift($allCertDomains, $this->getCommonName());
		foreach ($allCertDomains as $allCertDomain)
		{
			if ($allCertDomain === $domain || $allCertDomain === $wildcardDomain)
				return true;
		}
		return false;
	}

	/**
	 * Is certificate valid for time?
	 *
	 * @param int $ts Timestamp
	 *
	 * @return bool True if the certificate is valid for the timestamp
	 */
	public function isCertificateValidForTime(int $ts): bool
	{
		return $this->issuedTs <= $ts && $this->expirationTs >= $ts;
	}

	/**
	 * Is certificate valid for domain and time?
	 *
	 * @param string $domain Domain
	 * @param int $ts Timestamp
	 *
	 * @return bool True if the domain is on the certificate and the certificate is valid for the timestamp
	 */
	public function isCertificateValidForDomainTime(string $domain, int $ts): bool
	{
		return $this->isCertificateValidForTime($ts) && $this->isDomainIncluded($domain);
	}

	/**
	 * Get issued timestamp
	 *
	 * @return int Issued timestamp
	 */
	public function getIssuedTs(): int
	{
		return $this->issuedTs;
	}

	/**
	 * Get valid to timestamp (e.g. expiration)
	 *
	 * @return int Expiration timestamp
	 */
	public function getExpirationTs(): int
	{
		return $this->expirationTs;
	}

	/**
	 * Get serial number
	 *
	 * @return string Serial number
	 */
	public function getSerialNumber(): string
	{
		return $this->serialNumber;
	}
}
