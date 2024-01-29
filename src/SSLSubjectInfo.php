<?php

namespace ssigwart\SSLChecker;

/** SSL subject info */
class SSLSubjectInfo
{
	/** @var string|null Common name */
	private $cn = null;

	/** @var string|null Organization (O) */
	private $org = null;

	/** @var string|null Organizational unit (OU) */
	private $orgUnit = null;

	/** @var string|null Locality or City (L) */
	private $city = null;

	/** @var string|null State or Province (ST) */
	private $state = null;

	/** @var string|null Country Name (C) */
	private $country = null;

	/**
	 * Constructor
	 *
	 * @param array $subjectInfo Subject info from `openssl_x509_parse`
	 */
	public function __construct(array $subjectInfo)
	{
		$this->cn = $subjectInfo['CN'] ?? null;
		$this->org = $subjectInfo['O'] ?? null;
		$orgUnit = $subjectInfo['OU'] ?? null;
		$this->orgUnit = is_array($orgUnit) ? implode('; ', $orgUnit) : $orgUnit;
		$this->city = $subjectInfo['L'] ?? null;
		$this->state = $subjectInfo['ST'] ?? null;
		$this->country = $subjectInfo['C'] ?? null;
	}

	/**
	 * Get string representation
	 *
	 * @return string
	 */
	public function __toString(): string
	{
		$rtn = 'Organization: ' . $this->org . PHP_EOL;
		$rtn .= 'Organizational Unit: ' . $this->orgUnit . PHP_EOL;
		$rtn .= 'Location: ' . ($this->city !== null ? $this->city . ', ' : ''). ($this->state !== null ? $this->state . ' ' : '') . $this->country;
		return $rtn;
	}

	/**
	 * Get common name
	 *
	 * @return string|null Common name
	 */
	public function getCommonName(): ?string
	{
		return $this->cn;
	}

	/**
	 * Get organization
	 *
	 * @return string|null Organization
	 */
	public function getOrganization(): ?string
	{
		return $this->org;
	}

	/**
	 * Get organizational unit
	 *
	 * @return string|null Organizational unit
	 */
	public function getOrganizationalUnit(): ?string
	{
		return $this->orgUnit;
	}

	/**
	 * Get city
	 *
	 * @return string|null city
	 */
	public function getCity(): ?string
	{
		return $this->city;
	}

	/**
	 * Get state
	 *
	 * @return string|null State
	 */
	public function getState(): ?string
	{
		return $this->state;
	}

	/**
	 * Get country
	 *
	 * @return string|null Country
	 */
	public function getCountry(): ?string
	{
		return $this->country;
	}
}
