<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

use ssigwart\SSLChecker\SSLChecker;
use ssigwart\SSLChecker\SSLSubjectInfo;
use ssigwart\SSLChecker\SSLCheckerResult;
use ssigwart\SSLChecker\SSLCheckerException;

/**
 * SSLChecker test
 */
final class SSLCheckerTest extends TestCase
{
	/**
	 * Test valid SSL certificate
	 */
	public function testValidSsl(): void
	{
		$now = time();
		$domain = 'example.com';
		$expectedDomains = ['example.com', 'www.example.com'];
		$excludedDomains = ['www.otherdomain.com'];

		$sslCert = SSLChecker::getSSLInfoForDomain($domain);
		self::assertInstanceOf(SSLCheckerResult::class, $sslCert);
		self::assertInstanceOf(SSLSubjectInfo::class, $sslCert->getIssuerInfo());
		self::assertEquals('www.example.org', $sslCert->getCommonName());
		self::assertIsString($sslCert->getSerialNumber());
		self::assertLessThan($now, $sslCert->getIssuedTs());
		self::assertGreaterThan($now, $sslCert->getExpirationTs());
		self::assertTrue($sslCert->isCertificateValidForTime($now), 'Certificate should be valid.');

		// Check domains
		foreach ($expectedDomains as $checkDomain)
		{
			self::assertTrue($sslCert->isDomainIncluded($checkDomain), $checkDomain . ' should be on SSL.');
			self::assertTrue($sslCert->isCertificateValidForDomainTime($checkDomain, $now), $checkDomain . ' should be valid.');
		}
		foreach ($excludedDomains as $checkDomain)
			self::assertFalse($sslCert->isDomainIncluded($checkDomain), $checkDomain . ' should NOT be on SSL.');
	}

	/**
	 * Test expired SSL
	 */
	public function testExpiredSsl(): void
	{
		$now = time();
		$sslCert = SSLChecker::getSSLInfoForDomain('expired.badssl.com');
		self::assertLessThan($now, $sslCert->getExpirationTs());
		self::assertFalse($sslCert->isCertificateValidForTime($now), 'Certificate should NOT be valid.');
	}

	/**
	 * Test SSL timeout
	 */
	public function testSslTimeout(): void
	{
		$t1 = microtime(true);
		try
		{
			SSLChecker::setTimeout(0.25);
			SSLChecker::getSSLInfoForDomain('10.11.22.33');
			self::fail('Expected timeout.');
		} catch (SSLCheckerException $e) {
			self::assertTrue($e->isTimeout());
			self::assertTrue(preg_match('/Operation timed out/', $e->getMessage()) > 0);
		}
		$t2 = microtime(true);
		self::assertLessThanOrEqual(0.35, $t2 - $t1, 'Timeout should be < 0.25 sec (plus leeway).');
	}
}
