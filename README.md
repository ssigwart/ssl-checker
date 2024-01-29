# SSL Checker

## Installing
```sh
composer require ssigwart/ssl-checker
```

## Checking an SSL Certificate

**Step 1: Get Certificate for Domain**
```php
try
{
	SSLChecker::setTimeout(5); // Optionally, set a timeout
	$sslCert = SSLChecker::getSSLInfoForDomain('example.org');
} catch (SSLCheckerException $e) {
	// Handle exceptions. This include timeouts.
	if ($e->isTimeout())
		print 'Timeout!' . PHP_EOL;
}
```

**Step 2: Check Certificate**
```php
// Get domain
print $sslCert->getCommonName() . PHP_EOL; // Should return "www.example.org"

// Get serial number
print $sslCert->getSerialNumber() . PHP_EOL;

// Get validity timestamps
print $sslCert->getIssuedTs() . PHP_EOL;
print $sslCert->getExpirationTs() . PHP_EOL;

// Check if certificate is valid for the time
print ($sslCert->isCertificateValidForTime(time()) ? 'Valid' : 'Not Valid') . PHP_EOL;

// Check if certificate is valid for domain and time
print ($sslCert->isCertificateValidForDomainTime('example.org', time()) ? 'Valid' : 'Not Valid') . PHP_EOL;
```
