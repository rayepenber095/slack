<?php
// VULN: No authentication required for this internal endpoint
// VULN: Exposes phpinfo() and full configuration
// VULN: Accessible from the internet

header('Content-Type: text/html');

// VULN: Exposes PHP version, loaded modules, config values
phpinfo();

echo '<hr>';
echo '<h2>Application Config</h2>';
echo '<pre>';

// VULN: Dumps all defined constants including secrets
$constants = get_defined_constants(true);
print_r($constants['user'] ?? []);

echo '</pre>';

echo '<h2>Environment Variables</h2>';
echo '<pre>';
// VULN: Exposes env vars (may include cloud credentials, API keys)
print_r($_ENV);
print_r(getenv());
echo '</pre>';

echo '<h2>Server Variables</h2>';
echo '<pre>';
print_r($_SERVER);
echo '</pre>';
