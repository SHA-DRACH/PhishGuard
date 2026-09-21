<?php
/**
 * PhishingDetector
 *
 * Rule/feature-based phishing detection engine. Every feature contributes
 * "risk points"; the total (capped at 100) is mapped to a verdict:
 *   score <  THRESHOLD_SUSPICIOUS           => safe
 *   score >= THRESHOLD_SUSPICIOUS           => suspicious
 *   score >= THRESHOLD_PHISHING             => phishing
 *
 * Feature groups (Chapter 2.3.4 of the project document):
 *   Reputation – blacklist / trusted-domain (whitelist) lookup
 *   Lexical    – URL length, IP host, '@', redirects, hyphens, sub-domains,
 *                HTTPS, TLD, shorteners, keywords, brand impersonation,
 *                typosquatting, punycode, ports, entropy, obfuscation
 *   Host       – DNS resolution, SSL certificate validity & age
 *   Content    – password forms, external form actions, hidden iframes,
 *                brand in page title, meta-refresh, cross-domain redirects
 */
class PhishingDetector
{
    private const SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly',
        'rebrand.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bl.ink', 's.id', 'v.gd', 'lnkd.in', 'shorte.st', 'adf.ly',
    ];

    private const SUSPICIOUS_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'zip', 'mov', 'click', 'country', 'work', 'rest',
        'buzz', 'icu', 'cam', 'monster', 'quest', 'cyou', 'sbs', 'cfd', 'loan', 'win', 'bid', 'kim', 'support',
    ];

    private const KEYWORDS = [
        'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'account', 'update',
        'confirm', 'banking', 'password', 'passwd', 'wallet', 'suspend', 'unlock', 'webscr', 'billing',
        'invoice', 'recover', 'validate', 'authenticate', 'bonus', 'free-gift', 'lucky', 'reward', 'airtime',
        'mobilemoney', 'momo', 'kyc',
    ];

    /** Common second-level public suffixes (incl. Liberia .lr). */
    private const MULTI_SUFFIXES = [
        'com.lr', 'org.lr', 'net.lr', 'gov.lr', 'edu.lr',
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'co.za', 'org.za', 'com.ng', 'gov.ng',
        'com.gh', 'gov.gh', 'co.ke', 'co.in', 'co.jp', 'com.br', 'com.cn', 'com.sg', 'co.nz', 'com.mx',
    ];

    private PDO $db;
    private bool $networkChecks;
    private bool $deep;
    private array $features = [];
    private int $score = 0;
    private array $domainInfo = [];
    private array $weights = [];
    private array $weightDefaults = [];
    private array $keywords = [];
    private array $riskyTlds = [];
    private array $shorteners = [];

    /**
     * @param bool      $networkChecks Domain intelligence: DNS existence, registration/age, reachability, Safe Browsing
     * @param bool|null $deep          Also inspect the SSL certificate and download the page content (defaults to $networkChecks)
     */
    public function __construct(PDO $db, bool $networkChecks = true, ?bool $deep = null)
    {
        $this->db = $db;
        $this->networkChecks = $networkChecks;
        $this->deep = $networkChecks && ($deep ?? true);

        // Admin-managed lists and weights (Admin → System settings); constants are the fallbacks
        $this->weights = function_exists('setting_weights') ? setting_weights() : [];
        $this->weightDefaults = function_exists('weight_defaults') ? array_map(fn($d) => $d[1], weight_defaults()) : [];
        $this->keywords = function_exists('setting_list') ? (setting_list('keywords') ?: self::KEYWORDS) : self::KEYWORDS;
        $this->riskyTlds = function_exists('setting_list') ? (setting_list('suspicious_tlds') ?: self::SUSPICIOUS_TLDS) : self::SUSPICIOUS_TLDS;
        $this->shorteners = function_exists('setting_list') ? (setting_list('shorteners') ?: self::SHORTENERS) : self::SHORTENERS;
    }

    /* ------------------------------------------------------------------ */

    public function analyze(string $input): array
    {
        $start = microtime(true);
        $this->features = [];
        $this->score = 0;

        $url = self::normalizeUrl($input);
        $parts = parse_url($url);
        if ($url === '' || $parts === false || empty($parts['host'])) {
            throw new InvalidArgumentException('Please enter a valid website address (e.g. https://example.com).');
        }

        $host = strtolower(rtrim($parts['host'], '.'));
        $host = trim($host, '[]');
        $scheme = strtolower($parts['scheme'] ?? 'http');
        $isIp = filter_var($host, FILTER_VALIDATE_IP) !== false;
        $regDomain = $isIp ? $host : self::registrableDomain($host);

        $listMatch = null;
        $finalUrl = $url;
        $trusted = $this->loadTrusted();

        // ---------- Reputation ----------
        if ($bl = $this->matchList('blacklist', $host)) {
            $listMatch = 'blacklist';
            $this->add('reputation', 'blacklist', 'Blacklist lookup',
                'Domain is on the phishing blacklist' . ($bl['reason'] ? ' – ' . $bl['reason'] : ''), 100, 'danger');
        } elseif ($this->isTrusted($host, $trusted)) {
            $listMatch = 'whitelist';
            $this->add('reputation', 'whitelist', 'Trusted domain lookup', 'Domain is on the trusted (verified) list', 0, 'safe');
        } else {
            $this->add('reputation', 'lists', 'Blacklist / trusted list', 'Not found in either list', 0, 'info');
        }

        // ---------- Lexical ----------
        $len = strlen($url);
        if ($len > 75)      $this->add('lexical', 'length', 'URL length', "$len characters (very long)", 8, 'warn');
        elseif ($len > 54)  $this->add('lexical', 'length', 'URL length', "$len characters (long)", 4, 'warn');
        else                $this->add('lexical', 'length', 'URL length', "$len characters", 0, 'safe');

        $isIp
            ? $this->add('lexical', 'ip_host', 'IP address as host', 'Uses a raw IP address instead of a domain name', 25, 'danger')
            : $this->add('lexical', 'ip_host', 'IP address as host', 'Uses a domain name', 0, 'safe');

        $authority = self::authority($url);
        str_contains($authority, '@')
            ? $this->add('lexical', 'at_symbol', '"@" symbol', 'Contains "@" – browser ignores everything before it', 20, 'danger')
            : $this->add('lexical', 'at_symbol', '"@" symbol', 'Not present', 0, 'safe');

        strrpos($url, '//') > 7
            ? $this->add('lexical', 'double_slash', 'Double-slash redirect', 'Extra "//" found in path (possible redirect)', 10, 'warn')
            : $this->add('lexical', 'double_slash', 'Double-slash redirect', 'Not present', 0, 'safe');

        $hyphens = substr_count($regDomain, '-');
        if ($hyphens >= 2)     $this->add('lexical', 'hyphen', 'Hyphens in domain', "$hyphens hyphens in domain", 10, 'warn');
        elseif ($hyphens == 1) $this->add('lexical', 'hyphen', 'Hyphens in domain', '1 hyphen in domain', 5, 'warn');
        else                   $this->add('lexical', 'hyphen', 'Hyphens in domain', 'None', 0, 'safe');

        if (!$isIp) {
            $sub = $host === $regDomain ? '' : substr($host, 0, -strlen($regDomain) - 1);
            $subCount = $sub === '' || $sub === 'www' ? 0 : count(explode('.', $sub));
            if ($subCount >= 3)     $this->add('lexical', 'subdomains', 'Sub-domain depth', "$subCount sub-domain levels", 12, 'danger');
            elseif ($subCount == 2) $this->add('lexical', 'subdomains', 'Sub-domain depth', '2 sub-domain levels', 6, 'warn');
            else                    $this->add('lexical', 'subdomains', 'Sub-domain depth', $subCount ? '1 sub-domain level' : 'None', 0, 'safe');
        }

        $scheme === 'https'
            ? $this->add('lexical', 'https', 'HTTPS', 'Connection uses HTTPS', 0, 'safe')
            : $this->add('lexical', 'https', 'HTTPS', 'No HTTPS – data is sent unencrypted', 12, 'danger');

        $tld = $isIp ? '' : substr(strrchr($host, '.') ?: '', 1);
        in_array($tld, $this->riskyTlds, true)
            ? $this->add('lexical', 'tld', 'Top-level domain', ".$tld is frequently abused for phishing", 10, 'warn')
            : $this->add('lexical', 'tld', 'Top-level domain', $tld ? ".$tld" : 'n/a', 0, 'safe');

        in_array($regDomain, $this->shorteners, true) || in_array($host, $this->shorteners, true)
            ? $this->add('lexical', 'shortener', 'URL shortener', "$regDomain hides the real destination", 15, 'warn')
            : $this->add('lexical', 'shortener', 'URL shortener', 'Not a known shortener', 0, 'safe');

        $lower = strtolower($url);
        $found = array_values(array_filter($this->keywords, fn($k) => str_contains($lower, $k)));
        if ($found) {
            $pts = min(20, count($found) * 5);
            $this->add('lexical', 'keywords', 'Sensitive keywords', implode(', ', array_slice($found, 0, 6)), $pts, $pts >= 10 ? 'danger' : 'warn');
        } else {
            $this->add('lexical', 'keywords', 'Sensitive keywords', 'None found', 0, 'safe');
        }

        // Brand impersonation & typosquatting (uses trusted domains that carry a brand keyword)
        if (!$isIp && $listMatch !== 'whitelist') {
            [$impersonated, $typo] = $this->brandChecks($host, $regDomain, $trusted);
            $impersonated
                ? $this->add('lexical', 'brand', 'Brand impersonation', "Mentions \"{$impersonated['brand']}\" but is not {$impersonated['domain']}", 25, 'danger')
                : $this->add('lexical', 'brand', 'Brand impersonation', 'No trusted brand name misused', 0, 'safe');
            $typo
                ? $this->add('lexical', 'typosquat', 'Look-alike domain', "\"$regDomain\" closely resembles {$typo['domain']}", 30, 'danger')
                : $this->add('lexical', 'typosquat', 'Look-alike domain', 'No look-alike of a trusted domain', 0, 'safe');
        }

        str_contains($host, 'xn--')
            ? $this->add('lexical', 'punycode', 'Punycode / IDN', 'Internationalised domain – may use look-alike characters', 15, 'danger')
            : $this->add('lexical', 'punycode', 'Punycode / IDN', 'Not used', 0, 'safe');

        if (!empty($parts['port']) && !in_array((int)$parts['port'], [80, 443], true)) {
            $this->add('lexical', 'port', 'Non-standard port', 'Port ' . (int)$parts['port'], 8, 'warn');
        }

        $digits = preg_match_all('/\d/', $regDomain);
        if (!$isIp && $digits >= 4) {
            $this->add('lexical', 'digits', 'Digits in domain', "$digits digits in domain name", 6, 'warn');
        }

        $label = explode('.', $regDomain)[0] ?? '';
        $entropy = self::entropy($label);
        if (!$isIp && strlen($label) >= 10 && $entropy > 3.5) {
            $this->add('lexical', 'entropy', 'Random-looking domain', sprintf('Entropy %.2f – looks auto-generated', $entropy), 6, 'warn');
        }

        $encoded = preg_match_all('/%[0-9a-f]{2}/i', $url);
        if ($encoded > 3) {
            $this->add('lexical', 'encoding', 'URL obfuscation', "$encoded percent-encoded characters", 5, 'warn');
        }

        // ---------- Domain intelligence, host & content (network) ----------
        $this->domainInfo = ['checked' => false];
        if ($this->networkChecks && $listMatch === null) {
            if ($this->safeBrowsingListed($url)) {
                $listMatch = 'safebrowsing';
            } else {
                $exists = $this->domainChecks($host, $regDomain, $isIp);
                if ($exists) {
                    if ($this->deep) {
                        if ($scheme === 'https') $this->sslCheck($host);
                        if (FETCH_CONTENT) {
                            $finalUrl = $this->contentChecks($url, $host, $regDomain, $trusted) ?? $url;
                        }
                    } else {
                        $this->reachabilityCheck($url, $host);
                    }
                }
            }
        }

        // ---------- Verdict ----------
        $score = match ($listMatch) {
            'blacklist', 'safebrowsing' => 100,
            'whitelist' => 0,
            default     => min(100, $this->score),
        };
        // A website that cannot be found or opened can never be reported as safe
        if ($listMatch === null && (($this->domainInfo['exists'] ?? null) === false || ($this->domainInfo['reachable'] ?? null) === false)) {
            $score = max($score, THRESHOLD_SUSPICIOUS);
        }
        $verdict = $score >= THRESHOLD_PHISHING ? 'phishing' : ($score >= THRESHOLD_SUSPICIOUS ? 'suspicious' : 'safe');

        return [
            'url'         => $url,
            'host'        => $host,
            'domain'      => $regDomain,
            'score'       => $score,
            'verdict'     => $verdict,
            'list_match'  => $listMatch,
            'final_url'   => $finalUrl,
            'features'    => $this->features,
            'domain_info' => $this->domainInfo,
            'network'     => $this->networkChecks,
            'deep'        => $this->deep,
            'duration_ms' => (int)round((microtime(true) - $start) * 1000),
        ];
    }

    /* ------------------------------------------------------------------ */

    private function add(string $group, string $id, string $label, string $result, int $risk, string $status): void
    {
        // Scale by the admin-configured weight (0 switches the feature off)
        if ($risk > 0 && isset($this->weights[$id], $this->weightDefaults[$id]) && $this->weightDefaults[$id] > 0) {
            $risk = (int)round($risk * $this->weights[$id] / $this->weightDefaults[$id]);
            if ($risk === 0 && $status !== 'info') $status = 'info';
        }
        $this->features[] = compact('group', 'id', 'label', 'result', 'risk', 'status');
        $this->score += $risk;
    }

    private function loadTrusted(): array
    {
        return $this->db->query('SELECT domain, brand FROM whitelist')->fetchAll();
    }

    private function isTrusted(string $host, array $trusted): bool
    {
        foreach ($trusted as $t) {
            if ($host === $t['domain'] || str_ends_with($host, '.' . $t['domain'])) {
                return true;
            }
        }
        return false;
    }

    private function matchList(string $table, string $host): ?array
    {
        // Match exact host or any parent domain
        $candidates = [];
        $labels = explode('.', $host);
        for ($i = 0; $i < count($labels) - 1; $i++) {
            $candidates[] = implode('.', array_slice($labels, $i));
        }
        if (!$candidates) $candidates = [$host];
        $in = implode(',', array_fill(0, count($candidates), '?'));
        $stmt = $this->db->prepare("SELECT * FROM $table WHERE domain IN ($in) LIMIT 1");
        $stmt->execute($candidates);
        return $stmt->fetch() ?: null;
    }

    private function brandChecks(string $host, string $regDomain, array $trusted): array
    {
        $impersonated = null;
        $typo = null;
        $hostNorm = self::deHomoglyph($host);
        $label = explode('.', $regDomain)[0];
        $labelNorm = self::deHomoglyph($label);

        foreach ($trusted as $t) {
            $brand = strtolower((string)$t['brand']);
            if ($brand === '' || strlen($brand) < 4) continue;

            if (!$impersonated && (str_contains($host, $brand) || str_contains($hostNorm, $brand))) {
                $impersonated = $t;
            }

            $trustedLabel = explode('.', $t['domain'])[0];
            if (!$typo && $label !== $trustedLabel && strlen($trustedLabel) >= 4) {
                $maxDist = strlen($trustedLabel) >= 8 ? 2 : 1;
                if ($labelNorm === $trustedLabel || levenshtein($label, $trustedLabel) <= $maxDist) {
                    $typo = $t;
                }
            }
        }
        return [$impersonated, $typo];
    }

    /* ------------------------ domain intelligence ------------------------ */

    /**
     * Does the domain really exist on the Internet (can a browser open it)? Is it registered, and how old is it?
     * Uses DNS-over-HTTPS so ISP resolvers that answer for non-existent names cannot fool the check.
     * Returns false when the site cannot exist, so later network checks are skipped.
     */
    private function domainChecks(string $host, string $regDomain, bool $isIp): bool
    {
        $this->domainInfo = ['checked' => true, 'exists' => null, 'registered' => null, 'created' => null,
                             'age_days' => null, 'ips' => [], 'reachable' => null, 'safebrowsing' => SAFE_BROWSING_API_KEY !== '' ? 'clean' : 'off'];
        if ($isIp) {
            $this->domainInfo['exists'] = true;
            $this->domainInfo['ips'] = [$host];
            return true;
        }

        // 1. DNS existence
        $dns = $this->resolve($host);
        if ($dns['status'] === 'nxdomain') {
            $this->domainInfo['exists'] = false;
            $regMissing = $host === $regDomain || $this->resolve($regDomain)['status'] === 'nxdomain';
            $this->add('host', 'dns', 'Domain exists',
                $regMissing ? "\"$regDomain\" does not exist on the Internet – no browser can open it"
                            : "The sub-domain \"$host\" does not exist, although $regDomain does", 40, 'danger');
        } elseif ($dns['status'] === 'noaddress') {
            $this->domainInfo['exists'] = false;
            $this->add('host', 'dns', 'Domain exists', ($host === $regDomain ? 'The domain' : "The sub-domain \"$host\"") . ' points to no server – no browser can open it', 30, 'danger');
        } elseif ($dns['status'] === 'ok') {
            $this->domainInfo['exists'] = true;
            $this->domainInfo['ips'] = $dns['ips'];
            $this->add('host', 'dns', 'Domain exists', 'Found on the Internet – resolves to ' . implode(', ', array_slice($dns['ips'], 0, 2)), 0, 'safe');
            $private = array_filter($dns['ips'], fn($ip) => !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE));
            if ($private) {
                $this->add('host', 'dns_private', 'Public address', 'Domain points to a private/internal IP address', 15, 'danger');
            }
        } else {
            $this->add('host', 'dns', 'Domain exists', 'DNS lookup failed – existence could not be verified', 10, 'warn');
        }

        // 2. Registration & age (RDAP – the modern WHOIS)
        $rdap = $this->rdap($regDomain);
        if ($rdap['status'] === 'unregistered') {
            $this->domainInfo['registered'] = false;
            // Existence already scored above; registration adds a little weight only when DNS could not decide
            $this->add('host', 'registration', 'Domain registration', "\"$regDomain\" is not registered with any registrar", $this->domainInfo['exists'] === false ? 5 : 30, 'danger');
        } elseif ($rdap['status'] === 'ok' && $rdap['created']) {
            $this->domainInfo['registered'] = true;
            $days = (int)floor((time() - strtotime($rdap['created'])) / 86400);
            $this->domainInfo['created'] = substr($rdap['created'], 0, 10);
            $this->domainInfo['age_days'] = $days;
            $when = date('M j, Y', strtotime($rdap['created']));
            $ageText = $days >= 730 ? floor($days / 365) . ' years' : ($days >= 60 ? floor($days / 30) . ' months' : "$days days");
            [$risk, $status, $note] = match (true) {
                $days < 30  => [25, 'danger', ' – brand-new domains are a strong phishing sign'],
                $days < 180 => [12, 'warn', ' – recently created'],
                $days < 365 => [5, 'warn', ''],
                default     => [0, 'safe', ''],
            };
            $this->add('host', 'domain_age', 'Domain age', "Registered $when ($ageText ago)$note", $risk, $status);
        } elseif ($rdap['status'] === 'ok') {
            $this->domainInfo['registered'] = true;
            $this->add('host', 'domain_age', 'Domain age', 'Registered (creation date not published)', 0, 'info');
        } else {
            $tld = substr(strrchr($regDomain, '.') ?: '', 1);
            $this->add('host', 'domain_age', 'Domain age', $rdap['status'] === 'unsupported'
                ? "Registration data is not published for .$tld domains" : 'Registration lookup unavailable', 0, 'info');
        }

        return $this->domainInfo['exists'] !== false;
    }

    /** DNS-over-HTTPS lookup (Google, then Cloudflare), falling back to the system resolver. */
    private function resolve(string $name): array
    {
        static $cache = [];
        if (isset($cache[$name])) return $cache[$name];

        foreach (['https://dns.google/resolve?type=A&name=', 'https://cloudflare-dns.com/dns-query?type=A&name='] as $endpoint) {
            $json = self::httpGetJson($endpoint . rawurlencode($name), ['Accept: application/dns-json'], 5);
            if (!is_array($json) || !isset($json['Status'])) continue;
            if ((int)$json['Status'] === 3) return $cache[$name] = ['status' => 'nxdomain', 'ips' => []];
            if ((int)$json['Status'] !== 0) continue;
            $ips = array_values(array_map(fn($a) => $a['data'], array_filter($json['Answer'] ?? [], fn($a) => (int)$a['type'] === 1)));
            if (!$ips) {   // no IPv4 – try IPv6 before declaring "no address"
                $v6 = self::httpGetJson(str_replace('type=A', 'type=AAAA', $endpoint) . rawurlencode($name), ['Accept: application/dns-json'], 5);
                $ips = array_values(array_map(fn($a) => $a['data'], array_filter($v6['Answer'] ?? [], fn($a) => (int)$a['type'] === 28)));
            }
            return $cache[$name] = $ips ? ['status' => 'ok', 'ips' => $ips] : ['status' => 'noaddress', 'ips' => []];
        }

        $ips = @gethostbynamel($name) ?: [];
        return $cache[$name] = $ips ? ['status' => 'ok', 'ips' => $ips] : ['status' => 'error', 'ips' => []];
    }

    /** RDAP registration lookup via the IANA bootstrap registry. Cached in domain_cache for 12 hours. */
    private function rdap(string $domain): array
    {
        $stmt = $this->db->prepare('SELECT data FROM domain_cache WHERE domain = ? AND fetched_at > NOW() - INTERVAL 12 HOUR');
        $stmt->execute([$domain]);
        if ($row = $stmt->fetchColumn()) return json_decode($row, true);

        $tld = substr(strrchr($domain, '.') ?: '', 1);
        $servers = $this->rdapBootstrap();
        if ($servers === null) return ['status' => 'error', 'created' => null];
        if (empty($servers[$tld])) return ['status' => 'unsupported', 'created' => null];

        $code = 0;
        $json = self::httpGetJson(rtrim($servers[$tld], '/') . '/domain/' . rawurlencode($domain), ['Accept: application/rdap+json'], 8, $code);
        if ($code === 404) {
            $result = ['status' => 'unregistered', 'created' => null];
        } elseif (is_array($json) && isset($json['ldhName'])) {
            $created = null;
            foreach ($json['events'] ?? [] as $e) {
                if (($e['eventAction'] ?? '') === 'registration') $created = $e['eventDate'];
            }
            $result = ['status' => 'ok', 'created' => $created];
        } else {
            return ['status' => 'error', 'created' => null]; // do not cache transient failures
        }
        $this->db->prepare('REPLACE INTO domain_cache (domain, data, fetched_at) VALUES (?, ?, NOW())')
            ->execute([$domain, json_encode($result)]);
        return $result;
    }

    /** TLD => RDAP base URL map from IANA, cached on disk for 7 days. */
    private function rdapBootstrap(): ?array
    {
        $file = __DIR__ . '/../data/rdap_bootstrap.json';
        if (!is_file($file) || filemtime($file) < time() - 7 * 86400) {
            $json = self::httpGetJson('https://data.iana.org/rdap/dns.json', [], 10);
            if (is_array($json) && !empty($json['services'])) {
                $map = [];
                foreach ($json['services'] as [$tlds, $urls]) {
                    $https = array_values(array_filter($urls, fn($u) => str_starts_with($u, 'https://')));
                    foreach ($tlds as $t) $map[strtolower($t)] = $https[0] ?? $urls[0];
                }
                @file_put_contents($file, json_encode($map));
                return $map;
            }
        }
        return is_file($file) ? json_decode(file_get_contents($file), true) : null;
    }

    /** Quick check that a website actually answers (used when the deep content scan is off). */
    private function reachabilityCheck(string $url, string $host): void
    {
        $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : ($this->domainInfo['ips'][0] ?? '');
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return; // SSRF guard
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_NOBODY => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 5,
            CURLOPT_CONNECTTIMEOUT => FETCH_TIMEOUT, CURLOPT_TIMEOUT => FETCH_TIMEOUT + 2,
            CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0, CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS, CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard/1.0',
        ]);
        curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($status === 0) {
            $this->domainInfo['reachable'] = false;
            $this->add('host', 'reachable', 'Website reachable', 'The domain exists but no website answers – it cannot be opened in a browser', 25, 'danger');
        } else {
            $this->domainInfo['reachable'] = true;
            $this->domainInfo['http_status'] = $status;
            $this->add('host', 'reachable', 'Website reachable', "Website answers (HTTP $status)", 0, 'safe');
        }
    }

    /** Google Safe Browsing – the same threat list Chrome uses. Only active when an API key is configured. */
    private function safeBrowsingListed(string $url): bool
    {
        if (SAFE_BROWSING_API_KEY === '') return false;
        $payload = json_encode([
            'client' => ['clientId' => 'phishguard-ltc', 'clientVersion' => '1.0'],
            'threatInfo' => [
                'threatTypes' => ['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes' => ['ANY_PLATFORM'], 'threatEntryTypes' => ['URL'], 'threatEntries' => [['url' => $url]],
            ],
        ]);
        $ch = curl_init('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . rawurlencode(SAFE_BROWSING_API_KEY));
        curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $payload, CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 6, CURLOPT_HTTPHEADER => ['Content-Type: application/json']]);
        $json = json_decode((string)curl_exec($ch), true);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($code !== 200) {
            $this->add('reputation', 'safebrowsing', 'Google Safe Browsing', 'Lookup failed (check the API key)', 0, 'info');
            return false;
        }
        if (!empty($json['matches'])) {
            $type = str_replace('_', ' ', strtolower($json['matches'][0]['threatType'] ?? 'threat'));
            $this->domainInfo = ['checked' => true, 'safebrowsing' => 'listed'];
            $this->add('reputation', 'safebrowsing', 'Google Safe Browsing', "Flagged by Google as $type – Chrome would block this site", 100, 'danger');
            return true;
        }
        $this->add('reputation', 'safebrowsing', 'Google Safe Browsing', 'Not on Google\'s list of dangerous sites', 0, 'safe');
        return false;
    }

    private static function httpGetJson(string $url, array $headers = [], int $timeout = 6, ?int &$code = null): ?array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 3,
            CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => $timeout, CURLOPT_HTTPHEADER => $headers,
            CURLOPT_USERAGENT => 'PhishGuard/1.0 (+phishing detection)']);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($body === false || $body === '') return null;
        $json = json_decode($body, true);
        return is_array($json) ? $json : null;
    }

    private function sslCheck(string $host): void
    {
        $ctx = stream_context_create(['ssl' => [
            'capture_peer_cert' => true, 'verify_peer' => true, 'verify_peer_name' => true, 'SNI_enabled' => true, 'peer_name' => $host,
        ]]);
        $client = @stream_socket_client("ssl://$host:443", $errno, $errstr, FETCH_TIMEOUT, STREAM_CLIENT_CONNECT, $ctx);
        if (!$client) {
            $this->add('host', 'ssl', 'SSL certificate', 'Certificate is invalid, self-signed or does not match the domain', 15, 'danger');
            return;
        }
        $params = stream_context_get_params($client);
        fclose($client);
        $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate'] ?? '');
        if (!$cert) {
            $this->add('host', 'ssl', 'SSL certificate', 'Could not read certificate', 5, 'warn');
            return;
        }
        $issuer = $cert['issuer']['O'] ?? $cert['issuer']['CN'] ?? 'unknown issuer';
        $ageDays = (int)floor((time() - $cert['validFrom_time_t']) / 86400);
        $this->add('host', 'ssl', 'SSL certificate', "Valid – issued by $issuer", 0, 'safe');
        if ($ageDays < 7) {
            $this->add('host', 'cert_age', 'Certificate age', "Issued only $ageDays day(s) ago", 5, 'warn');
        }
    }

    /** Returns the final URL after redirects, or null if the page could not be fetched. */
    private function contentChecks(string $url, string $host, string $regDomain, array $trusted): ?string
    {
        // SSRF guard – never fetch internal / private addresses
        $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : ($this->domainInfo['ips'][0] ?? gethostbyname($host));
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $this->add('content', 'fetch', 'Page content', 'Skipped (private or internal address)', 0, 'info');
            return null;
        }

        $body = '';
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_CONNECTTIMEOUT => FETCH_TIMEOUT,
            CURLOPT_TIMEOUT        => FETCH_TIMEOUT + 2,
            CURLOPT_SSL_VERIFYPEER => false, // we analyse, we don't trust
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS=> CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard/1.0',
            CURLOPT_WRITEFUNCTION  => function ($ch, $chunk) use (&$body) {
                $body .= $chunk;
                return strlen($body) > FETCH_MAX_BYTES ? 0 : strlen($chunk);
            },
        ]);
        curl_exec($ch);
        $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) ?: $url;
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status === 0) {
            $this->domainInfo['reachable'] = false;
            $this->add('host', 'reachable', 'Website reachable', 'The domain exists but no website answers – it cannot be opened in a browser', 25, 'danger');
            return null;
        }
        $this->domainInfo['reachable'] = true;
        $this->domainInfo['http_status'] = $status;
        if ($body === '') {
            $this->add('content', 'fetch', 'Page content', "Empty page (HTTP $status)", 3, 'warn');
            return null;
        }
        $this->add('content', 'fetch', 'Page content', "Downloaded (HTTP $status, " . number_format(strlen($body) / 1024, 1) . ' KB)', 0, 'info');

        $finalHost = strtolower(parse_url($finalUrl, PHP_URL_HOST) ?? $host);
        $finalReg = self::registrableDomain($finalHost);
        if ($finalReg !== $regDomain) {
            $this->add('content', 'redirect', 'Cross-domain redirect', "Redirected to $finalReg", 8, 'warn');
        }

        libxml_use_internal_errors(true);
        $dom = new DOMDocument();
        $dom->loadHTML('<?xml encoding="utf-8"?>' . $body, LIBXML_NOERROR | LIBXML_NOWARNING);
        libxml_clear_errors();

        // Password fields
        $hasPassword = false;
        foreach ($dom->getElementsByTagName('input') as $input) {
            if (strtolower($input->getAttribute('type')) === 'password') { $hasPassword = true; break; }
        }
        $hasPassword
            ? $this->add('content', 'password', 'Password field', 'Page asks for a password', 8, 'warn')
            : $this->add('content', 'password', 'Password field', 'No password field', 0, 'safe');

        // Forms posting elsewhere
        $externalForm = null;
        foreach ($dom->getElementsByTagName('form') as $form) {
            $action = trim($form->getAttribute('action'));
            if (preg_match('#^(https?:)?//#i', $action)) {
                $actionHost = strtolower(parse_url(str_starts_with($action, '//') ? "http:$action" : $action, PHP_URL_HOST) ?? '');
                if ($actionHost && self::registrableDomain($actionHost) !== $finalReg) { $externalForm = $actionHost; break; }
            } elseif (preg_match('#^mailto:#i', $action)) {
                $externalForm = 'an e-mail address'; break;
            }
        }
        $externalForm
            ? $this->add('content', 'form_action', 'Form destination', "Form submits data to $externalForm", 15, 'danger')
            : $this->add('content', 'form_action', 'Form destination', 'Forms stay on the same site', 0, 'safe');

        // Hidden iframes
        foreach ($dom->getElementsByTagName('iframe') as $iframe) {
            $style = strtolower(str_replace(' ', '', $iframe->getAttribute('style')));
            if ($iframe->getAttribute('width') === '0' || $iframe->getAttribute('height') === '0'
                || str_contains($style, 'display:none') || str_contains($style, 'visibility:hidden')) {
                $this->add('content', 'iframe', 'Hidden iframe', 'Invisible iframe embedded in page', 6, 'warn');
                break;
            }
        }

        // Meta refresh
        foreach ($dom->getElementsByTagName('meta') as $meta) {
            if (strtolower($meta->getAttribute('http-equiv')) === 'refresh'
                && preg_match('#url=\s*[\'"]?(https?://[^\'" ]+)#i', $meta->getAttribute('content'), $m)) {
                $refreshReg = self::registrableDomain(strtolower(parse_url($m[1], PHP_URL_HOST) ?? ''));
                if ($refreshReg && $refreshReg !== $finalReg) {
                    $this->add('content', 'meta_refresh', 'Meta refresh', "Auto-redirects to $refreshReg", 8, 'warn');
                }
                break;
            }
        }

        // Brand in <title> but domain isn't the brand's
        $title = trim($dom->getElementsByTagName('title')->item(0)?->textContent ?? '');
        if ($title !== '' && !$this->isTrusted($finalHost, $trusted)) {
            $tl = strtolower($title);
            foreach ($trusted as $t) {
                $brand = strtolower((string)$t['brand']);
                if (strlen($brand) >= 4 && preg_match('/\b' . preg_quote($brand, '/') . '\b/', $tl)) {
                    $this->add('content', 'title_brand', 'Page title', "Title claims \"" . mb_substr($title, 0, 60) . "\" but site is not {$t['domain']}", 15, 'danger');
                    break;
                }
            }
        }

        // External link ratio
        $total = 0; $external = 0;
        foreach ($dom->getElementsByTagName('a') as $a) {
            $href = trim($a->getAttribute('href'));
            if ($href === '' || str_starts_with($href, '#') || str_starts_with($href, 'javascript:')) { $total++; $external++; continue; }
            $total++;
            if (preg_match('#^https?://#i', $href)) {
                $h = strtolower(parse_url($href, PHP_URL_HOST) ?? '');
                if ($h && self::registrableDomain($h) !== $finalReg) $external++;
            }
        }
        if ($total >= 5 && $external / $total > 0.8) {
            $this->add('content', 'links', 'Link anchors', round($external / $total * 100) . '% of links are empty or point elsewhere', 6, 'warn');
        }

        return $finalUrl;
    }

    /* ---------------------------- helpers ----------------------------- */

    public static function normalizeUrl(string $input): string
    {
        $url = trim($input);
        $url = preg_replace('/\s+/', '', $url);
        if ($url === '') return '';
        if (!preg_match('#^[a-z][a-z0-9+.-]*://#i', $url)) {
            $url = 'http://' . $url;
        }
        return $url;
    }

    private static function authority(string $url): string
    {
        $noScheme = preg_replace('#^[a-z][a-z0-9+.-]*://#i', '', $url);
        return strtok($noScheme, '/?#') ?: '';
    }

    public static function registrableDomain(string $host): string
    {
        $labels = explode('.', $host);
        $n = count($labels);
        if ($n <= 2) return $host;
        $lastTwo = $labels[$n - 2] . '.' . $labels[$n - 1];
        $take = in_array($lastTwo, self::MULTI_SUFFIXES, true) ? 3 : 2;
        return implode('.', array_slice($labels, -$take));
    }

    private static function deHomoglyph(string $s): string
    {
        return strtr(str_replace(['rn', 'vv'], ['m', 'w'], strtolower($s)),
            ['0' => 'o', '1' => 'l', '3' => 'e', '4' => 'a', '5' => 's', '7' => 't', '8' => 'b', '@' => 'a', '$' => 's']);
    }

    private static function entropy(string $s): float
    {
        $len = strlen($s);
        if ($len === 0) return 0.0;
        $h = 0.0;
        foreach (count_chars($s, 1) as $count) {
            $p = $count / $len;
            $h -= $p * log($p, 2);
        }
        return $h;
    }
}
