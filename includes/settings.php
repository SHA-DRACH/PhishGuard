<?php
/**
 * System settings: admin-editable configuration stored in the `settings` table.
 * The schema below drives the admin form, validation, defaults and typed access via setting().
 */

function settings_schema(): array
{
    static $schema = null;
    if ($schema !== null) return $schema;

    $defaultPositions = "[Cybersecurity Analyst]\nInvestigate phishing reports assigned to you and submit a finding\nScan suspicious links received by staff and customers\nRecommend malicious domains for the blacklist\nEscalate confirmed incidents to the ICT Security Manager\n\n"
        . "[ICT Support Officer]\nHelp staff verify suspicious emails and links using PhishGuard\nInvestigate assigned reports from internal departments\nGuide users who may have entered credentials on a phishing page\n\n"
        . "[Customer Care Officer]\nScan links reported by customers before advising them\nReport fake LTC websites and SMS links to the security team\nShare phishing awareness tips with customers\n\n"
        . "[Billing & Finance Officer]\nVerify payment and billing links before opening them\nReport fake LTC billing or payment pages immediately\nNever share financial credentials through links or email\n\n"
        . "[General Staff]\nScan unfamiliar links before opening or entering any details\nReport suspicious websites, emails and SMS links\nComplete the phishing awareness quiz";

    return $schema = [
        'general' => ['label' => 'General', 'icon' => 'grid', 'intro' => 'Names, contact details and regional settings used across every page.', 'fields' => [
            'app_name'      => ['type' => 'text', 'label' => 'System name', 'default' => 'PhishGuard', 'max' => 40, 'required' => true, 'help' => 'Shown in the header, browser tab, footer and e-mails.'],
            'org_name'      => ['type' => 'text', 'label' => 'Organisation name', 'default' => 'Liberia Telecommunications Corporation', 'max' => 120, 'required' => true],
            'org_short'     => ['type' => 'text', 'label' => 'Organisation short name', 'default' => 'LTC', 'max' => 20, 'required' => true],
            'tagline'       => ['type' => 'text', 'label' => 'Tagline under the logo', 'default' => 'Phishing Detection', 'max' => 40],
            'support_email' => ['type' => 'email', 'label' => 'Support e-mail', 'default' => '', 'help' => 'Shown in the footer and on the report page. Leave empty to hide.'],
            'support_phone' => ['type' => 'text', 'label' => 'Support phone', 'default' => '', 'max' => 40],
            'footer_note'   => ['type' => 'text', 'label' => 'Footer safety note', 'default' => 'Never enter passwords, PINs or mobile-money codes on a site you did not type yourself.', 'max' => 200],
            'timezone'      => ['type' => 'select', 'label' => 'Time zone', 'default' => 'Africa/Monrovia', 'options' => 'timezones'],
        ]],
        'appearance' => ['label' => 'Appearance', 'icon' => 'theme', 'intro' => 'Logo, colours and default theme.', 'fields' => [
            'logo'          => ['type' => 'image', 'label' => 'Logo', 'default' => '', 'help' => 'PNG, JPG or WebP, max 1 MB, ideally square. Leave empty to keep the current logo.'],
            'accent_color'  => ['type' => 'color', 'label' => 'Accent colour', 'default' => '#38e1c6', 'help' => 'Used for buttons, links and highlights.'],
            'accent_color_2'=> ['type' => 'color', 'label' => 'Secondary colour', 'default' => '#4f8dff'],
            'default_theme' => ['type' => 'select', 'label' => 'Default theme', 'default' => 'dark', 'options' => ['dark' => 'Dark', 'light' => 'Light'], 'help' => 'Visitors can still switch with the theme button.'],
        ]],
        'content' => ['label' => 'Page content', 'icon' => 'list', 'intro' => 'Texts shown on the public pages.', 'fields' => [
            'home_eyebrow'  => ['type' => 'text', 'label' => 'Home – small heading', 'default' => 'Real-time phishing detection', 'max' => 60],
            'home_title'    => ['type' => 'text', 'label' => 'Home – main headline', 'default' => 'Check the link *before* you trust it.', 'max' => 90, 'help' => 'Wrap a word in *asterisks* to highlight it.'],
            'home_lead'     => ['type' => 'textarea', 'label' => 'Home – introduction', 'default' => 'Paste any website address. {app} inspects the URL, the domain, its security certificate and the page itself, then tells you in seconds whether it is safe to enter your details.', 'max' => 400, 'help' => '{app} is replaced by the system name.'],
            'home_card1_title' => ['type' => 'text', 'label' => 'Home card 1 – title', 'default' => '01 · URL analysis', 'max' => 60],
            'home_card1_text'  => ['type' => 'textarea', 'label' => 'Home card 1 – text', 'default' => 'Over 15 lexical checks: IP-address hosts, the "@" trick, look-alike domains (g00gle, paypa1), brand impersonation, risky TLDs, shorteners and more.', 'max' => 300],
            'home_card2_title' => ['type' => 'text', 'label' => 'Home card 2 – title', 'default' => '02 · Domain verification', 'max' => 60],
            'home_card2_text'  => ['type' => 'textarea', 'label' => 'Home card 2 – text', 'default' => 'Confirms the domain really exists, checks when it was registered and whether its website responds, and validates the SSL certificate.', 'max' => 300],
            'home_card3_title' => ['type' => 'text', 'label' => 'Home card 3 – title', 'default' => '03 · Page inspection', 'max' => 60],
            'home_card3_text'  => ['type' => 'textarea', 'label' => 'Home card 3 – text', 'default' => 'Looks for password forms that submit elsewhere, hidden iframes, fake brand titles and cross-domain redirects – before you type anything.', 'max' => 300],
            'awareness_title'  => ['type' => 'text', 'label' => 'Awareness – headline', 'default' => 'Spot a phishing link in 10 seconds', 'max' => 90],
            'awareness_intro'  => ['type' => 'textarea', 'label' => 'Awareness – introduction', 'default' => 'Phishing succeeds by exploiting trust and urgency. Learn the signs our detector looks for, and you\'ll catch most attacks yourself.', 'max' => 400],
            'report_intro'     => ['type' => 'textarea', 'label' => 'Report page – introduction', 'default' => 'Received a suspicious link by SMS, WhatsApp or email? Report it. Confirmed sites are blacklisted for every user.', 'max' => 400],
            'login_headline'   => ['type' => 'text', 'label' => 'Sign-in page – headline', 'default' => 'Stay one step ahead of phishing.', 'max' => 90],
            'login_text'       => ['type' => 'textarea', 'label' => 'Sign-in page – text', 'default' => 'A secure workspace for {org} staff and customers to verify links, report fraud and track threats.', 'max' => 300, 'help' => '{org} is replaced by the organisation short name.'],
        ]],
        'detection' => ['label' => 'Detection', 'icon' => 'shield', 'intro' => 'How the scanner scores and classifies websites.', 'fields' => [
            'threshold_suspicious' => ['type' => 'int', 'label' => 'Suspicious from score', 'default' => 25, 'min' => 1, 'max' => 99, 'help' => 'Scores at or above this are "suspicious".'],
            'threshold_phishing'   => ['type' => 'int', 'label' => 'Phishing from score', 'default' => 50, 'min' => 2, 'max' => 100, 'help' => 'Must be higher than the suspicious score.'],
            'domain_checks'  => ['type' => 'bool', 'label' => 'Verify domains on every scan', 'default' => true, 'help' => 'DNS existence, registration age and reachability. Turning this off lets non-existent domains pass as safe.'],
            'deep_default'   => ['type' => 'bool', 'label' => '"Deep scan" ticked by default', 'default' => true],
            'fetch_content'  => ['type' => 'bool', 'label' => 'Allow page-content analysis', 'default' => true, 'help' => 'Deep scans download the page HTML.'],
            'fetch_timeout'  => ['type' => 'int', 'label' => 'Network timeout (seconds)', 'default' => 6, 'min' => 2, 'max' => 30],
            'safe_browsing_key' => ['type' => 'secret', 'label' => 'Google Safe Browsing API key', 'default' => '', 'help' => 'Checks every scan against the list Chrome uses. Leave empty to disable; leave blank when saving to keep the current key.'],
            'keywords'       => ['type' => 'list', 'label' => 'Sensitive keywords', 'default' => "login\nlog-in\nsignin\nsign-in\nverify\nverification\nsecure\naccount\nupdate\nconfirm\nbanking\npassword\npasswd\nwallet\nsuspend\nunlock\nwebscr\nbilling\ninvoice\nrecover\nvalidate\nauthenticate\nbonus\nfree-gift\nlucky\nreward\nairtime\nmobilemoney\nmomo\nkyc", 'help' => 'One per line. Each one found in a URL adds risk points.'],
            'suspicious_tlds'=> ['type' => 'list', 'label' => 'Risky top-level domains', 'default' => "tk\nml\nga\ncf\ngq\nxyz\ntop\nzip\nmov\nclick\ncountry\nwork\nrest\nbuzz\nicu\ncam\nmonster\nquest\ncyou\nsbs\ncfd\nloan\nwin\nbid\nkim\nsupport", 'help' => 'One per line, without the dot.'],
            'shorteners'     => ['type' => 'list', 'label' => 'URL shortener domains', 'default' => "bit.ly\ntinyurl.com\ngoo.gl\nt.co\now.ly\nis.gd\nbuff.ly\ncutt.ly\nrebrand.ly\nshorturl.at\ntiny.cc\nrb.gy\nbl.ink\ns.id\nv.gd\nlnkd.in\nshorte.st\nadf.ly"],
        ]],
        'weights' => ['label' => 'Risk weights', 'icon' => 'chart', 'intro' => 'Risk points added by each warning sign. Set a feature to 0 to switch it off. Features with several levels (e.g. 1 or 2+ hyphens) scale proportionally.', 'fields' => [
            'weights' => ['type' => 'weights', 'label' => 'Feature weights', 'default' => ''],
        ]],
        'access' => ['label' => 'Access & security', 'icon' => 'users', 'intro' => 'Who can use the system and how accounts are protected.', 'fields' => [
            'allow_registration' => ['type' => 'bool', 'label' => 'Allow public registration', 'default' => true, 'help' => 'When off, only administrators can create accounts.'],
            'allow_guest_scan'   => ['type' => 'bool', 'label' => 'Allow scanning without signing in', 'default' => true],
            'allow_guest_report' => ['type' => 'bool', 'label' => 'Allow reports without signing in', 'default' => true],
            'password_min_length'=> ['type' => 'int', 'label' => 'Minimum password length', 'default' => 8, 'min' => 6, 'max' => 64],
            'login_max_attempts' => ['type' => 'int', 'label' => 'Failed sign-ins before lock', 'default' => 5, 'min' => 3, 'max' => 20],
            'login_lock_minutes' => ['type' => 'int', 'label' => 'Lock duration (minutes)', 'default' => 5, 'min' => 1, 'max' => 120],
            'scan_rate_limit'    => ['type' => 'int', 'label' => 'Max full scans per minute (per visitor)', 'default' => 20, 'min' => 1, 'max' => 500],
            'maintenance_mode'   => ['type' => 'bool', 'label' => 'Maintenance mode', 'default' => false, 'help' => 'Only administrators can use the site; everyone else sees the message below.'],
            'maintenance_message'=> ['type' => 'textarea', 'label' => 'Maintenance message', 'default' => 'PhishGuard is being updated and will be back shortly. Thank you for your patience.', 'max' => 300],
        ]],
        'staff' => ['label' => 'Staff positions', 'icon' => 'user', 'intro' => 'Positions offered when creating staff accounts, and the responsibilities pre-filled for each.', 'fields' => [
            'positions' => ['type' => 'positions', 'label' => 'Positions and responsibilities', 'default' => $defaultPositions,
                'help' => 'Write each position in [square brackets], followed by one responsibility per line. Leave a blank line between positions.'],
        ]],
    ];
}

/** Default risk points per feature id (primary level). Mirrors the detector. */
function weight_defaults(): array
{
    return [
        'ip_host' => ['IP address as host', 25], 'at_symbol' => ['"@" symbol in URL', 20], 'double_slash' => ['Double-slash redirect', 10],
        'length' => ['Very long URL', 8], 'hyphen' => ['Hyphens in domain (2+)', 10], 'subdomains' => ['Deep sub-domains (3+)', 12],
        'https' => ['No HTTPS', 12], 'tld' => ['Risky top-level domain', 10], 'shortener' => ['URL shortener', 15],
        'keywords' => ['Sensitive keywords (max)', 20], 'brand' => ['Brand impersonation', 25], 'typosquat' => ['Look-alike domain', 30],
        'punycode' => ['Punycode domain', 15], 'port' => ['Non-standard port', 8], 'digits' => ['Many digits in domain', 6],
        'entropy' => ['Random-looking domain', 6], 'encoding' => ['URL obfuscation', 5],
        'dns' => ['Domain does not exist', 40], 'dns_private' => ['Points to private IP', 15], 'registration' => ['Domain not registered', 30],
        'domain_age' => ['Brand-new domain (< 30 days)', 25], 'reachable' => ['Website unreachable', 25],
        'ssl' => ['Invalid SSL certificate', 15], 'cert_age' => ['Brand-new certificate', 5],
        'redirect' => ['Cross-domain redirect', 8], 'password' => ['Password field on page', 8], 'form_action' => ['Form posts elsewhere', 15],
        'iframe' => ['Hidden iframe', 6], 'meta_refresh' => ['Meta-refresh redirect', 8], 'title_brand' => ['Brand in page title', 15],
        'links' => ['Empty / external links', 6],
    ];
}

function settings_load(bool $refresh = false): array
{
    static $values = null;
    if ($values === null || $refresh) {
        $values = [];
        try {
            foreach (db()->query('SELECT name, value FROM settings') as $row) $values[$row['name']] = $row['value'];
        } catch (PDOException) { /* table missing before migration – use defaults */ }
    }
    return $values;
}

function setting_field(string $key): ?array
{
    foreach (settings_schema() as $group) {
        if (isset($group['fields'][$key])) return $group['fields'][$key];
    }
    return null;
}

/** Typed access to a setting, falling back to its default. */
function setting(string $key): mixed
{
    $field = setting_field($key);
    $values = settings_load();
    $raw = $values[$key] ?? null;
    $type = $field['type'] ?? 'text';
    if ($raw === null) return $field['default'] ?? null;
    return match ($type) {
        'int'  => (int)$raw,
        'bool' => $raw === '1',
        default => $raw,
    };
}

function setting_list(string $key): array
{
    return array_values(array_unique(array_filter(array_map(fn($l) => strtolower(trim($l)), preg_split('/\R/', (string)setting($key))))));
}

/** Parse the [Position] / duties text format. */
function parse_positions(string $text): array
{
    $out = [];
    $current = null;
    foreach (preg_split('/\R/', $text) as $line) {
        $line = trim($line);
        if ($line === '') continue;
        if (preg_match('/^\[(.+)\]$/', $line, $m)) {
            $current = trim($m[1]);
            $out[$current] = [];
        } elseif ($current !== null) {
            $out[$current][] = $line;
        }
    }
    return array_filter($out);
}

function setting_weights(): array
{
    $saved = json_decode((string)setting('weights'), true) ?: [];
    $out = [];
    foreach (weight_defaults() as $id => [$label, $default]) {
        $out[$id] = isset($saved[$id]) ? max(0, min(100, (int)$saved[$id])) : $default;
    }
    return $out;
}

function logo_url(): string
{
    $logo = (string)setting('logo');
    return $logo !== '' && is_file(__DIR__ . '/../' . $logo) ? url($logo) . '?v=' . filemtime(__DIR__ . '/../' . $logo) : url('assets/img/shield.svg');
}

/**
 * Validate and store one group of settings. Returns a list of error messages (empty on success).
 */
function settings_save(string $groupKey, array $input, array $files, int $userId): array
{
    $group = settings_schema()[$groupKey] ?? null;
    if (!$group) return ['Unknown settings section.'];
    $errors = [];
    $save = [];

    foreach ($group['fields'] as $key => $f) {
        $label = $f['label'];
        $value = $input[$key] ?? null;
        switch ($f['type']) {
            case 'bool':
                $save[$key] = !empty($value) ? '1' : '0';
                break;
            case 'int':
                if (!is_numeric($value) || (int)$value < $f['min'] || (int)$value > $f['max']) {
                    $errors[] = "$label must be a number between {$f['min']} and {$f['max']}.";
                } else {
                    $save[$key] = (string)(int)$value;
                }
                break;
            case 'email':
                $value = trim((string)$value);
                if ($value !== '' && !filter_var($value, FILTER_VALIDATE_EMAIL)) $errors[] = "$label is not a valid e-mail address.";
                else $save[$key] = $value;
                break;
            case 'color':
                $value = strtolower(trim((string)$value));
                if (!preg_match('/^#[0-9a-f]{6}$/', $value)) $errors[] = "$label must be a colour such as #38e1c6.";
                else $save[$key] = $value;
                break;
            case 'select':
                $options = $f['options'] === 'timezones' ? array_combine(DateTimeZone::listIdentifiers(), DateTimeZone::listIdentifiers()) : $f['options'];
                if (!isset($options[$value])) $errors[] = "Please choose a valid $label.";
                else $save[$key] = (string)$value;
                break;
            case 'secret':
                $value = trim((string)$value);
                if (!empty($input[$key . '_clear'])) $save[$key] = '';
                elseif ($value !== '') {
                    if (!preg_match('/^[A-Za-z0-9_\-]{20,100}$/', $value)) $errors[] = "$label does not look like a valid API key.";
                    else $save[$key] = $value;
                }
                break;
            case 'list':
                $lines = array_values(array_unique(array_filter(array_map(fn($l) => strtolower(trim($l)), preg_split('/\R/', (string)$value)))));
                $bad = array_filter($lines, fn($l) => !preg_match('/^[a-z0-9.\-]{1,60}$/', $l));
                if ($bad) $errors[] = "$label contains invalid entries: " . implode(', ', array_slice($bad, 0, 3)) . ' (letters, digits, dots and hyphens only).';
                elseif (!$lines) $errors[] = "$label cannot be empty.";
                else $save[$key] = implode("\n", $lines);
                break;
            case 'weights':
                $w = [];
                foreach (weight_defaults() as $id => $_) {
                    $v = $input['w'][$id] ?? null;
                    if (!is_numeric($v) || (int)$v < 0 || (int)$v > 100) { $errors[] = 'Every weight must be between 0 and 100.'; break; }
                    $w[$id] = (int)$v;
                }
                if (!$errors) $save[$key] = json_encode($w);
                break;
            case 'positions':
                $parsed = parse_positions((string)$value);
                if (!$parsed) $errors[] = 'Add at least one position in [square brackets] with responsibilities below it.';
                else $save[$key] = trim(str_replace("\r", '', (string)$value));
                break;
            case 'image':
                if (!empty($input[$key . '_remove'])) {
                    $save[$key] = '';
                    break;
                }
                $file = $files[$key] ?? null;
                if (!$file || ($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) break;
                if ($file['error'] !== UPLOAD_ERR_OK || $file['size'] > 1048576) { $errors[] = "$label must be an image under 1 MB."; break; }
                $info = @getimagesize($file['tmp_name']);
                $ext = ['image/png' => 'png', 'image/jpeg' => 'jpg', 'image/webp' => 'webp'][$info['mime'] ?? ''] ?? null;
                if (!$ext) { $errors[] = "$label must be a PNG, JPG or WebP image."; break; }
                $dir = __DIR__ . '/../assets/uploads';
                if (!is_dir($dir)) mkdir($dir, 0755, true);
                foreach (glob("$dir/logo.*") ?: [] as $old) @unlink($old);
                if (!move_uploaded_file($file['tmp_name'], "$dir/logo.$ext")) { $errors[] = 'The logo could not be saved.'; break; }
                $save[$key] = "assets/uploads/logo.$ext";
                break;
            default: // text, textarea
                $value = trim((string)$value);
                if (!empty($f['required']) && $value === '') $errors[] = "$label is required.";
                elseif (mb_strlen($value) > ($f['max'] ?? 500)) $errors[] = "$label must be at most {$f['max']} characters.";
                else $save[$key] = $value;
        }
    }

    if ($groupKey === 'detection' && isset($save['threshold_suspicious'], $save['threshold_phishing'])
        && (int)$save['threshold_phishing'] <= (int)$save['threshold_suspicious']) {
        $errors[] = 'The phishing score must be higher than the suspicious score.';
    }
    if ($errors) return array_values(array_unique($errors));

    $stmt = db()->prepare('REPLACE INTO settings (name, value, updated_by, updated_at) VALUES (?, ?, ?, NOW())');
    foreach ($save as $k => $v) $stmt->execute([$k, $v, $userId]);
    settings_load(true);
    return [];
}

function settings_reset(string $groupKey): void
{
    $keys = array_keys(settings_schema()[$groupKey]['fields'] ?? []);
    if (!$keys) return;
    if ($groupKey === 'appearance') foreach (glob(__DIR__ . '/../assets/uploads/logo.*') ?: [] as $old) @unlink($old);
    $in = implode(',', array_fill(0, count($keys), '?'));
    db()->prepare("DELETE FROM settings WHERE name IN ($in)")->execute($keys);
    settings_load(true);
}

/** Replace {app} / {org} placeholders in admin-editable texts. */
function setting_text(string $key): string
{
    return strtr((string)setting($key), ['{app}' => APP_NAME, '{org}' => ORG_SHORT, '{organisation}' => ORG_NAME]);
}

/** Block non-admins while maintenance mode is on (login and admin pages stay reachable). */
function enforce_maintenance(): void
{
    if (PHP_SAPI === 'cli' || !setting('maintenance_mode')) return;
    $path = ltrim(substr($_SERVER['SCRIPT_NAME'] ?? '', strlen(BASE_URL)), '/');
    if (in_array($path, ['login.php', 'logout.php'], true) || str_starts_with($path, 'admin/') || is_admin()) return;
    http_response_code(503);
    header('Retry-After: 3600');
    if (str_starts_with($path, 'api/')) json_response(['ok' => false, 'error' => setting('maintenance_message')], 503);
    $pageTitle = 'Maintenance';
    $formHtml = '<h1>Under maintenance</h1><p class="muted">' . e(setting('maintenance_message')) . '</p>'
              . '<p class="small muted">Administrators can still <a href="' . url('login.php') . '">sign in</a>.</p>';
    require __DIR__ . '/auth_layout.php';
    exit;
}
