<?php
/**
 * Plugin Name: ClamAV Upload Security
 * Plugin Version: 1.0
 * Description: Synchronous ClamAV upload scanning with role enforcement, automatic lockout, logging, and dashboard visibility.
 */

if (!defined('ABSPATH')) exit;

define('CLAMAV_VERSION', '1.0');
define('CLAMAV_LOG', '/var/log/apache2/wp-upload-clamav-scan.log');
define('CLAMAV_FORCE_ALLOW_FILE', WP_CONTENT_DIR . '/mu-plugins/force-allow-uploads.txt');

/* ============================================================
 * ROLE & LOCKOUT ENFORCEMENT
 * ============================================================ */

add_filter('wp_handle_upload_prefilter', function ($file) {

    $user = wp_get_current_user();
    $username = $user->user_login ?: 'unknown';

    // Role enforcement
    if (!array_intersect(['administrator', 'editor'], (array) $user->roles)) {
        $file['error'] = 'Upload blocked: your user role is not permitted to upload files.';
        return $file;
    }

    // Lockout enforcement
    $stats = get_option('clamav_stats', []);
    if (!file_exists(CLAMAV_FORCE_ALLOW_FILE) && !empty($stats['lockout_until'])) {
        if (time() < $stats['lockout_until']) {
            $file['error'] = 'Uploads are temporarily disabled due to repeated virus detections.';
            return $file;
        }
    }

    return $file;
});

/* ============================================================
 * CLAMAV SCANNING
 * ============================================================ */

add_filter('wp_handle_upload_prefilter', function ($file) {

    $tmp = $file['tmp_name'];
    $name = $file['name'];
    $user = wp_get_current_user();
    $username = $user->user_login ?: 'unknown';

    if (!file_exists($tmp)) return $file;

    $start = microtime(true);
    exec("clamscan --no-summary " . escapeshellarg($tmp), $out, $ret);
    $duration_ms = round((microtime(true) - $start) * 1000, 2);
    $duration_sec = (int) round($duration_ms / 1000);

    $now = time();
    $today = date('Y-m-d');

    $stats = get_option('clamav_stats', [
        'today' => $today,
        'today_clean' => 0,
        'today_infected' => 0,
        'all_clean' => 0,
        'all_infected' => 0,
        'recent' => [],
        'infections' => [],
        'lockout_until' => null,
        'total_scans' => 0,
        'total_scan_time' => 0
    ]);

    if ($stats['today'] !== $today) {
        $stats['today'] = $today;
        $stats['today_clean'] = 0;
        $stats['today_infected'] = 0;
    }

    $status = ($ret === 1) ? 'INFECTED' : 'CLEAN';

    if ($status === 'INFECTED') {
        unlink($tmp);

        $stats['today_infected']++;
        $stats['all_infected']++;
        $stats['infections'][] = $now;

        // Keep only last 30 minutes
        $stats['infections'] = array_filter(
            $stats['infections'],
            fn($t) => $t > ($now - 1800)
        );

        // Trigger lockout
        if (count($stats['infections']) > 3) {
            $stats['lockout_until'] = $now + (3 * 3600);
        }

        wp_mail(
            get_option('admin_email'),
            'ClamAV Alert: Infected Upload Deleted',
            "File: $name\nUser: $username\nScan time: {$duration_sec}s"
        );

        $file['error'] = 'Upload blocked: a virus was detected and the file was deleted.';
    } else {
        $stats['today_clean']++;
        $stats['all_clean']++;
    }

    $stats['total_scans']++;
    $stats['total_scan_time'] += $duration_sec;

    $stats['recent'][] = [
        'file' => $name,
        'user' => $username,
        'status' => $status,
        'time' => $duration_sec,
        'timestamp' => $now
    ];

    if (count($stats['recent']) > 20) {
        $stats['recent'] = array_slice($stats['recent'], -20);
    }

    update_option('clamav_stats', $stats);

    // Logging (ms)
    $line = sprintf(
        "[%s] [%s] %s [%s] %s – %.2f ms\n",
        date('Y-m-d H:i:s.u'),
        parse_url(get_site_url(), PHP_URL_HOST),
        $name,
        $username,
        $status,
        $duration_ms
    );

    @file_put_contents(CLAMAV_LOG, $line, FILE_APPEND | LOCK_EX);

    return $file;
});

/* ============================================================
 * DASHBOARD WIDGET 1 — SCAN DETAILS
 * ============================================================ */

add_action('wp_dashboard_setup', function () {
    wp_add_dashboard_widget(
        'clamav_details',
        'Clam AV Plugin Scan Details (ver ' . CLAMAV_VERSION . ')',
        function () {
            $s = get_option('clamav_stats', []);
            $avg = $s['total_scans'] ? round($s['total_scan_time'] / $s['total_scans']) : 0;

            echo "<p><strong>Today's uploads:</strong> Clean {$s['today_clean']} // Infected {$s['today_infected']}</p>";
            echo "<p><strong>All time uploads:</strong> Clean {$s['all_clean']} // Infected {$s['all_infected']}</p>";
            echo "<p><strong>Average scan time:</strong> {$avg} seconds</p>";

            if (!empty($s['recent'])) {
                echo "<h4>Recent uploads</h4><ul>";
                foreach (array_reverse($s['recent']) as $r) {
                    $c = ($r['status'] === 'INFECTED') ? '#b30000' : '#007c2f';
                    echo "<li style='color:$c'>{$r['file']} [{$r['user']}] {$r['status']} – {$r['time']}s</li>";
                }
                echo "</ul>";
            }
        }
    );
});

/* ============================================================
 * DASHBOARD WIDGET 2 — SECURITY EVENTS WITH OVERRIDE CHECK
 * ============================================================ */

add_action('wp_dashboard_setup', function () {
    wp_add_dashboard_widget(
        'clamav_events',
        'ClamAV Security Events',
        function () {
            $s = get_option('clamav_stats', []);

            // Display override warning if override file exists
            if (file_exists(CLAMAV_FORCE_ALLOW_FILE)) {
                echo "<p style='color:#b30000'><strong>Upload blocking disabled as: " . CLAMAV_FORCE_ALLOW_FILE . " is present</strong></p>";
            }

            if (empty($s['infections'])) {
                echo "<p style='color:#007c2f'><strong>No recent infections detected.</strong></p>";
                return;
            }

            $last = max($s['infections']);
            $age = time() - $last;

            if ($age < 3600) {
                $sev = 'HIGH';
                $col = '#b30000';
            } elseif ($age < 86400) {
                $sev = 'MODERATE';
                $col = '#b36b00';
            } else {
                $sev = 'LOW';
                $col = '#007c2f';
            }

            echo "<p><strong>Security status:</strong> <span style='color:$col'><strong>$sev</strong></span></p>";
            echo "<p><strong>Infections in last 30 minutes:</strong> " . count($s['infections']) . "</p>";

            if (!empty($s['lockout_until']) && time() < $s['lockout_until']) {
                echo "<p style='color:#b30000'><strong>Uploads locked until:</strong> " .
                     date('Y-m-d H:i:s', $s['lockout_until']) . "</p>";
            }

            echo "<hr><p><strong>Recommended actions:</strong></p>
                  <ul>
                    <li>Review user roles</li>
                    <li>Check compromised credentials</li>
                    <li>Review firewall rules</li>
                    <li>Disable uploads if attack persists</li>
                  </ul>";
        }
    );
});
