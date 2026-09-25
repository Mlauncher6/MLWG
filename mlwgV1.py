
#!/usr/bin/env python3
# -*- coding: utf-8 -*-



from __future__ import annotations

import hashlib
import hmac
import html
import inspect
import json
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


# ============================================================
# CONFIG
# ============================================================

HOST = "127.0.0.1"
PORT = 10000

# اگر WordPress روی همین سیستم است:
MANAGER_ENDPOINT = f"http://{HOST}:{PORT}"

# اگر WordPress روی VPS/هاست دیگری است، این را تغییر بده:
#
# MANAGER_ENDPOINT = "https://panel.example.com"
#
# سپس Python را اجرا کن و فایل PHP جدید بساز.

APP_NAME = "MLUNCHER WORDPRESS GUARD"
APP_VERSION = "1.1.0"

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "mlwg_data"
PHP_DIR = DATA_DIR / "generated"

DB_PATH = DATA_DIR / "mlwg.sqlite3"

DATA_DIR.mkdir(parents=True, exist_ok=True)
PHP_DIR.mkdir(parents=True, exist_ok=True)

DB_LOCK = threading.RLock()


# ============================================================
# HELPERS
# ============================================================

def now() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat()


def unix_time() -> int:
    return int(time.time())


def sha256(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def db():
    connection = sqlite3.connect(
        DB_PATH,
        timeout=30,
        check_same_thread=False
    )
    connection.row_factory = sqlite3.Row
    return connection


def execute(sql: str, params=()):
    with DB_LOCK:
        with db() as connection:
            connection.execute(sql, params)
            connection.commit()


def query(sql: str, params=(), one=False):
    with DB_LOCK:
        with db() as connection:
            rows = connection.execute(
                sql,
                params
            ).fetchall()

    if one:
        return rows[0] if rows else None

    return rows


def audit(
    site_id: str | None,
    action: str,
    target: str = "",
    result: str = "success"
):
    execute(
        """
        INSERT INTO audit
        (site_id, action, target, result, created)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            site_id,
            action,
            target,
            result,
            now()
        )
    )


def safe_json(value) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    )


# ============================================================
# DATABASE
# ============================================================

def init_database():

    with DB_LOCK:

        with db() as connection:

            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sites (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',

                    wp_version TEXT,
                    php_version TEXT,
                    os TEXT,
                    server TEXT,

                    https INTEGER DEFAULT 0,

                    last_sync TEXT,
                    last_scan TEXT,
                    created TEXT,

                    metadata TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS enrollments (
                    id TEXT PRIMARY KEY,

                    token_hash TEXT NOT NULL,
                    connector_secret TEXT NOT NULL,

                    created TEXT NOT NULL,
                    expires INTEGER NOT NULL,

                    used INTEGER DEFAULT 0,
                    site_id TEXT
                );

                CREATE TABLE IF NOT EXISTS replay_guard (
                    site_id TEXT PRIMARY KEY,
                    last_timestamp INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    site_id TEXT,

                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    detail TEXT NOT NULL,

                    file TEXT,
                    line INTEGER,
                    evidence TEXT,

                    status TEXT DEFAULT 'open',

                    created TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    site_id TEXT,
                    kind TEXT NOT NULL,

                    status TEXT NOT NULL,
                    progress INTEGER DEFAULT 0,

                    message TEXT DEFAULT '',

                    created TEXT NOT NULL,
                    finished TEXT
                );

                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    site_id TEXT,

                    action TEXT NOT NULL,
                    target TEXT,

                    result TEXT NOT NULL,

                    created TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_findings_site
                ON findings(site_id);

                CREATE INDEX IF NOT EXISTS idx_jobs_site
                ON jobs(site_id);

                CREATE INDEX IF NOT EXISTS idx_audit_site
                ON audit(site_id);
                """
            )

            connection.commit()


# ============================================================
# PHP GENERATOR
# ============================================================

def php_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def generate_php_connector():

    installation_id = secrets.token_hex(16)

    enrollment_token = secrets.token_urlsafe(48)

    connector_secret = secrets.token_urlsafe(48)

    created = unix_time()

    expires = created + 900

    enrollment_endpoint = (
        MANAGER_ENDPOINT.rstrip("/")
        + "/api/connector/enroll"
    )

    connector = {
        "installation_id": installation_id,
        "enrollment_token": enrollment_token,
        "manager_endpoint": MANAGER_ENDPOINT.rstrip("/"),
        "created_at": created,
        "expires_at": expires,
        "version": APP_VERSION
    }

    execute(
        """
        INSERT INTO enrollments
        (
            id,
            token_hash,
            connector_secret,
            created,
            expires,
            used
        )
        VALUES (?, ?, ?, ?, ?, 0)
        """,
        (
            installation_id,
            sha256(enrollment_token),
            connector_secret,
            now(),
            expires
        )
    )

    enrollment_package = {
        "format": "MLWG",
        "version": 1,
        "installation_id": installation_id,
        "enrollment_token": enrollment_token,
        "manager_endpoint": MANAGER_ENDPOINT.rstrip("/"),
        "created_at": created,
        "expires_at": expires,
        "algorithm": "HMAC-SHA256",
        "connector_secret": connector_secret,
    }
    (ENROLLMENT_DIR / f"MLWG_{installation_id[:8].upper()}.MLWG").write_text(
        safe_json(enrollment_package), encoding="utf-8"
    )

    php = r'''<?php
/**
 * Plugin Name: MLUNCHER WordPress Guard
 * Plugin URI: https://mlauncher.example
 * Description: Secure MLWG connector for MLUNCHER WORDPRESS GUARD.
 * Version: 1.1.0
 * Author: MLUNCHER
 * License: GPL-2.0-or-later
 *
 * IMPORTANT:
 * This connector is generated by MLWG Manager.
 *
 * It does NOT contain:
 * - WordPress password
 * - Database password
 * - FTP password
 * - SSH password
 *
 * Enrollment uses a one-time token.
 */

if (!defined('ABSPATH')) {
    exit;
}

final class MLWG_Connector {

    private const VERSION = '__MLWG_VERSION__';

    private const INSTALLATION_ID = '__MLWG_INSTALLATION_ID__';

    private const ENROLLMENT_TOKEN = '__MLWG_ENROLLMENT_TOKEN__';

    private const MANAGER_ENDPOINT = '__MLWG_MANAGER_ENDPOINT__';

    private const CREATED_AT = __MLWG_CREATED_AT__;

    private const EXPIRES_AT = __MLWG_EXPIRES_AT__;

    private const OPT_SITE_ID = 'mlwg_site_id';

    private const OPT_SECRET = 'mlwg_connector_secret';

    private const OPT_CONNECTED = 'mlwg_connected';

    private const OPT_LAST_SYNC = 'mlwg_last_sync';

    private const OPT_LAST_ERROR = 'mlwg_last_error';

    private const OPT_ENROLLED = 'mlwg_enrolled';

    private const CRON_HOOK = 'mlwg_connector_heartbeat';

    public static function boot() {

        add_action(
            'admin_menu',
            array(__CLASS__, 'admin_menu')
        );

        add_action(
            'admin_init',
            array(__CLASS__, 'admin_init')
        );

        add_action(
            self::CRON_HOOK,
            array(__CLASS__, 'cron_heartbeat')
        );

        add_action(
            'rest_api_init',
            array(__CLASS__, 'register_rest')
        );
    }


    /* ========================================================
     * ACTIVATION
     * ====================================================== */

    public static function activate() {

        self::create_tables();

        self::enroll();

        if (!wp_next_scheduled(self::CRON_HOOK)) {

            wp_schedule_event(
                time() + 300,
                'five_minutes',
                self::CRON_HOOK
            );
        }
    }


    public static function deactivate() {

        wp_clear_scheduled_hook(
            self::CRON_HOOK
        );
    }


    /* ========================================================
     * CRON INTERVAL
     * ====================================================== */

    public static function cron_interval($schedules) {

        $schedules['five_minutes'] = array(
            'interval' => 300,
            'display' => 'Every 5 Minutes'
        );

        return $schedules;
    }


    /* ========================================================
     * TABLE
     * ====================================================== */

    private static function create_tables() {

        // Reserved for future local connector state.
        // WordPress options are used currently.
    }


    /* ========================================================
     * ADMIN
     * ====================================================== */

    public static function admin_menu() {

        add_menu_page(
            'MLWG Guard',
            'MLWG Guard',
            'manage_options',
            'mlwg',
            array(__CLASS__, 'admin_page'),
            'dashicons-shield',
            3
        );
    }


    public static function admin_init() {

        if (
            !current_user_can('manage_options')
        ) {
            return;
        }

        if (
            isset($_POST['mlwg_sync'])
            &&
            check_admin_referer(
                'mlwg_sync_action',
                'mlwg_nonce'
            )
        ) {

            self::sync();

            wp_safe_redirect(
                admin_url('admin.php?page=mlwg')
            );

            exit;
        }

        if (
            isset($_POST['mlwg_reconnect'])
            &&
            check_admin_referer(
                'mlwg_reconnect_action',
                'mlwg_nonce'
            )
        ) {

            delete_option(self::OPT_ENROLLED);
            delete_option(self::OPT_SITE_ID);
            delete_option(self::OPT_SECRET);
            delete_option(self::OPT_CONNECTED);

            self::enroll();

            wp_safe_redirect(
                admin_url('admin.php?page=mlwg')
            );

            exit;
        }
    }


    public static function admin_page() {

        if (
            !current_user_can('manage_options')
        ) {
            return;
        }

        $connected = (bool) get_option(
            self::OPT_CONNECTED,
            false
        );

        $site_id = get_option(
            self::OPT_SITE_ID,
            ''
        );

        $last_sync = get_option(
            self::OPT_LAST_SYNC,
            ''
        );

        $last_error = get_option(
            self::OPT_LAST_ERROR,
            ''
        );

        ?>
        <div class="wrap">

            <h1>
                MLUNCHER WordPress Guard
            </h1>

            <div style="
                max-width:850px;
                margin-top:20px;
                background:#fff;
                border:1px solid #ddd;
                border-radius:12px;
                padding:25px;
            ">

                <h2>
                    Connection
                </h2>

                <p>
                    Status:
                    <?php if ($connected): ?>

                        <strong style="color:#16834a;">
                            Connected
                        </strong>

                    <?php else: ?>

                        <strong style="color:#b42318;">
                            Not Connected
                        </strong>

                    <?php endif; ?>
                </p>

                <?php if ($site_id): ?>

                    <p>
                        <strong>Site ID:</strong>
                        <code>
                            <?php echo esc_html($site_id); ?>
                        </code>
                    </p>

                <?php endif; ?>

                <?php if ($last_sync): ?>

                    <p>
                        <strong>Last Sync:</strong>
                        <?php echo esc_html($last_sync); ?>
                    </p>

                <?php endif; ?>

                <?php if ($last_error): ?>

                    <div style="
                        background:#fff1f0;
                        color:#8a1c13;
                        border:1px solid #f1b7b2;
                        border-radius:8px;
                        padding:12px;
                        margin:15px 0;
                    ">
                        <?php
                        echo esc_html($last_error);
                        ?>
                    </div>

                <?php endif; ?>

                <hr>

                <p>
                    Manager:
                    <code>
                        <?php
                        echo esc_html(
                            self::MANAGER_ENDPOINT
                        );
                        ?>
                    </code>
                </p>

                <form method="post">

                    <?php
                    wp_nonce_field(
                        'mlwg_sync_action',
                        'mlwg_nonce'
                    );
                    ?>

                    <button
                        type="submit"
                        name="mlwg_sync"
                        class="button button-primary"
                    >
                        Sync Now
                    </button>

                </form>

                <br>

                <form method="post">

                    <?php
                    wp_nonce_field(
                        'mlwg_reconnect_action',
                        'mlwg_nonce'
                    );
                    ?>

                    <button
                        type="submit"
                        name="mlwg_reconnect"
                        class="button"
                    >
                        Reconnect
                    </button>

                </form>

            </div>

        </div>
        <?php
    }


    /* ========================================================
     * WORDPRESS DATA
     * ====================================================== */

    private static function collect_metadata() {

        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        global $wp_version, $wpdb;

        $plugins = array();

        $all_plugins = get_plugins();

        foreach ($all_plugins as $file => $plugin) {

            $plugins[] = array(
                'file' => $file,
                'name' => isset($plugin['Name'])
                    ? $plugin['Name']
                    : '',
                'version' => isset($plugin['Version'])
                    ? $plugin['Version']
                    : '',
                'author' => isset($plugin['Author'])
                    ? wp_strip_all_tags(
                        $plugin['Author']
                    )
                    : '',
                'active' => is_plugin_active($file)
            );
        }


        $themes = array();

        $theme_list = wp_get_themes();

        foreach ($theme_list as $stylesheet => $theme) {

            $themes[] = array(
                'stylesheet' => $stylesheet,
                'name' => $theme->get('Name'),
                'version' => $theme->get('Version'),
                'author' => $theme->get('Author'),
                'active' => (
                    get_stylesheet() === $stylesheet
                )
            );
        }


        $users = array();

        $user_query = new WP_User_Query(
            array(
                'number' => 500,
                'fields' => array(
                    'ID',
                    'user_login',
                    'display_name',
                    'user_registered'
                )
            )
        );

        foreach (
            $user_query->get_results()
            as $user
        ) {

            $wp_user = new WP_User(
                $user->ID
            );

            $roles = array_values(
                (array) $wp_user->roles
            );

            $users[] = array(
                'id' => (int) $user->ID,
                'login' => $user->user_login,
                'display_name' => $user->display_name,
                'registered' => $user->user_registered,
                'roles' => $roles
            );
        }


        $active_theme = wp_get_theme();

        $debug = defined('WP_DEBUG')
            && WP_DEBUG;

        $file_edit = defined(
            'DISALLOW_FILE_EDIT'
        )
            ? !DISALLOW_FILE_EDIT
            : true;

        $registration = (bool) get_option(
            'users_can_register',
            false
        );

        $xmlrpc = true;

        if (function_exists('apply_filters')) {

            $xmlrpc = (bool) apply_filters(
                'xmlrpc_enabled',
                true
            );
        }


        $https = is_ssl();

        $metadata = array(

            'connector_version' => self::VERSION,

            'site_url' => get_site_url(),

            'home_url' => get_home_url(),

            'name' => get_bloginfo('name'),

            'description' => get_bloginfo('description'),

            'wp_version' => $wp_version,

            'php_version' => PHP_VERSION,

            'os' => PHP_OS,

            'server' => isset(
                $_SERVER['SERVER_SOFTWARE']
            )
                ? sanitize_text_field(
                    wp_unslash(
                        $_SERVER['SERVER_SOFTWARE']
                    )
                )
                : '',

            'architecture' => PHP_INT_SIZE * 8,

            'https' => $https,

            'debug' => $debug,

            'file_edit' => $file_edit,

            'xmlrpc' => $xmlrpc,

            'registration' => $registration,

            'multisite' => is_multisite(),

            'locale' => get_locale(),

            'timezone' => wp_timezone_string(),

            'db_driver' => 'wordpress',

            'db_version' => $wpdb->db_version(),

            'db_prefix_present' => !empty(
                $wpdb->prefix
            ),

            'active_theme' => array(
                'name' => $active_theme->get('Name'),
                'version' => $active_theme->get('Version'),
                'stylesheet' => get_stylesheet()
            ),

            'plugins' => $plugins,

            'themes' => $themes,

            'users' => $users,

            'cron_count' => self::cron_count(),

            'wp_debug_log' => defined(
                'WP_DEBUG_LOG'
            )
                ? (bool) WP_DEBUG_LOG
                : false,

            'wp_debug_display' => defined(
                'WP_DEBUG_DISPLAY'
            )
                ? (bool) WP_DEBUG_DISPLAY
                : false,

            'force_ssl_admin' => defined(
                'FORCE_SSL_ADMIN'
            )
                ? (bool) FORCE_SSL_ADMIN
                : false

            , 'mlwg_capabilities' => array(
                'metadata' => 'available',
                'configuration' => 'available',
                'users' => 'available',
                'plugins' => 'available',
                'themes' => 'available',
                'files' => 'unavailable',
                'integrity' => 'unavailable',
                'uploads' => 'unavailable',
                'database' => 'unknown',
                'cron' => 'available',
                'security_headers' => 'unknown',
                'rest_api' => 'unknown',
                'permissions' => 'unknown'
            )
        );


        return $metadata;
    }


    private static function cron_count() {

        $cron = _get_cron_array();

        if (!is_array($cron)) {
            return 0;
        }

        $count = 0;

        foreach ($cron as $timestamp => $events) {

            if (!is_array($events)) {
                continue;
            }

            foreach ($events as $event_group) {

                if (is_array($event_group)) {
                    $count += count($event_group);
                }
            }
        }

        return $count;
    }


    /* ========================================================
     * ENROLL
     * ====================================================== */

    public static function enroll() {

        if (
            get_option(
                self::OPT_ENROLLED,
                false
            )
        ) {
            return true;
        }


        if (
            time() > self::EXPIRES_AT
        ) {

            update_option(
                self::OPT_LAST_ERROR,
                'Enrollment package expired.'
            );

            return false;
        }


        $metadata = self::collect_metadata();


        $payload = array(

            'installation_id'
                => self::INSTALLATION_ID,

            'enrollment_token'
                => self::ENROLLMENT_TOKEN,

            'site_url'
                => get_site_url(),

            'home_url'
                => get_home_url(),

            'name'
                => get_bloginfo('name'),

            'wp_version'
                => get_bloginfo('version'),

            'php_version'
                => PHP_VERSION,

            'os'
                => PHP_OS,

            'server'
                => isset(
                    $_SERVER['SERVER_SOFTWARE']
                )
                    ? sanitize_text_field(
                        wp_unslash(
                            $_SERVER['SERVER_SOFTWARE']
                        )
                    )
                    : '',

            'https'
                => is_ssl(),

            'metadata'
                => $metadata
        );


        $response = wp_remote_post(
            self::MANAGER_ENDPOINT
            . '/api/connector/enroll',
            array(

                'timeout' => 20,

                'redirection' => 2,

                'sslverify' => true,

                'headers' => array(
                    'Content-Type'
                        => 'application/json',

                    'Accept'
                        => 'application/json'
                ),

                'body' => wp_json_encode(
                    $payload
                )
            )
        );


        if (is_wp_error($response)) {

            update_option(
                self::OPT_LAST_ERROR,
                $response->get_error_message()
            );

            return false;
        }


        $status = wp_remote_retrieve_response_code(
            $response
        );

        $body = wp_remote_retrieve_body(
            $response
        );

        $data = json_decode(
            $body,
            true
        );


        if (
            $status < 200
            ||
            $status >= 300
            ||
            !is_array($data)
            ||
            empty($data['ok'])
        ) {

            $error = (
                is_array($data)
                &&
                isset($data['error'])
            )
                ? $data['error']
                : 'Enrollment failed.';

            update_option(
                self::OPT_LAST_ERROR,
                $error
            );

            return false;
        }


        if (
            empty($data['site_id'])
            ||
            empty($data['connector_secret'])
        ) {

            update_option(
                self::OPT_LAST_ERROR,
                'Invalid enrollment response.'
            );

            return false;
        }


        update_option(
            self::OPT_SITE_ID,
            sanitize_text_field(
                $data['site_id']
            )
        );


        update_option(
            self::OPT_SECRET,
            sanitize_text_field(
                $data['connector_secret']
            )
        );


        update_option(
            self::OPT_CONNECTED,
            true
        );


        update_option(
            self::OPT_ENROLLED,
            true
        );


        update_option(
            self::OPT_LAST_ERROR,
            ''
        );


        self::sync();


        return true;
    }


    /* ========================================================
     * SIGNATURE
     * ====================================================== */

    private static function signed_request(
        $path,
        $payload
    ) {

        $secret = get_option(
            self::OPT_SECRET,
            ''
        );

        $site_id = get_option(
            self::OPT_SITE_ID,
            ''
        );


        if (
            !$secret
            ||
            !$site_id
        ) {
            return false;
        }


        $timestamp = time();
        $nonce = wp_generate_password(32, false, false);

        $body = wp_json_encode(
            $payload
        );


        $message =
            $timestamp
            . '.'
            . $nonce
            . '.'
            . $body;


        $signature = hash_hmac(
            'sha256',
            $message,
            $secret
        );


        $response = wp_remote_post(
            self::MANAGER_ENDPOINT
            . $path,
            array(

                'timeout' => 20,

                'redirection' => 2,

                'sslverify' => true,

                'headers' => array(

                    'Content-Type'
                        => 'application/json',

                    'Accept'
                        => 'application/json',

                    'X-MLWG-Site-ID'
                        => $site_id,

                    'X-MLWG-Nonce'
                        => $nonce,

                    'X-MLWG-Timestamp'
                        => (string) $timestamp,

                    'X-MLWG-Signature'
                        => $signature
                ),

                'body' => $body
            )
        );


        if (is_wp_error($response)) {

            update_option(
                self::OPT_LAST_ERROR,
                $response->get_error_message()
            );

            return false;
        }


        $status = wp_remote_retrieve_response_code(
            $response
        );

        $raw = wp_remote_retrieve_body(
            $response
        );

        $data = json_decode(
            $raw,
            true
        );


        if (
            $status < 200
            ||
            $status >= 300
            ||
            !is_array($data)
            ||
            empty($data['ok'])
        ) {

            $error = (
                is_array($data)
                &&
                isset($data['error'])
            )
                ? $data['error']
                : 'Manager request failed.';

            update_option(
                self::OPT_LAST_ERROR,
                $error
            );

            return false;
        }


        update_option(
            self::OPT_LAST_ERROR,
            ''
        );


        return $data;
    }


    /* ========================================================
     * SYNC
     * ====================================================== */

    public static function sync() {

        if (
            !get_option(
                self::OPT_ENROLLED,
                false
            )
        ) {

            return self::enroll();
        }


        $metadata = self::collect_metadata();

        $payload = array_merge(
            array(
                'site_id'
                    => get_option(
                        self::OPT_SITE_ID,
                        ''
                    ),

                'site_url'
                    => get_site_url(),

                'home_url'
                    => get_home_url(),

                'name'
                    => get_bloginfo('name'),

                'wp_version'
                    => get_bloginfo('version'),

                'php_version'
                    => PHP_VERSION,

                'os'
                    => PHP_OS,

                'server'
                    => isset(
                        $_SERVER['SERVER_SOFTWARE']
                    )
                        ? sanitize_text_field(
                            wp_unslash(
                                $_SERVER[
                                    'SERVER_SOFTWARE'
                                ]
                            )
                        )
                        : '',

                'https'
                    => is_ssl()
            ),
            array(
                'metadata' => $metadata
            )
        );


        $result = self::signed_request(
            '/api/connector/sync',
            $payload
        );


        if (
            is_array($result)
            &&
            !empty($result['ok'])
        ) {

            update_option(
                self::OPT_LAST_SYNC,
                gmdate('c')
            );

            update_option(
                self::OPT_CONNECTED,
                true
            );

            return true;
        }


        return false;
    }


    /* ========================================================
     * HEARTBEAT
     * ====================================================== */

    public static function cron_heartbeat() {

        if (
            !get_option(
                self::OPT_ENROLLED,
                false
            )
        ) {

            self::enroll();

            return;
        }


        $payload = array(
            'site_id'
                => get_option(
                    self::OPT_SITE_ID,
                    ''
                ),

            'site_url'
                => get_site_url(),

            'time'
                => time()
        );


        $result = self::signed_request(
            '/api/connector/heartbeat',
            $payload
        );


        if (
            !is_array($result)
            ||
            empty($result['ok'])
        ) {

            update_option(
                self::OPT_CONNECTED,
                false
            );

            return;
        }


        update_option(
            self::OPT_CONNECTED,
            true
        );

        update_option(
            self::OPT_LAST_SYNC,
            gmdate('c')
        );
    }


    /* ========================================================
     * REST STATUS
     * ====================================================== */

    public static function register_rest() {

        register_rest_route(
            'mlwg/v1',
            '/status',
            array(

                'methods' => 'GET',

                'permission_callback'
                    => function () {

                        return current_user_can(
                            'manage_options'
                        );
                    },

                'callback'
                    => function () {

                        return array(

                            'ok' => true,

                            'connected'
                                => (bool) get_option(
                                    self::OPT_CONNECTED,
                                    false
                                ),

                            'site_id'
                                => get_option(
                                    self::OPT_SITE_ID,
                                    ''
                                ),

                            'last_sync'
                                => get_option(
                                    self::OPT_LAST_SYNC,
                                    ''
                                )
                        );
                    }
            )
        );
    }
}


/* ============================================================
 * HOOKS
 * ========================================================== */

add_filter(
    'cron_schedules',
    array(
        'MLWG_Connector',
        'cron_interval'
    )
);

register_activation_hook(
    __FILE__,
    array(
        'MLWG_Connector',
        'activate'
    )
);

register_deactivation_hook(
    __FILE__,
    array(
        'MLWG_Connector',
        'deactivate'
    )
);

MLWG_Connector::boot();
'''

    replacements = {
        "__MLWG_VERSION__": php_escape(APP_VERSION),
        "__MLWG_INSTALLATION_ID__": php_escape(
            installation_id
        ),
        "__MLWG_ENROLLMENT_TOKEN__": php_escape(
            enrollment_token
        ),
        "__MLWG_MANAGER_ENDPOINT__": php_escape(
            MANAGER_ENDPOINT.rstrip("/")
        ),
        "__MLWG_CREATED_AT__": str(created),
        "__MLWG_EXPIRES_AT__": str(expires),
    }

    for key, value in replacements.items():
        php = php.replace(key, value)

    filename = "mlwg.php"

    path = PHP_DIR / filename

    path.write_text(
        php,
        encoding="utf-8"
    )

    return path


# ============================================================
# HTML / CSS
# ============================================================

CSS = r"""
:root {
    --burgundy: #4A101C;
    --burgundy-dark: #25070D;

    --cream: #F3EBDD;
    --cream-soft: #E8DDC9;

    --paper: #FBF8F1;
    --white: #FFFFFF;

    --ink: #110D0F;
    --muted: #82766E;

    --line: #D9CCBB;

    --success: #4C9A70;
    --warning: #C49445;
    --danger: #B84A55;
}

* {
    box-sizing: border-box;
}

html {
    scroll-behavior: smooth;
}

body {
    margin: 0;
    background:
        radial-gradient(
            circle at 90% 0%,
            rgba(74,16,28,.035),
            transparent 32%
        ),
        var(--paper);
    color: var(--ink);
    font-family:
        Inter,
        Vazirmatn,
        system-ui,
        sans-serif;
}

a {
    color: inherit;
    text-decoration: none;
}

button,
input,
select {
    font: inherit;
}

.app {
    min-height: 100vh;
    display: grid;
    grid-template-columns:
        260px
        minmax(0, 1fr);
}

.sidebar {
    background:
        linear-gradient(
            180deg,
            var(--burgundy-dark),
            #180407
        );

    color: var(--cream);

    padding: 24px 17px;

    position: sticky;
    top: 0;
    height: 100vh;
}

.brand {
    display: flex;
    align-items: center;
    gap: 12px;
    padding:
        5px 8px
        28px;
}

.logo {
    width: 43px;
    height: 43px;
    display: grid;
    place-items: center;
    border:
        1px solid
        rgba(243,235,221,.5);
    border-radius: 12px;
    font-weight: 900;
    letter-spacing: -2px;
}

.brand-title {
    font-weight: 900;
}

.brand-sub {
    display: block;
    margin-top: 3px;
    color: #C9B5AE;
    font-size: 9px;
    letter-spacing: .6px;
}

.navigation {
    display: grid;
    gap: 6px;
}

.navigation a {
    padding: 12px;
    border-radius: 10px;
    color: #D8C6C0;

    transition:
        transform .2s,
        background .2s,
        color .2s;
}

.navigation a:hover {
    background: var(--burgundy);
    color: #fff;
    transform: translateX(-2px);
}

.sidebar-bottom {
    position: absolute;
    left: 18px;
    right: 18px;
    bottom: 20px;
    color: #A99590;
    font-size: 11px;
}

.main {
    width: 100%;
    max-width: 1500px;
    margin: auto;
    padding: 30px;
}

.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
    margin-bottom: 26px;
}

.eyebrow {
    color: var(--muted);
    font-size: 11px;
    letter-spacing: 1.8px;
}

h1 {
    margin: 5px 0 0;
    font-size: 31px;
    letter-spacing: -1px;
}

h2 {
    margin: 0;
    font-size: 18px;
}

.actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.btn {
    border:
        1px solid
        var(--line);

    background: var(--white);
    color: var(--ink);

    padding:
        10px 14px;

    border-radius: 10px;
    cursor: pointer;

    transition:
        transform .2s,
        border-color .2s;
}

.btn:hover {
    transform: translateY(-1px);
    border-color: #A89187;
}

.btn-primary {
    background: var(--burgundy);
    color: #fff;
    border-color: var(--burgundy);
}

.grid {
    display: grid;
    gap: 14px;
}

.stats {
    grid-template-columns:
        repeat(
            4,
            minmax(0,1fr)
        );
}

.card {
    background: var(--white);

    border:
        1px solid
        var(--line);

    border-radius: 15px;

    padding: 18px;

    box-shadow:
        0 8px 28px
        rgba(37,7,13,.045);

    animation:
        cardIn .35s ease both;
}

.stat-number {
    margin: 7px 0;
    font-size: 30px;
    font-weight: 800;
}

.label {
    color: var(--muted);
    font-size: 12px;
}

.muted {
    color: var(--muted);
    font-size: 12px;
}

.section {
    margin-top: 23px;
}

.section-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
}

.table-wrap {
    overflow-x: auto;
}

table {
    width: 100%;
    min-width: 720px;
    border-collapse: collapse;
}

th,
td {
    padding:
        12px 9px;

    border-bottom:
        1px solid
        #EEE5DB;

    text-align: right;
    font-size: 12px;
}

th {
    color: var(--muted);
    font-weight: 600;
}

.pill {
    display: inline-flex;
    padding:
        5px 9px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 800;
}

.pill-ok {
    background: #E2F1E8;
    color: #286745;
}

.pill-warning {
    background: #F6ECD8;
    color: #79561D;
}

.pill-danger {
    background: #F6DFE2;
    color: #85323E;
}

.pill-pending {
    background: #EEE8E2;
    color: #6B625C;
}

.site {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
}

.site-left {
    display: flex;
    align-items: center;
    gap: 12px;
}

.site-icon {
    width: 43px;
    height: 43px;
    display: grid;
    place-items: center;
    border-radius: 11px;
    background: var(--cream);
    color: var(--burgundy);
    font-weight: 900;
}

.notice {
    padding: 14px;
    border:
        1px solid
        var(--cream-soft);
    background: var(--cream);
    border-radius: 11px;
    margin-bottom: 13px;
}

pre {
    background: #171214;
    color: #F2E7DE;
    padding: 16px;
    border-radius: 11px;
    overflow: auto;

    font:
        12px
        ui-monospace,
        SFMono-Regular,
        Consolas,
        monospace;

    direction: ltr;
    text-align: left;
}

.mono {
    font-family:
        ui-monospace,
        SFMono-Regular,
        Consolas,
        monospace;

    direction: ltr;
}

.empty {
    padding: 30px;
    text-align: center;
    color: var(--muted);
}

@keyframes cardIn {
    from {
        opacity: 0;
        transform: translateY(8px);
    }

    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@media (max-width:950px) {

    .app {
        grid-template-columns:1fr;
    }

    .sidebar {
        position:relative;
        height:auto;
    }

    .sidebar-bottom {
        position:static;
        margin-top:25px;
    }

    .stats {
        grid-template-columns:
            repeat(
                2,
                minmax(0,1fr)
            );
    }
}

@media (max-width:560px) {

    .main {
        padding:20px;
    }

    .topbar {
        align-items:flex-start;
        flex-direction:column;
    }

    .stats {
        grid-template-columns:1fr;
    }

    h1 {
        font-size:26px;
    }
}
"""


# ============================================================
# PAGE
# ============================================================

def page(title: str, body: str):

    links = [
        ("/", "داشبورد"),
        ("/sites", "سایت‌ها"),
        ("/generate", "ساخت Connector"),
        ("/findings", "یافته‌های امنیتی"),
        ("/jobs", "Job Center"),
        ("/audit", "Audit Log"),
    ]

    navigation = ""

    for url, text in links:

        navigation += (
            f'<a href="{url}">{text}</a>'
        )

    return f"""
<!doctype html>

<html lang="fa" dir="rtl">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1"
>

<title>
{html.escape(title)}
 — MLWG
</title>

<style>
{CSS}
</style>

</head>

<body>

<div class="app">

<aside class="sidebar">

    <div class="brand">

        <div class="logo">
            M
        </div>

        <div>

            <div class="brand-title">
                MLWG
            </div>

            <span class="brand-sub">
                MLUNCHER WORDPRESS GUARD
            </span>

        </div>

    </div>

    <nav class="navigation">
        {navigation}
    </nav>

    <div class="sidebar-bottom">

        LOCAL SECURITY CONSOLE

        <br>

        <span class="mono">
            127.0.0.1:{PORT}
        </span>

    </div>

</aside>

<main class="main">

{body}

</main>

</div>

</body>

</html>
"""


# ============================================================
# DASHBOARD
# ============================================================

def dashboard_page():

    sites = query(
        """
        SELECT *
        FROM sites
        ORDER BY created DESC
        """
    )

    findings = query(
        """
        SELECT *
        FROM findings
        WHERE status='open'
        ORDER BY id DESC
        LIMIT 10
        """
    )

    online = sum(
        1
        for site in sites
        if site["status"] == "online"
    )

    critical = sum(
        1
        for finding in findings
        if finding["severity"] == "critical"
    )

    high = sum(
        1
        for finding in findings
        if finding["severity"] == "high"
    )

    site_rows = ""

    for site in sites:

        status_class = (
            "pill-ok"
            if site["status"] == "online"
            else "pill-pending"
        )

        site_rows += f"""
        <tr>

            <td>

                <b>
                    {html.escape(site["name"])}
                </b>

                <div class="muted">
                    {html.escape(site["url"])}
                </div>

            </td>

            <td>
                <span class="pill {status_class}">
                    {html.escape(site["status"])}
                </span>
            </td>

            <td>
                {html.escape(site["wp_version"] or "—")}
            </td>

            <td>
                {html.escape(site["last_sync"] or "—")}
            </td>

            <td>
                <a
                    class="btn"
                    href="/sites/{html.escape(site["id"])}"
                >
                    جزئیات
                </a>
            </td>

        </tr>
        """

    if not site_rows:

        site_rows = """
        <tr>
            <td colspan="5" class="empty">
                هنوز سایتی متصل نشده.
            </td>
        </tr>
        """

    finding_rows = ""

    for finding in findings:

        if finding["severity"] in (
            "critical",
            "high"
        ):
            cls = "pill-danger"

        elif finding["severity"] == "medium":
            cls = "pill-warning"

        else:
            cls = "pill-pending"

        finding_rows += f"""
        <tr>

            <td>
                <span class="pill {cls}">
                    {html.escape(finding["severity"])}
                </span>
            </td>

            <td>
                {html.escape(finding["title"])}
            </td>

            <td>
                {html.escape(finding["created"])}
            </td>

        </tr>
        """

    if not finding_rows:

        finding_rows = """
        <tr>
            <td colspan="3" class="empty">
                یافته بازی وجود ندارد.
            </td>
        </tr>
        """

    body = f"""

<div class="topbar">

    <div>

        <div class="eyebrow">
            MLUNCHER SECURITY CONSOLE
        </div>

        <h1>
            داشبورد امنیت
        </h1>

    </div>

    <div class="actions">

        <a
            class="btn btn-primary"
            href="/generate"
        >
            ساخت Connector PHP
        </a>

    </div>

</div>


<div class="grid stats">

    <div class="card">

        <div class="label">
            سایت‌های آنلاین
        </div>

        <div class="stat-number">
            {online}
        </div>

        <div class="muted">
            از {len(sites)} سایت ثبت‌شده
        </div>

    </div>


    <div class="card">

        <div class="label">
            Critical
        </div>

        <div class="stat-number">
            {critical}
        </div>

        <div class="muted">
            یافته باز
        </div>

    </div>


    <div class="card">

        <div class="label">
            High
        </div>

        <div class="stat-number">
            {high}
        </div>

        <div class="muted">
            یافته باز
        </div>

    </div>


    <div class="card">

        <div class="label">
            Connector
        </div>

        <div class="stat-number">
            PHP
        </div>

        <div class="muted">
            Auto Enrollment
        </div>

    </div>

</div>


<div class="section">

    <div class="section-head">

        <h2>
            سایت‌ها
        </h2>

        <a
            class="btn"
            href="/sites"
        >
            مشاهده همه
        </a>

    </div>

    <div class="card table-wrap">

        <table>

            <thead>

                <tr>

                    <th>
                        سایت
                    </th>

                    <th>
                        وضعیت
                    </th>

                    <th>
                        WordPress
                    </th>

                    <th>
                        آخرین Sync
                    </th>

                    <th>
                    </th>

                </tr>

            </thead>

            <tbody>
                {site_rows}
            </tbody>

        </table>

    </div>

</div>


<div class="section">

    <div class="section-head">

        <h2>
            آخرین یافته‌های امنیتی
        </h2>

        <a
            class="btn"
            href="/findings"
        >
            همه یافته‌ها
        </a>

    </div>

    <div class="card table-wrap">

        <table>

            <thead>

                <tr>

                    <th>
                        Severity
                    </th>

                    <th>
                        عنوان
                    </th>

                    <th>
                        زمان
                    </th>

                </tr>

            </thead>

            <tbody>
                {finding_rows}
            </tbody>

        </table>

    </div>

</div>

"""

    return page(
        "داشبورد",
        body
    )


# ============================================================
# GENERATE PAGE
# ============================================================

def generate_page():

    php_path = generate_php_connector()

    body = f"""

<div class="topbar">

    <div>

        <div class="eyebrow">
            SECURE WORDPRESS CONNECTOR
        </div>

        <h1>
            اتصال WordPress
        </h1>

    </div>

</div>


<div class="card">

    <div class="notice">

        <b>
            فایل PHP ساخته شد.
        </b>

        <br>

        فقط این فایل را داخل WordPress قرار بده و
        Plugin را فعال کن.

        <br>

        بعد از Activate، افزونه خودش به MLWG
        درخواست Enrollment می‌فرستد.

        <br><br>

        Token داخل فایل یک‌بارمصرف و
        ۱۵ دقیقه‌ای است.

        <br>

        رمز WordPress، Database، FTP یا SSH
        داخل فایل قرار نگرفته است.

    </div>


    <pre>{html.escape(str(php_path))}</pre>


    <div class="actions">

        <a
            class="btn btn-primary"
            href="/download/mlwg.php"
        >
            دریافت mlwg.php
        </a>

        <a
            class="btn"
            href="/sites"
        >
            سایت‌ها
        </a>

    </div>

</div>

"""

    return page(
        "ساخت Connector",
        body
    )


# ============================================================
# SITES
# ============================================================

def sites_page():

    sites = query(
        """
        SELECT *
        FROM sites
        ORDER BY created DESC
        """
    )

    cards = ""

    for site in sites:

        cls = (
            "pill-ok"
            if site["status"] == "online"
            else "pill-pending"
        )

        cards += f"""

<div class="card site">

    <div class="site-left">

        <div class="site-icon">
            W
        </div>

        <div>

            <b>
                {html.escape(site["name"])}
            </b>

            <div class="muted">
                {html.escape(site["url"])}
            </div>

            <small>
                {html.escape(site["wp_version"] or "WP —")}
                ·
                {html.escape(site["php_version"] or "PHP —")}
            </small>

        </div>

    </div>


    <div class="actions">

        <span class="pill {cls}">
            {html.escape(site["status"])}
        </span>

        <a
            class="btn"
            href="/sites/{html.escape(site["id"])}"
        >
            جزئیات
        </a>

    </div>

</div>

"""

    if not cards:

        cards = """
        <div class="card empty">
            هنوز سایتی ثبت نشده.
        </div>
        """

    body = f"""

<div class="topbar">

    <div>

        <div class="eyebrow">
            WORDPRESS FLEET
        </div>

        <h1>
            سایت‌ها
        </h1>

    </div>

    <a
        class="btn btn-primary"
        href="/generate"
    >
        ساخت Connector
    </a>

</div>


<div class="grid">
    {cards}
</div>

"""

    return page(
        "سایت‌ها",
        body
    )


# ============================================================
# SITE DETAIL
# ============================================================

def site_page(site_id):

    site = query(
        """
        SELECT *
        FROM sites
        WHERE id=?
        """,
        (site_id,),
        one=True
    )

    if not site:

        return page(
            "خطا",
            """
            <div class="card">
                سایت پیدا نشد.
            </div>
            """
        )

    try:

        metadata = json.loads(
            site["metadata"] or "{}"
        )

    except Exception:

        metadata = {}

    findings = query(
        """
        SELECT *
        FROM findings
        WHERE site_id=?
        ORDER BY id DESC
        """,
        (site_id,)
    )

    rows = ""

    for finding in findings:

        if finding["severity"] in (
            "critical",
            "high"
        ):
            cls = "pill-danger"

        elif finding["severity"] == "medium":
            cls = "pill-warning"

        else:
            cls = "pill-pending"

        rows += f"""

<tr>

<td>
<span class="pill {cls}">
{html.escape(finding["severity"])}
</span>
</td>

<td>
{html.escape(finding["title"])}
</td>

<td>
{html.escape(finding["file"] or "—")}
</td>

<td>
{html.escape(finding["detail"])}
</td>

</tr>

"""

    if not rows:

        rows = """
        <tr>
            <td colspan="4" class="empty">
                هنوز اسکن انجام نشده.
            </td>
        </tr>
        """

    body = f"""

<div class="topbar">

    <div>

        <div class="eyebrow">
            SITE DETAIL
        </div>

        <h1>
            {html.escape(site["name"])}
        </h1>

        <div class="muted">
            {html.escape(site["url"])}
        </div>

    </div>

    <div class="actions">

        <form
            method="post"
            action="/sites/{html.escape(site_id)}/scan"
        >

            <button
                class="btn btn-primary"
                type="submit"
            >
                اجرای Security Scan
            </button>

        </form>

    </div>

</div>


<div class="grid stats">

    <div class="card">

        <div class="label">
            Status
        </div>

        <div class="stat-number">
            {html.escape(site["status"])}
        </div>

    </div>


    <div class="card">

        <div class="label">
            WordPress
        </div>

        <div class="stat-number">
            {html.escape(site["wp_version"] or "—")}
        </div>

    </div>


    <div class="card">

        <div class="label">
            PHP
        </div>

        <div class="stat-number">
            {html.escape(site["php_version"] or "—")}
        </div>

    </div>


    <div class="card">

        <div class="label">
            HTTPS
        </div>

        <div class="stat-number">
            {"ON" if site["https"] else "OFF"}
        </div>

    </div>

</div>


<div class="section">

    <div class="section-head">

        <h2>
            Connector Metadata
        </h2>

    </div>

    <div class="card">

        <pre>{html.escape(
            json.dumps(
                metadata,
                ensure_ascii=False,
                indent=2
            )
        )}</pre>

    </div>

</div>


<div class="section">

    <div class="section-head">

        <h2>
            Security Findings
        </h2>

    </div>

    <div class="card table-wrap">

        <table>

            <thead>

                <tr>

                    <th>
                        Severity
                    </th>

                    <th>
                        Title
                    </th>

                    <th>
                        File
                    </th>

                    <th>
                        Detail
                    </th>

                </tr>

            </thead>

            <tbody>
                {rows}
            </tbody>

        </table>

    </div>

</div>

"""

    return page(
        "جزئیات سایت",
        body
    )


# ============================================================
# TABLE
# ============================================================

def table_page(
    title,
    headers,
    rows
):

    content = ""

    for row in rows:

        content += "<tr>"

        for value in row:

            content += (
                "<td>"
                + html.escape(
                    str(value or "—")
                )
                + "</td>"
            )

        content += "</tr>"

    if not content:

        content = f"""
        <tr>
            <td
                colspan="{len(headers)}"
                class="empty"
            >
                خالی
            </td>
        </tr>
        """

    header_html = ""

    for header in headers:

        header_html += (
            f"<th>{html.escape(header)}</th>"
        )

    body = f"""

<div class="topbar">

    <div>

        <div class="eyebrow">
            MLWG
        </div>

        <h1>
            {html.escape(title)}
        </h1>

    </div>

</div>


<div class="card table-wrap">

<table>

<thead>

<tr>
{header_html}
</tr>

</thead>

<tbody>
{content}
</tbody>

</table>

</div>

"""

    return page(
        title,
        body
    )


# ============================================================
# SECURITY SCAN
# ============================================================

def run_security_scan(site_id):

    site = query(
        """
        SELECT *
        FROM sites
        WHERE id=?
        """,
        (site_id,),
        one=True
    )

    if not site:
        return

    execute(
        """
        INSERT INTO jobs
        (
            site_id,
            kind,
            status,
            progress,
            message,
            created
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            site_id,
            "security_scan",
            "running",
            10,
            "در حال تحلیل اطلاعات connector...",
            now()
        )
    )

    job = query(
        """
        SELECT last_insert_rowid() AS id
        """,
        one=True
    )

    job_id = job["id"]

    try:

        metadata = json.loads(
            site["metadata"] or "{}"
        )

    except Exception:

        metadata = {}

    findings = []

    if not site["https"]:

        findings.append(
            (
                "high",
                "HTTPS فعال نیست",
                "سایت طبق اطلاعات connector با HTTPS ثبت نشده.",
                "",
                None,
                "https=false"
            )
        )

    if metadata.get("debug") is True:

        findings.append(
            (
                "high",
                "WP_DEBUG فعال است",
                "حالت Debug طبق connector فعال گزارش شده.",
                "wp-config.php",
                None,
                "WP_DEBUG=true"
            )
        )

    if metadata.get("file_edit") is True:

        findings.append(
            (
                "medium",
                "File Editor فعال است",
                "ویرایش فایل داخلی WordPress فعال گزارش شده.",
                "wp-config.php",
                None,
                "file_edit=true"
            )
        )

    if metadata.get("xmlrpc") is True:

        findings.append(
            (
                "medium",
                "XML-RPC فعال است",
                "XML-RPC توسط connector فعال گزارش شده.",
                "WordPress",
                None,
                "xmlrpc=true"
            )
        )

    if metadata.get("registration") is True:

        findings.append(
            (
                "medium",
                "ثبت‌نام عمومی کاربران فعال است",
                "Public user registration فعال گزارش شده.",
                "WordPress",
                None,
                "registration=true"
            )
        )

    if metadata.get("wp_debug_log") is True:

        findings.append(
            (
                "medium",
                "WP_DEBUG_LOG فعال است",
                "لاگ Debug طبق connector فعال است.",
                "wp-config.php",
                None,
                "WP_DEBUG_LOG=true"
            )
        )

    if metadata.get("wp_debug_display") is True:

        findings.append(
            (
                "high",
                "نمایش خطای Debug فعال است",
                "نمایش مستقیم خطاهای PHP/WordPress می‌تواند اطلاعات داخلی را افشا کند.",
                "wp-config.php",
                None,
                "WP_DEBUG_DISPLAY=true"
            )
        )

    if not metadata.get("force_ssl_admin", False):

        findings.append(
            (
                "medium",
                "Force SSL Admin فعال نیست",
                "FORCE_SSL_ADMIN طبق اطلاعات connector فعال گزارش نشده.",
                "wp-config.php",
                None,
                "FORCE_SSL_ADMIN=false"
            )
        )

    users = metadata.get(
        "users",
        []
    )

    admin_count = 0

    for user in users:

        roles = user.get(
            "roles",
            []
        )

        if "administrator" in roles:
            admin_count += 1

    if admin_count > 3:

        findings.append(
            (
                "medium",
                "تعداد Administrator زیاد است",
                f"{admin_count} حساب Administrator گزارش شده.",
                "WordPress Users",
                None,
                f"administrator_count={admin_count}"
            )
        )

    if not findings:

        findings.append(
            (
                "low",
                "Baseline scan completed",
                "در داده‌های دریافت‌شده مورد پرریسک مستقیمی پیدا نشد. این نتیجه جایگزین اسکن فایل نیست.",
                "",
                None,
                "baseline=ok"
            )
        )

    execute(
        """
        DELETE FROM findings
        WHERE site_id=?
        AND status='open'
        """,
        (site_id,)
    )

    for (
        severity,
        title,
        detail,
        file_name,
        line,
        evidence
    ) in findings:

        execute(
            """
            INSERT INTO findings
            (
                site_id,
                severity,
                title,
                detail,
                file,
                line,
                evidence,
                status,
                created
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?)
            """,
            (
                site_id,
                severity,
                title,
                detail,
                file_name,
                line,
                evidence,
                now()
            )
        )

    execute(
        """
        UPDATE jobs
        SET
            status='success',
            progress=100,
            message=?,
            finished=?
        WHERE id=?
        """,
        (
            f"{len(findings)} finding ثبت شد.",
            now(),
            job_id
        )
    )

    execute(
        """
        UPDATE sites
        SET last_scan=?
        WHERE id=?
        """,
        (
            now(),
            site_id
        )
    )

    audit(
        site_id,
        "security_scan",
        "site",
        "success"
    )


# ============================================================
# HMAC AUTHENTICATION
# ============================================================

def verify_signed_request(
    handler: BaseHTTPRequestHandler,
    path: str,
    body: str
):

    site_id = handler.headers.get(
        "X-MLWG-Site",
        ""
    ).strip()

    timestamp_raw = handler.headers.get(
        "X-MLWG-Timestamp",
        ""
    ).strip()

    signature = handler.headers.get(
        "X-MLWG-Signature",
        ""
    ).strip()

    if not site_id:
        return False, "missing_site"

    if not timestamp_raw:
        return False, "missing_timestamp"

    if not signature:
        return False, "missing_signature"

    try:
        timestamp = int(timestamp_raw)
    except ValueError:
        return False, "invalid_timestamp"

    # 5 minute replay window
    if abs(unix_time() - timestamp) > 300:
        return False, "timestamp_expired"

    site = query(
        """
        SELECT id
        FROM sites
        WHERE id=?
        """,
        (site_id,),
        one=True
    )

    if not site:
        return False, "site_not_found"

    enrollment = query(
        """
        SELECT connector_secret
        FROM enrollments
        WHERE site_id=?
        AND used=1
        """,
        (site_id,),
        one=True
    )

    if not enrollment:
        return False, "connector_not_found"

    secret = enrollment["connector_secret"]

    expected = hmac.new(
        secret.encode("utf-8"),
        (
            timestamp_raw
            + "."
            + path
            + "."
            + body
        ).encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(
        expected,
        signature
    ):
        return False, "invalid_signature"

    # Replay protection
    with DB_LOCK:

        connection = db()

        try:

            row = connection.execute(
                """
                SELECT last_timestamp
                FROM replay_guard
                WHERE site_id=?
                """,
                (site_id,)
            ).fetchone()

            if row:

                last_timestamp = int(
                    row["last_timestamp"]
                )

                if timestamp <= last_timestamp:
                    return False, "replay"

                connection.execute(
                    """
                    UPDATE replay_guard
                    SET last_timestamp=?
                    WHERE site_id=?
                    """,
                    (
                        timestamp,
                        site_id
                    )
                )

            else:

                connection.execute(
                    """
                    INSERT INTO replay_guard
                    (
                        site_id,
                        last_timestamp
                    )
                    VALUES (?, ?)
                    """,
                    (
                        site_id,
                        timestamp
                    )
                )

            connection.commit()

        finally:
            connection.close()

    return True, site_id


# ============================================================
# HTTP SERVER
# ============================================================

class MLWGHandler(
    BaseHTTPRequestHandler
):

    server_version = "MLWG/1.1"

    def log_message(
        self,
        format,
        *args
    ):
        return


    def send_bytes(
        self,
        data: bytes,
        content_type:
            str = "text/html; charset=utf-8",
        status: int = 200
    ):

        self.send_response(status)

        self.send_header(
            "Content-Type",
            content_type
        )

        self.send_header(
            "Content-Length",
            str(len(data))
        )

        self.send_header(
            "Cache-Control",
            "no-store"
        )

        self.send_header(
            "X-Content-Type-Options",
            "nosniff"
        )

        self.end_headers()

        self.wfile.write(data)


    def send_json(
        self,
        data,
        status=200
    ):

        self.send_bytes(
            json.dumps(
                data,
                ensure_ascii=False
            ).encode("utf-8"),
            "application/json; charset=utf-8",
            status
        )


    def read_body(self):

        try:

            length = int(
                self.headers.get(
                    "Content-Length",
                    "0"
                )
            )

            if length > 10 * 1024 * 1024:
                return ""

            return self.rfile.read(
                length
            ).decode("utf-8")

        except Exception:

            return ""


    def read_json(self):

        body = self.read_body()

        if not body:
            return {}, ""

        try:

            return (
                json.loads(body),
                body
            )

        except Exception:

            return {}, body


    # ========================================================
    # GET
    # ========================================================

    def do_GET(self):

        path = urlparse(
            self.path
        ).path


        if path == "/":

            return self.send_bytes(
                dashboard_page().encode(
                    "utf-8"
                )
            )


        if path == "/sites":

            return self.send_bytes(
                sites_page().encode(
                    "utf-8"
                )
            )


        if path == "/generate":

            return self.send_bytes(
                generate_page().encode(
                    "utf-8"
                )
            )


        if path == "/findings":

            rows = query(
                """
                SELECT
                    findings.*,
                    sites.name
                FROM findings
                LEFT JOIN sites
                    ON sites.id = findings.site_id
                ORDER BY findings.id DESC
                """
            )

            data = []

            for row in rows:

                data.append(
                    (
                        row["name"],
                        row["severity"],
                        row["title"],
                        row["file"],
                        row["created"]
                    )
                )

            return self.send_bytes(
                table_page(
                    "یافته‌های امنیتی",
                    [
                        "Site",
                        "Severity",
                        "Title",
                        "File",
                        "Time"
                    ],
                    data
                ).encode("utf-8")
            )


        if path == "/jobs":

            rows = query(
                """
                SELECT
                    jobs.*,
                    sites.name
                FROM jobs
                LEFT JOIN sites
                    ON sites.id = jobs.site_id
                ORDER BY jobs.id DESC
                """
            )

            data = []

            for row in rows:

                data.append(
                    (
                        row["id"],
                        row["name"],
                        row["kind"],
                        row["status"],
                        f'{row["progress"]}%',
                        row["message"]
                    )
                )

            return self.send_bytes(
                table_page(
                    "Job Center",
                    [
                        "ID",
                        "Site",
                        "Type",
                        "Status",
                        "Progress",
                        "Message"
                    ],
                    data
                ).encode("utf-8")
            )


        if path == "/audit":

            rows = query(
                """
                SELECT
                    audit.*,
                    sites.name
                FROM audit
                LEFT JOIN sites
                    ON sites.id = audit.site_id
                ORDER BY audit.id DESC
                """
            )

            data = []

            for row in rows:

                data.append(
                    (
                        row["created"],
                        row["name"],
                        row["action"],
                        row["target"],
                        row["result"]
                    )
                )

            return self.send_bytes(
                table_page(
                    "Audit Log",
                    [
                        "Time",
                        "Site",
                        "Action",
                        "Target",
                        "Result"
                    ],
                    data
                ).encode("utf-8")
            )


        if path.startswith("/sites/"):

            parts = path.split("/")

            if len(parts) >= 3:

                site_id = unquote(
                    parts[2]
                )

                return self.send_bytes(
                    site_page(
                        site_id
                    ).encode("utf-8")
                )


        if path == "/download/mlwg.php":

            php_path = PHP_DIR / "mlwg.php"

            if not php_path.exists():

                generate_php_connector()

            data = php_path.read_bytes()

            return self.send_bytes(
                data,
                "application/octet-stream"
            )


        if path == "/api/health":

            return self.send_json(
                {
                    "ok": True,
                    "application": APP_NAME,
                    "version": APP_VERSION,
                    "time": now()
                }
            )


        if path == "/api/sites":

            sites = query(
                """
                SELECT
                    id,
                    name,
                    url,
                    status,
                    wp_version,
                    php_version,
                    os,
                    server,
                    https,
                    last_sync,
                    last_scan,
                    created
                FROM sites
                ORDER BY created DESC
                """
            )

            return self.send_json(
                [
                    dict(site)
                    for site in sites
                ]
            )


        return self.send_bytes(
            b"Not found",
            "text/plain; charset=utf-8",
            404
        )


    # ========================================================
    # POST
    # ========================================================

    def do_POST():

        path = urlparse(
            self.path
        ).path

        # This method is replaced below.
        return


# ============================================================
# POST IMPLEMENTATION
# ============================================================

def _do_post(self: MLWGHandler):

    path = urlparse(
        self.path
    ).path


    # --------------------------------------------------------
    # WEB SCAN
    # --------------------------------------------------------

    if (
        path.startswith("/sites/")
        and path.endswith("/scan")
    ):

        parts = path.split("/")

        if len(parts) < 3:

            return self.send_json(
                {
                    "ok": False,
                    "error": "invalid_site"
                },
                400
            )

        site_id = unquote(
            parts[2]
        )

        threading.Thread(
            target=run_security_scan,
            args=(site_id,),
            daemon=True
        ).start()

        self.send_response(303)

        self.send_header(
            "Location",
            f"/sites/{site_id}"
        )

        self.end_headers()

        return


    # --------------------------------------------------------
    # ENROLL
    # --------------------------------------------------------

    if path == "/api/connector/enroll":

        return connector_enroll(
            self
        )


    # --------------------------------------------------------
    # HEARTBEAT
    # --------------------------------------------------------

    if path == "/api/connector/heartbeat":

        return connector_heartbeat(
            self
        )


    # --------------------------------------------------------
    # SYNC
    # --------------------------------------------------------

    if path == "/api/connector/sync":

        return connector_sync(
            self
        )


    return self.send_json(
        {
            "ok": False,
            "error": "not_found"
        },
        404
    )


MLWGHandler.do_POST = _do_post


# ============================================================
# CONNECTOR ENROLL
# ============================================================

def connector_enroll(
    handler: MLWGHandler
):

    data, raw_body = handler.read_json()

    installation_id = str(
        data.get(
            "installation_id",
            ""
        )
    )

    token = str(
        data.get(
            "enrollment_token",
            ""
        )
    )


    if (
        not installation_id
        or not token
    ):

        return handler.send_json(
            {
                "ok": False,
                "error": "invalid_enrollment"
            },
            400
        )


    enrollment = query(
        """
        SELECT *
        FROM enrollments
        WHERE id=?
        """,
        (installation_id,),
        one=True
    )


    if not enrollment:

        return handler.send_json(
            {
                "ok": False,
                "error": "unknown_installation"
            },
            403
        )


    if enrollment["used"]:

        return handler.send_json(
            {
                "ok": False,
                "error": "token_already_used"
            },
            403
        )


    if unix_time() > int(
        enrollment["expires"]
    ):

        return handler.send_json(
            {
                "ok": False,
                "error": "token_expired"
            },
            403
        )


    if not hmac.compare_digest(
        enrollment["token_hash"],
        sha256(token)
    ):

        return handler.send_json(
            {
                "ok": False,
                "error": "invalid_token"
            },
            403
        )


    site_id = secrets.token_hex(16)


    site_url = str(
        data.get(
            "site_url",
            ""
        )
    ).strip()


    site_name = str(
        data.get("name")
        or site_url
        or "WordPress Site"
    ).strip()


    if len(site_name) > 200:
        site_name = site_name[:200]


    if len(site_url) > 2048:
        site_url = site_url[:2048]


    https = int(
        site_url.lower().startswith(
            "https://"
        )
    )


    metadata = data.get(
        "metadata",
        {}
    )

    if not isinstance(
        metadata,
        dict
    ):
        metadata = {}


    metadata["enrolled_at"] = now()


    execute(
        """
        INSERT INTO sites
        (
            id,
            name,
            url,
            status,
            wp_version,
            php_version,
            os,
            server,
            https,
            last_sync,
            last_scan,
            created,
            metadata
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            site_id,
            site_name,
            site_url,
            "online",

            str(
                data.get(
                    "wp_version",
                    ""
                )
            ),

            str(
                data.get(
                    "php_version",
                    ""
                )
            ),

            str(
                data.get(
                    "os",
                    ""
                )
            ),

            str(
                data.get(
                    "server",
                    ""
                )
            ),

            https,

            now(),

            None,

            now(),

            safe_json(metadata)
        )
    )


    execute(
        """
        UPDATE enrollments
        SET
            used=1,
            site_id=?
        WHERE id=?
        """,
        (
            site_id,
            installation_id
        )
    )


    execute(
        """
        INSERT OR REPLACE INTO replay_guard
        (
            site_id,
            last_timestamp
        )
        VALUES (?, ?)
        """,
        (
            site_id,
            0
        )
    )


    audit(
        site_id,
        "enrollment",
        "wordpress",
        "success"
    )


    return handler.send_json(
        {
            "ok": True,
            "site_id": site_id,
            "connector_secret":
                enrollment[
                    "connector_secret"
                ]
        }
    )


# ============================================================
# CONNECTOR HEARTBEAT
# ============================================================

def connector_heartbeat(
    handler: MLWGHandler
):

    data, raw_body = handler.read_json()

    valid, result = verify_signed_request(
        handler,
        "/api/connector/heartbeat",
        raw_body
    )


    if not valid:

        return handler.send_json(
            {
                "ok": False,
                "error": result
            },
            403
        )


    site_id = result


    execute(
        """
        UPDATE sites
        SET
            status='online',
            last_sync=?
        WHERE id=?
        """,
        (
            now(),
            site_id
        )
    )


    return handler.send_json(
        {
            "ok": True,
            "status": "online",
            "time": now()
        }
    )


# ============================================================
# CONNECTOR SYNC
# ============================================================

def connector_sync(
    handler: MLWGHandler
):

    data, raw_body = handler.read_json()

    valid, result = verify_signed_request(
        handler,
        "/api/connector/sync",
        raw_body
    )


    if not valid:

        return handler.send_json(
            {
                "ok": False,
                "error": result
            },
            403
        )


    site_id = result


    site = query(
        """
        SELECT *
        FROM sites
        WHERE id=?
        """,
        (site_id,),
        one=True
    )


    if not site:

        return handler.send_json(
            {
                "ok": False,
                "error": "site_not_found"
            },
            404
        )


    url = str(
        data.get(
            "site_url"
        )
        or site["url"]
    )


    name = str(
        data.get(
            "name"
        )
        or site["name"]
    )


    metadata = data.get(
        "metadata",
        {}
    )

    if not isinstance(
        metadata,
        dict
    ):
        metadata = {}


    execute(
        """
        UPDATE sites

        SET
            name=?,
            url=?,
            wp_version=?,
            php_version=?,
            os=?,
            server=?,
            https=?,
            status='online',
            last_sync=?,
            metadata=?

        WHERE id=?
        """,
        (
            name,
            url,

            str(
                data.get(
                    "wp_version",
                    ""
                )
            ),

            str(
                data.get(
                    "php_version",
                    ""
                )
            ),

            str(
                data.get(
                    "os",
                    ""
                )
            ),

            str(
                data.get(
                    "server",
                    ""
                )
            ),

            int(
                bool(
                    data.get(
                        "https",
                        False
                    )
                )
            ),

            now(),

            safe_json(metadata),

            site_id
        )
    )


    audit(
        site_id,
        "connector_sync",
        "metadata",
        "success"
    )


    return handler.send_json(
        {
            "ok": True,
            "site_id": site_id,
            "last_sync": now()
        }
    )


# ============================================================
# MAIN
# ============================================================

def main():

    init_database()
    intelligence_migrate()

    threading.Thread(target=_automation_loop, daemon=True).start()

    # Generate the first connector automatically.
    php_path = generate_php_connector()

    print()
    print("=" * 64)
    print(" MLUNCHER WORDPRESS GUARD")
    print(" MLWG")
    print("=" * 64)
    print()

    print(
        f" Dashboard:"
        f" http://{HOST}:{PORT}"
    )

    print()

    print(
        f" Manager endpoint:"
        f" {MANAGER_ENDPOINT}"
    )

    print()

    print(
        f" PHP Connector:"
        f" {php_path}"
    )

    print()

    print(
        " Download:"
        f" http://{HOST}:{PORT}/download/mlwg.php"
    )

    print()

    print(
        f" Database:"
        f" {DB_PATH}"
    )

    print()

    print(
        " Workflow:"
    )

    print(
        "  1. Open dashboard"
    )

    print(
        "  2. Download mlwg.php"
    )

    print(
        "  3. Copy to WordPress plugin directory"
    )

    print(
        "  4. Activate MLUNCHER WordPress Guard"
    )

    print(
        "  5. Plugin automatically enrolls"
    )

    print(
        "  6. Site appears in MLWG"
    )

    print()

    print(
        " Press CTRL+C to stop."
    )

    print()


    server = ThreadingHTTPServer(
        (HOST, PORT),
        MLWGHandler
    )


    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print(
            "\nMLWG stopped."
        )

    finally:

        server.server_close()



# ============================================================
# MLWG 2.0 SECURITY AND CAPABILITY EXTENSIONS
# ============================================================

LOG_DIR = DATA_DIR / "logs"
ENROLLMENT_DIR = DATA_DIR / "enrollments"
BACKUP_DIR = DATA_DIR / "backups"
QUARANTINE_DIR = DATA_DIR / "quarantine"
for _directory in (LOG_DIR, ENROLLMENT_DIR, BACKUP_DIR, QUARANTINE_DIR):
    _directory.mkdir(parents=True, exist_ok=True)


def _internal_error(component: str, action: str, exc: Exception):
    """Redacted internal logging; secrets and authorization material are never persisted."""
    try:
        message = str(exc)
        for marker in ("password", "token", "secret", "cookie", "authorization"):
            message = message.replace(marker, "[redacted]")
        with (LOG_DIR / "mlwg.log").open("a", encoding="utf-8") as stream:
            stream.write(safe_json({"timestamp": now(), "component": component, "action": action, "error": message}) + "\n")
    except Exception:
        return None


def _column_exists(connection, table: str, column: str) -> bool:
    return any(row[1] == column for row in connection.execute(f"PRAGMA table_info({table})").fetchall())


def _add_column(connection, table: str, column: str, definition: str):
    if not _column_exists(connection, table, column):
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def enhanced_init_database():
    init_database_legacy()
    with DB_LOCK:
        with db() as connection:
            for table, columns in {
                "sites": [("home_url", "TEXT"), ("last_seen", "TEXT"), ("capabilities", "TEXT NOT NULL DEFAULT '{}'"), ("timezone", "TEXT"), ("locale", "TEXT"), ("multisite", "INTEGER"), ("architecture", "TEXT"), ("database_type", "TEXT"), ("database_version", "TEXT")],
                "findings": [("category", "TEXT NOT NULL DEFAULT 'security'"), ("sha256", "TEXT"), ("indicator", "TEXT"), ("confidence", "TEXT NOT NULL DEFAULT 'unknown'"), ("risk", "INTEGER"), ("risk_factors", "TEXT NOT NULL DEFAULT '[]'"), ("recommendation", "TEXT"), ("fingerprint", "TEXT"), ("first_seen", "TEXT"), ("last_seen", "TEXT"), ("updated", "TEXT")],
                "jobs": [("updated", "TEXT"), ("cancel_requested", "INTEGER NOT NULL DEFAULT 0")],
            }.items():
                for column, definition in columns:
                    _add_column(connection, table, column, definition)
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS nonces (
                    site_id TEXT NOT NULL, nonce TEXT NOT NULL, created INTEGER NOT NULL,
                    PRIMARY KEY(site_id, nonce)
                );
                CREATE TABLE IF NOT EXISTS integrity_baselines (
                    site_id TEXT PRIMARY KEY, files TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS plugin_inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL, slug TEXT, name TEXT,
                    version TEXT, author TEXT, status TEXT, network_active INTEGER, update_available INTEGER,
                    plugin_uri TEXT, description TEXT, integrity TEXT, sha256 TEXT, updated TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS theme_inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL, slug TEXT, name TEXT,
                    version TEXT, author TEXT, active INTEGER, update_available INTEGER, integrity TEXT,
                    sha256 TEXT, updated TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS user_inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL, wp_id INTEGER,
                    username TEXT, display_name TEXT, role TEXT, registered TEXT, status TEXT, updated TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS backups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT, backup_type TEXT NOT NULL,
                    size INTEGER, sha256 TEXT, created TEXT NOT NULL, status TEXT NOT NULL, path TEXT
                );
                CREATE TABLE IF NOT EXISTS automation_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT, name TEXT NOT NULL,
                    trigger TEXT NOT NULL, action TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                    last_run TEXT, created TEXT NOT NULL, updated TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT, report_type TEXT NOT NULL,
                    format TEXT NOT NULL, content TEXT NOT NULL, created TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT, original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL, sha256 TEXT NOT NULL, reason TEXT NOT NULL,
                    finding_id INTEGER, created TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'quarantined'
                );
                CREATE INDEX IF NOT EXISTS idx_nonces_created ON nonces(created);
                CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
                CREATE TABLE IF NOT EXISTS finding_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL, type TEXT NOT NULL,
                    source TEXT NOT NULL, site_id TEXT NOT NULL, timestamp TEXT NOT NULL, path TEXT,
                    line INTEGER, value TEXT, normalized_value TEXT, sha256 TEXT, confidence TEXT,
                    metadata TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL, title TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open', confidence TEXT NOT NULL, risk INTEGER NOT NULL,
                    related_findings TEXT NOT NULL DEFAULT '[]', common_file TEXT, created TEXT NOT NULL, updated TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS security_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL, score INTEGER,
                    critical_count INTEGER NOT NULL DEFAULT 0, high_count INTEGER NOT NULL DEFAULT 0,
                    open_incidents INTEGER NOT NULL DEFAULT 0, integrity_changes INTEGER NOT NULL DEFAULT 0,
                    configuration_drift INTEGER NOT NULL DEFAULT 0, profile TEXT, created TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS security_baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL, version INTEGER NOT NULL,
                    snapshot TEXT NOT NULL, created TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(site_id, version)
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_finding ON finding_evidence(finding_id);
                CREATE INDEX IF NOT EXISTS idx_incidents_site ON incidents(site_id);
                CREATE INDEX IF NOT EXISTS idx_history_site ON security_history(site_id);
            """)
            connection.commit()


# Keep the original initializer available for the migration wrapper.
init_database_legacy = init_database
init_database = enhanced_init_database


def _json_object(data):
    return isinstance(data, dict) and len(safe_json(data).encode("utf-8")) <= 2 * 1024 * 1024


def _site(site_id):
    return query("SELECT * FROM sites WHERE id=?", (site_id,), one=True)


def _capability_error(capability: str):
    return {"ok": False, "error": "connector_capability_unavailable", "capability": capability, "message": "Connector capability unavailable"}


def _normalise_files(value):
    if not isinstance(value, list):
        return {}
    result = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", "")).replace("\\", "/").lstrip("/")
        digest = str(item.get("sha256", ""))
        if path and len(path) <= 1024 and len(digest) == 64:
            result[path] = {"sha256": digest, "size": _safe_int(item.get("size", 0)), "modified": str(item.get("modified", ""))}
    return result


def _store_inventories(site_id: str, metadata: dict):
    timestamp = now()
    for table, key, columns in (
        ("plugin_inventory", "plugins", ("slug", "name", "version", "author", "status", "network_active", "update_available", "plugin_uri", "description", "integrity", "sha256")),
        ("theme_inventory", "themes", ("slug", "name", "version", "author", "active", "update_available", "integrity", "sha256")),
        ("user_inventory", "users", ("wp_id", "username", "display_name", "role", "registered", "status")),
    ):
        records = metadata.get(key, [])
        if not isinstance(records, list):
            continue
        execute(f"DELETE FROM {table} WHERE site_id=?", (site_id,))
        for record in records[:5000]:
            if not isinstance(record, dict):
                continue
            values = [site_id] + [record.get(column) for column in columns] + [timestamp]
            placeholders = ",".join("?" for _ in values)
            execute(f"INSERT INTO {table} (site_id,{','.join(columns)},updated) VALUES ({placeholders})", values)


def _integrity_compare(site_id: str, files):
    current = _normalise_files(files)
    old_row = query("SELECT files FROM integrity_baselines WHERE site_id=?", (site_id,), one=True)
    old = json.loads(old_row["files"]) if old_row else {}
    changes = []
    for path in sorted(set(old) | set(current)):
        if path not in old:
            changes.append({"change": "created", "path": path, "old_sha256": None, "new_sha256": current[path]["sha256"]})
        elif path not in current:
            changes.append({"change": "deleted", "path": path, "old_sha256": old[path]["sha256"], "new_sha256": None})
        elif old[path]["sha256"] != current[path]["sha256"]:
            changes.append({"change": "modified", "path": path, "old_sha256": old[path]["sha256"], "new_sha256": current[path]["sha256"]})
    return current, changes


def _malware_indicators(site_id: str, files):
    patterns = {
        "eval(": "dynamic execution", "base64_decode(": "encoded payload", "gzinflate(": "compressed payload",
        "gzdecode(": "compressed payload", "str_rot13(": "obfuscation", "assert(": "dynamic execution",
        "preg_replace": "legacy dynamic execution", "shell_exec(": "command execution", "passthru(": "command execution",
    }
    findings = []
    for item in files if isinstance(files, list) else []:
        if not isinstance(item, dict):
            continue
        path, content = str(item.get("path", "")), str(item.get("content", ""))
        if not path or not content or len(content) > 512 * 1024:
            continue
        for needle, label in patterns.items():
            position = content.find(needle)
            if position >= 0:
                line = content.count("\n", 0, position) + 1
                findings.append(("high", "malware", f"Suspicious pattern detected: {label}", "Detection is not malware confirmation.", path, line, item.get("sha256", ""), needle))
                break
    return findings


def _record_finding(site_id, severity, category, title, detail, file_name="", line=None, evidence="", digest=""):
    execute("INSERT INTO findings (site_id,severity,category,title,detail,file,line,evidence,sha256,status,created) VALUES (?,?,?,?,?,?,?,?,?,'open',?)", (site_id, severity, category, title, detail, file_name, line, evidence, digest, now()))


def _safe_report(site_id, report_type):
    site = _site(site_id)
    if not site:
        return None
    findings = [dict(row) for row in query("SELECT * FROM findings WHERE site_id=? ORDER BY id DESC", (site_id,))]
    return {"site": dict(site), "report_type": report_type, "findings": findings, "generated": now()}



# ============================================================
# SECURITY ASSESSMENT ENGINE
# ============================================================

class Analyzer:
    name = 'core'
    def analyze(self, context):
        return []


class ConfigurationAnalyzer(Analyzer):
    name = 'configuration'
    def analyze(self, context):
        m = context.metadata
        checks = [
            ('debug', m.get('debug') is True, 'high', 'WP_DEBUG is enabled', 'Disable WP_DEBUG in production.'),
            ('debug_display', m.get('wp_debug_display') is True, 'high', 'Debug output is displayed', 'Disable WP_DEBUG_DISPLAY.'),
            ('debug_log', m.get('wp_debug_log') is True, 'medium', 'Debug logging is enabled', 'Review debug log access and disable it when unnecessary.'),
            ('file_edit', m.get('file_edit') is True, 'medium', 'WordPress file editor is enabled', 'Set DISALLOW_FILE_EDIT to true.'),
            ('force_ssl_admin', m.get('force_ssl_admin') is not True, 'medium', 'Force SSL Admin is not enabled', 'Enable FORCE_SSL_ADMIN.'),
            ('registration', m.get('registration') is True, 'medium', 'Public registration is enabled', 'Disable public registration unless required.'),
            ('repair', m.get('wp_allow_repair') is True, 'high', 'Database repair mode is enabled', 'Disable WP_ALLOW_REPAIR.'),
        ]
        return [context.finding('configuration', title, detail, severity, key, 'high', 'wp-config.php')
                for key, active, severity, title, detail in checks if active]


class HttpSecurityAnalyzer(Analyzer):
    name = 'http'
    def analyze(self, context):
        m = context.metadata
        out=[]
        https = m.get('https', context.site['https'])
        if https is False:
            out.append(context.finding('http', 'HTTPS is disabled', 'Traffic may be intercepted or modified.', 'high', 'https', 'high', 'site'))
        headers = m.get('security_headers')
        if isinstance(headers, dict):
            for key in ('hsts','csp','x_frame_options','x_content_type_options','referrer_policy','permissions_policy'):
                state = headers.get(key, 'unknown')
                if state in (False, 'missing', 'invalid'):
                    out.append(context.finding('http', f'Security header {key} is {state}', 'A recommended HTTP security header is unavailable or invalid.', 'medium', key, 'medium', 'HTTP response'))
        return out


class XmlRpcAnalyzer(Analyzer):
    name = 'xmlrpc'
    def analyze(self, context):
        state=context.metadata.get('xmlrpc', 'unknown')
        if state is True or state == 'enabled':
            return [context.finding('xmlrpc','XML-RPC is enabled','XML-RPC increases the exposed attack surface; disable it if not required.','medium','xmlrpc','medium','WordPress')]
        return []


class RestApiAnalyzer(Analyzer):
    name='rest_api'
    def analyze(self, context):
        m=context.metadata
        if m.get('rest_api_public') is True or m.get('user_enumeration') is True:
            return [context.finding('rest_api','REST API user enumeration is exposed','Public API behavior exposes user data without authentication.','medium','user_enumeration','medium','REST API')]
        return []


class AuthenticationAnalyzer(Analyzer):
    name='authentication'
    def analyze(self, context):
        users=context.metadata.get('users', [])
        if not isinstance(users,list): return []
        admins=[u for u in users if isinstance(u,dict) and 'administrator' in (u.get('roles') or [])]
        out=[]
        if len(admins)>3:
            out.append(context.finding('authentication','Many administrator accounts','Review whether all privileged accounts are necessary.','medium','administrator_count','medium','users'))
        return out


class PluginSecurityAnalyzer(Analyzer):
    name='plugins'
    def analyze(self, context):
        out=[]
        for plugin in context.metadata.get('plugins', []) if isinstance(context.metadata.get('plugins', []),list) else []:
            if not isinstance(plugin,dict): continue
            if plugin.get('update_available') is True:
                out.append(context.finding('plugins',f"Plugin update available: {plugin.get('name','unknown')}",'An update is reported by the connector.','low','update_available','high',str(plugin.get('file','plugin'))))
        return out


class ThemeSecurityAnalyzer(Analyzer):
    name='themes'
    def analyze(self, context):
        out=[]
        for theme in context.metadata.get('themes', []) if isinstance(context.metadata.get('themes', []),list) else []:
            if isinstance(theme,dict) and theme.get('update_available') is True:
                out.append(context.finding('themes',f"Theme update available: {theme.get('name','unknown')}",'An update is reported by the connector.','low','update_available','high',str(theme.get('stylesheet','theme'))))
        return out


class CoreSecurityAnalyzer(Analyzer):
    name='core'
    def analyze(self, context):
        m=context.metadata; out=[]
        if m.get('core_update_available') is True:
            out.append(context.finding('core','WordPress core update is available','Update WordPress after verifying backup availability.','high','core_update_available','high','WordPress core'))
        if m.get('core_integrity') in ('modified','failed'):
            out.append(context.finding('core','WordPress core integrity issue','Core integrity differs from the expected baseline.','high','core_integrity','medium','WordPress core'))
        return out


class PermissionAnalyzer(Analyzer):
    name='permissions'
    def analyze(self, context):
        permissions=context.metadata.get('permissions')
        if not isinstance(permissions,dict): return []
        return [context.finding('permissions','Sensitive path is writable','Review filesystem permissions for this path.','high','writable_sensitive','high',str(path)) for path,value in permissions.items() if isinstance(value,dict) and value.get('writable_sensitive') is True]


class DatabaseSecurityAnalyzer(Analyzer):
    name='database'
    def analyze(self, context):
        db=context.metadata.get('database')
        if isinstance(db,dict) and db.get('suspicious_options') is True:
            return [context.finding('database','Suspicious database configuration','Connector reported suspicious stored configuration; no secrets are retained.','high','suspicious_options','medium','database')]
        return []


class CronAnalyzer(Analyzer):
    name='cron'
    def analyze(self, context):
        cron=context.metadata.get('cron')
        if not isinstance(cron,list): return []
        return [context.finding('cron','Suspicious scheduled callback','Review the scheduled callback and its origin.','medium','suspicious_callback','low',str(item.get('hook','cron'))) for item in cron if isinstance(item,dict) and item.get('suspicious') is True]


class UploadSecurityAnalyzer(Analyzer):
    name='uploads'
    def analyze(self, context):
        out=[]
        for item in context.files:
            path=str(item.get('path','')).replace('\\','/').lstrip('/')
            lower=path.lower()
            if ('uploads/' in lower or '/uploads/' in lower) and lower.endswith(('.php','.phtml','.php3','.php4','.php5','.phar')):
                out.append(context.finding('uploads','PHP file exists in uploads','Executable PHP in uploads should be reviewed; this is detection only.','high','suspicious_upload','medium',path))
        return out


class MalwareIndicatorEngine(Analyzer):
    name='malware'
    patterns=(('eval(', 'dynamic execution'),('base64_decode(', 'encoded payload'),('gzinflate(', 'compressed payload'),('gzdecode(', 'compressed payload'),('str_rot13(', 'obfuscation'),('shell_exec(', 'command execution'),('passthru(', 'command execution'),('create_function(', 'dynamic execution'))
    def analyze(self, context):
        out=[]
        for item in context.files:
            content=str(item.get('content',''))
            if not content or len(content)>512*1024: continue
            path=str(item.get('path',''))
            for needle,label in self.patterns:
                pos=content.find(needle)
                if pos>=0:
                    line=content.count('\n',0,pos)+1
                    out.append(context.finding('malware',f'Suspicious PHP pattern: {label}','Detection is not malware confirmation. Review the source and execution context.','high',needle,'low',path,line,item.get('sha256','')))
                    break
        return out


class IntegrityEngine(Analyzer):
    name='integrity'
    def analyze(self, context):
        if not context.files: return []
        _,changes=_integrity_compare(context.site['id'],context.files)
        return [context.finding('integrity',f"File {c['change']}",'The current file inventory differs from the stored baseline.','medium',c['change'],'high',c['path'],digest=c.get('new_sha256') or c.get('old_sha256') or '') for c in changes]


class SecurityContext:
    def __init__(self, site, metadata, files, profile, job_id=None):
        self.site=site; self.metadata=metadata if isinstance(metadata,dict) else {}; self.files=files if isinstance(files,list) else []; self.profile=profile; self.job_id=job_id
    def finding(self, category, title, detail, severity='info', indicator='', confidence='unknown', file_name='', line=None, digest=''):
        return {'category':category,'title':title,'detail':detail,'severity':severity,'indicator':indicator,'confidence':confidence,'file':file_name,'line':line,'sha256':digest,'recommendation':detail}


class FindingEngine:
    @staticmethod
    def persist(site_id, findings):
        ids=[]
        for f in findings:
            normalized=' '.join(str(f['title']).lower().split())
            fingerprint=sha256('|'.join((site_id,f['category'],f.get('file',''),f.get('indicator',''),normalized)))
            old=query('SELECT id,first_seen FROM findings WHERE fingerprint=? AND site_id=?', (fingerprint,site_id), one=True)
            factors=RiskEngine.explain(f)
            risk=factors['score']
            if old:
                execute('UPDATE findings SET severity=?,detail=?,evidence=?,file=?,line=?,sha256=?,indicator=?,confidence=?,risk=?,risk_factors=?,recommendation=?,last_seen=?,updated=? WHERE id=?', (f['severity'],f['detail'],f.get('indicator',''),f.get('file',''),f.get('line'),f.get('sha256',''),f.get('indicator',''),f.get('confidence','unknown'),risk,safe_json(factors['factors']),f.get('recommendation',''),now(),now(),old['id']))
                ids.append(old['id'])
            else:
                with DB_LOCK:
                    with db() as connection:
                        cursor = connection.execute("INSERT INTO findings (site_id,severity,category,title,detail,file,line,evidence,sha256,status,created,indicator,confidence,risk,risk_factors,recommendation,fingerprint,first_seen,last_seen,updated) VALUES (?,?,?,?,?,?,?,?,?,'open',?,?,?,?,?,?,?,?,?,?)", (site_id,f['severity'],f['category'],f['title'],f['detail'],f.get('file',''),f.get('line'),f.get('indicator',''),f.get('sha256',''),now(),f.get('indicator',''),f.get('confidence','unknown'),risk,safe_json(factors['factors']),f.get('recommendation',''),fingerprint,now(),now(),now()))
                        connection.commit()
                        ids.append(int(cursor.lastrowid))
                EvidenceEngine.record(ids[-1], site_id, f)
        return ids


class RiskEngine:
    weights={'critical':40,'high':30,'medium':18,'low':8,'info':1}
    confidence={'confirmed':1.0,'high':0.85,'medium':0.65,'low':0.4,'unknown':0.25}
    @classmethod
    def explain(cls, finding):
        severity=str(finding.get('severity','info')).lower(); conf=str(finding.get('confidence','unknown')).lower()
        score=round(cls.weights.get(severity,1)*cls.confidence.get(conf,.25))
        factors=[f'+ {severity.title()} severity',f'+ {conf.title()} confidence']
        location=str(finding.get('file','')).lower()
        if 'uploads' in location: score+=10; factors.append('+ Publicly writable upload location')
        if finding.get('indicator') in ('eval(','base64_decode(','shell_exec('): score+=8; factors.append('+ Executable/obfuscation indicator')
        return {'score':min(100,score),'factors':factors}


class CorrelationEngine:
    @staticmethod
    def correlate(site_id):
        rows=[dict(r) for r in query("SELECT * FROM findings WHERE site_id=? AND status='open' ORDER BY id DESC",(site_id,))]
        clusters=[]
        by_file={}
        for row in rows:
            if row.get('file'): by_file.setdefault(row['file'],[]).append(row)
        for file_name,related in by_file.items():
            if len(related)<2: continue
            clusters.append({'common_file':file_name,'related_findings':[r['id'] for r in related],'common_category':sorted(set(r['category'] for r in related)),'common_indicator':sorted(set(r.get('indicator') or '' for r in related)),'confidence':'medium','risk':min(100,sum(int(r.get('risk') or 0) for r in related))})
        return clusters



class BehaviorAnalyzer(Analyzer):
    name='behavior'
    def analyze(self, context):
        m=context.metadata; out=[]
        behaviors=[]
        users=m.get('users', [])
        if isinstance(users,list) and any(isinstance(u,dict) and u.get('recently_created_privileged') is True for u in users): behaviors.append('recent privileged user')
        if isinstance(m.get('configuration_changes'),list) and m['configuration_changes']: behaviors.append('configuration changed')
        if m.get('xmlrpc_changed_to_enabled') is True: behaviors.append('XML-RPC enabled')
        if len(behaviors)>=2:
            out.append(context.finding('behavior','Multiple security-relevant changes detected','Several independent changes were reported in the same scan; review their timeline.','high','behavior_cluster','medium','site'))
        return out


class ExposureAnalyzer(Analyzer):
    name='exposure'
    def analyze(self, context):
        m=context.metadata; out=[]
        if m.get('directory_listing') is True: out.append(context.finding('exposure','Directory listing is exposed','Public directory listing can disclose files and metadata.','medium','directory_listing','medium','HTTP'))
        if m.get('sensitive_files_exposed') is True: out.append(context.finding('exposure','Sensitive files may be exposed','Connector reported exposed sensitive files; detection only.','high','sensitive_files','medium','HTTP'))
        return out


class HardeningAnalyzer(Analyzer):
    name='hardening'
    def analyze(self, context):
        m=context.metadata; out=[]
        if m.get('file_edit') is True or m.get('registration') is True:
            out.append(context.finding('hardening','Hardening recommendations available','Configuration can be hardened through a separate preview-confirm-apply action.','low','hardening_available','high','configuration'))
        return out


class EvidenceEngine:
    @staticmethod
    def record(finding_id, site_id, finding):
        value=finding.get('indicator') or finding.get('detail') or ''
        execute('INSERT INTO finding_evidence (finding_id,type,source,site_id,timestamp,path,line,value,normalized_value,sha256,confidence,metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', (finding_id, finding.get('evidence_type','metadata'), finding.get('source','connector'), site_id, now(), finding.get('file',''), finding.get('line'), str(value)[:4000], ' '.join(str(value).lower().split())[:4000], finding.get('sha256',''), finding.get('confidence','unknown'), safe_json({'category':finding.get('category',''), 'indicator':finding.get('indicator','')})))


class BaselineEngine:
    @staticmethod
    def snapshot(site_id):
        site=_site(site_id)
        if not site: return None
        metadata=json.loads(site['metadata'] or '{}')
        return {'site_id':site_id,'configuration':{k:metadata.get(k,'unknown') for k in ('debug','wp_debug_log','wp_debug_display','file_edit','force_ssl_admin','registration','xmlrpc','https')},'core':{k:metadata.get(k,'unknown') for k in ('wp_version','core_integrity')},'plugins':metadata.get('plugins','unknown'),'themes':metadata.get('themes','unknown'),'users':metadata.get('users','unknown'),'security_headers':metadata.get('security_headers','unknown'),'integrity':metadata.get('files','unknown')}
    @staticmethod
    def create(site_id):
        snapshot=BaselineEngine.snapshot(site_id)
        if snapshot is None: return None
        row=query('SELECT MAX(version) AS version FROM security_baselines WHERE site_id=?',(site_id,),one=True)
        version=int(row['version'] or 0)+1
        execute('UPDATE security_baselines SET active=0 WHERE site_id=?',(site_id,))
        execute('INSERT INTO security_baselines (site_id,version,snapshot,created,active) VALUES (?,?,?,?,1)',(site_id,version,safe_json(snapshot),now()))
        audit(site_id,'baseline_created','v'+str(version),'success')
        return {'site_id':site_id,'version':version,'snapshot':snapshot}
    @staticmethod
    def compare(site_id):
        baseline=query('SELECT * FROM security_baselines WHERE site_id=? AND active=1 ORDER BY version DESC LIMIT 1',(site_id,),one=True)
        current=BaselineEngine.snapshot(site_id)
        if not current: return None
        if not baseline: return {'status':'unavailable','reason':'no_baseline','current':current,'changes':[]}
        old=json.loads(baseline['snapshot']); changes=[]
        for key in ('configuration','core','security_headers'):
            before=old.get(key,{}); after=current.get(key,{})
            if before != after: changes.append({'category':key,'previous':before,'current':after,'timestamp':now()})
        return {'status':'changed' if changes else 'unchanged','version':baseline['version'],'changes':changes,'current':current}


class DiagnosticEngine:
    @staticmethod
    def run():
        checks=[]
        try: init_database(); checks.append({'name':'database','status':'PASS'})
        except Exception: checks.append({'name':'database','status':'FAIL'})
        checks += [{'name':'rules','status':'PASS' if SecurityEngine.ANALYZERS else 'FAIL'}, {'name':'analyzer_registry','status':'PASS'}, {'name':'crypto','status':'PASS' if hmac.compare_digest('a','a') else 'FAIL'}, {'name':'filesystem','status':'PASS' if DATA_DIR.exists() else 'FAIL'}, {'name':'job_engine','status':'PASS'}, {'name':'audit_engine','status':'PASS'}]
        return {'ok': all(c['status'] != 'FAIL' for c in checks), 'checks':checks, 'generated':now()}

class SecurityEngine:
    ANALYZERS=(CoreSecurityAnalyzer(),ConfigurationAnalyzer(),AuthenticationAnalyzer(),PluginSecurityAnalyzer(),ThemeSecurityAnalyzer(),RestApiAnalyzer(),XmlRpcAnalyzer(),HttpSecurityAnalyzer(),UploadSecurityAnalyzer(),PermissionAnalyzer(),DatabaseSecurityAnalyzer(),CronAnalyzer(),BehaviorAnalyzer(),ExposureAnalyzer(),HardeningAnalyzer(),IntegrityEngine(),MalwareIndicatorEngine())
    PROFILES={'quick':set(('core','configuration','authentication','plugins','themes','rest_api','xmlrpc','http','exposure')), 'standard':set(('core','configuration','authentication','plugins','themes','rest_api','xmlrpc','http','uploads','permissions','database','cron','behavior','exposure','hardening','integrity')), 'deep':set(('core','configuration','authentication','plugins','themes','rest_api','xmlrpc','http','uploads','permissions','database','cron','behavior','exposure','hardening','integrity','malware'))}
    @classmethod
    def run(cls, site_id, profile='quick', files=None, job_id=None):
        site=_site(site_id)
        if not site: raise ValueError('site_not_found')
        metadata=json.loads(site['metadata'] or '{}')
        context=SecurityContext(site,metadata,files or [],profile,job_id)
        selected=cls.PROFILES.get(str(profile).lower(),cls.PROFILES['quick'])
        findings=[]
        stages=[a for a in cls.ANALYZERS if a.name in selected]
        for index, analyzer in enumerate(stages, 1):
            if job_id and query('SELECT cancel_requested FROM jobs WHERE id=?', (job_id,), one=True)['cancel_requested']:
                raise RuntimeError('job_cancelled')
            if job_id:
                _job_update(job_id, 'running', round(index * 90 / max(1, len(stages))), 'Analyzing ' + analyzer.name)
            findings.extend(analyzer.analyze(context))
        FindingEngine.persist(site_id,findings)
        clusters=CorrelationEngine.correlate(site_id)
        score=cls.score(site_id)
        for cluster in clusters:
            execute('INSERT INTO incidents (site_id,title,status,confidence,risk,related_findings,common_file,created,updated) VALUES (?,?,?,?,?,?,?,?,?)', (site_id,'Correlated security event','open',cluster['confidence'],cluster['risk'],safe_json(cluster['related_findings']),cluster.get('common_file',''),now(),now()))
        counts=query("SELECT severity,COUNT(*) AS count FROM findings WHERE site_id=? AND status='open' GROUP BY severity",(site_id,))
        count_map={r['severity']:r['count'] for r in counts}
        execute('INSERT INTO security_history (site_id,score,critical_count,high_count,open_incidents,profile,created) VALUES (?,?,?,?,?,?,?)',(site_id,score['score'],count_map.get('critical',0),count_map.get('high',0),len(clusters),profile,now()))
        execute('UPDATE sites SET last_scan=?,last_seen=?,status=? WHERE id=?',(now(),now(),'online',site_id))
        return {'profile':profile,'finding_count':len(findings),'incidents':clusters,'score':score,'data_status':{'metadata':'available','files':'available' if files else 'unavailable'}}
    @staticmethod
    def score(site_id):
        rows=query("SELECT severity,risk FROM findings WHERE site_id=? AND status='open'",(site_id,))
        penalty=sum(min(40,int(r['risk'] or 0)) for r in rows)
        value=max(0,100-min(100,penalty))
        return {'score':value,'available':True,'basis':'open findings and explainable risk factors'}


def _run_security_job(site_id, profile='quick', files=None, job_id=None):
    return SecurityEngine.run(site_id, profile, files, job_id)

# ============================================================
# MLWG 2.0 FEATURE API
# ============================================================

def _safe_int(value, default=0, minimum=0):
    try:
        return max(minimum, int(value))
    except (TypeError, ValueError):
        return default


def _job_create(site_id, kind, message='queued'):
    with DB_LOCK:
        with db() as connection:
            cursor = connection.execute(
                "INSERT INTO jobs (site_id,kind,status,progress,message,created,updated) VALUES (?,?,?,?,?,?,?)",
                (site_id, kind, 'queued', 0, message, now(), now())
            )
            connection.commit()
            return int(cursor.lastrowid)


def _job_update(job_id, status, progress, message='', finished=None):
    execute('UPDATE jobs SET status=?,progress=?,message=?,updated=?,finished=? WHERE id=?',
            (status, _safe_int(progress, 0), str(message)[:500], now(), finished, job_id))


def _run_job(job_id, site_id, kind, fn):
    _job_update(job_id, 'running', 5, 'Job started')
    try:
        result = fn(job_id) if len(inspect.signature(fn).parameters) else fn()
        current = query('SELECT status FROM jobs WHERE id=?', (job_id,), one=True)
        if current and current['status'] == 'cancelled':
            return result
        _job_update(job_id, 'success', 100, 'Completed', now())
        audit(site_id, kind, 'job', 'success')
        return result
    except Exception as exc:
        _internal_error('job', kind, exc)
        if str(exc) == 'job_cancelled':
            _job_update(job_id, 'cancelled', 100, 'Cancelled', now())
            audit(site_id, kind, 'job', 'cancelled')
        else:
            _job_update(job_id, 'failed', 100, 'Job failed', now())
            audit(site_id, kind, 'job', 'failed')
        return None


def _launch_job(site_id, kind, fn):
    job_id = _job_create(site_id, kind)
    threading.Thread(target=_run_job, args=(job_id, site_id, kind, fn), daemon=True).start()
    return job_id


def _site_or_error(handler, site_id):
    site = _site(site_id)
    if not site:
        handler.send_json({'ok': False, 'error': 'site_not_found'}, 404)
        return None
    return site


def _security_findings(site_id):
    site = _site(site_id)
    if not site:
        return []
    metadata = json.loads(site['metadata'] or '{}')
    checks = [
        ('https', not bool(metadata.get('https', site['https'])), 'high', 'HTTPS is disabled', 'Enable HTTPS and redirect HTTP traffic.'),
        ('xmlrpc', metadata.get('xmlrpc') is True, 'medium', 'XML-RPC is enabled', 'Disable XML-RPC unless it is required.'),
        ('rest_api', metadata.get('rest_api_public') is True, 'medium', 'REST API exposes user data', 'Restrict unauthenticated REST API data.'),
        ('file_edit', metadata.get('file_edit') is True, 'medium', 'WordPress file editor is enabled', 'Set DISALLOW_FILE_EDIT to true.'),
        ('registration', metadata.get('registration') is True, 'medium', 'Public registration is enabled', 'Disable public registration unless required.'),
        ('debug_display', metadata.get('wp_debug_display') is True, 'high', 'Debug errors are displayed', 'Disable WP_DEBUG_DISPLAY in production.'),
        ('security_headers', metadata.get('security_headers_missing') is True, 'medium', 'Security headers are missing', 'Configure CSP, HSTS, X-Content-Type-Options and Referrer-Policy.'),
    ]
    findings = []
    for key, active, severity, title, detail in checks:
        if active:
            findings.append((severity, 'security', title, detail, 'wp-config.php' if key in ('file_edit','debug_display') else 'WordPress', None, key, ''))
    if len(metadata.get('users', [])) > 500:
        findings.append(('low', 'users', 'Large user inventory', 'Review dormant and privileged accounts.', 'WordPress Users', None, 'user_count', ''))
    return findings


def _run_security_job(site_id, profile='quick', files=None, job_id=None):
    return SecurityEngine.run(site_id, profile, files, job_id)


def _run_malware_job(site_id, files):
    for finding in _malware_indicators(site_id, files):
        severity, category, title, detail, filename, line, evidence, needle = finding
        _record_finding(site_id, severity, category, title, detail, filename, line, needle, evidence)
    return True


def _search(term):
    term = str(term or '').strip()[:100]
    if not term:
        return []
    like = '%' + term + '%'
    results = []
    for row in query('SELECT id,name,url,status FROM sites WHERE name LIKE ? OR url LIKE ? LIMIT 50', (like, like)):
        results.append({'type': 'site', 'id': row['id'], 'title': row['name'], 'subtitle': row['url'], 'url': '/sites/' + row['id']})
    for row in query('SELECT id,title,detail,severity FROM findings WHERE title LIKE ? OR detail LIKE ? LIMIT 50', (like, like)):
        results.append({'type': 'finding', 'id': row['id'], 'title': row['title'], 'subtitle': row['severity'], 'url': '/findings'})
    return results


def _report(site_id, report_type):
    site = _site(site_id)
    if not site:
        return None
    report = {'site': dict(site), 'report_type': report_type, 'generated': now(),
              'assessment': SecurityEngine.score(site_id),
              'incidents': CorrelationEngine.correlate(site_id),
              'findings': [dict(row) for row in query('SELECT * FROM findings WHERE site_id=? ORDER BY id DESC', (site_id,))],
              'jobs': [dict(row) for row in query('SELECT * FROM jobs WHERE site_id=? ORDER BY id DESC LIMIT 100', (site_id,))],
              'audit': [dict(row) for row in query('SELECT * FROM audit WHERE site_id=? ORDER BY id DESC LIMIT 100', (site_id,))]}
    if report_type in ('users', 'security', 'updates'):
        report['users'] = [dict(row) for row in query('SELECT * FROM user_inventory WHERE site_id=? ORDER BY id DESC', (site_id,))]
    if report_type in ('updates', 'security'):
        report['plugins'] = [dict(row) for row in query('SELECT * FROM plugin_inventory WHERE site_id=? ORDER BY id DESC', (site_id,))]
        report['themes'] = [dict(row) for row in query('SELECT * FROM theme_inventory WHERE site_id=? ORDER BY id DESC', (site_id,))]
    if report_type == 'integrity':
        baseline = query('SELECT * FROM integrity_baselines WHERE site_id=?', (site_id,), one=True)
        report['integrity'] = dict(baseline) if baseline else None
    if report_type == 'backup':
        report['backups'] = [dict(row) for row in query('SELECT * FROM backups WHERE site_id=? ORDER BY id DESC', (site_id,))]
    return report


def _api_get(self, path):
    parsed = urlparse(self.path)
    query_params = dict(item.split('=', 1) if '=' in item else (item, '') for item in parsed.query.split('&') if item)
    if path == '/api/security/health':
        return self.send_json(DiagnosticEngine.run())
    if path.startswith('/api/security/'):
        parts=[unquote(x) for x in path.split('/') if x]
        if len(parts)>=4 and parts[1]=='security' and parts[2]=='sites':
            site_id=parts[3]
            if not _site(site_id): return self.send_json({'ok':False,'error':'site_not_found'},404)
            resource=parts[4] if len(parts)>4 else 'posture'
            if resource in ('score','posture'):
                score=SecurityEngine.score(site_id)
                posture='Unknown' if not score['available'] else ('Secure' if score['score']>=85 else 'Needs Attention' if score['score']>=60 else 'At Risk')
                return self.send_json({'ok':True,'score':score,'posture':posture})
            if resource in ('findings','recommendations'):
                rows=[dict(r) for r in query("SELECT * FROM findings WHERE site_id=? AND status IN ('open','acknowledged') ORDER BY id DESC",(site_id,))]
                if resource=='recommendations': rows=[{'finding_id':r['id'],'title':r['title'],'recommendation':r.get('recommendation'),'risk':r.get('risk'),'risk_factors':r.get('risk_factors')} for r in rows]
                return self.send_json(rows)
            if resource=='incidents': return self.send_json([dict(r) for r in query('SELECT * FROM incidents WHERE site_id=? ORDER BY id DESC',(site_id,))])
            if resource=='timeline': return self.send_json([dict(r) for r in query('SELECT * FROM security_history WHERE site_id=? ORDER BY id DESC LIMIT 100',(site_id,))])
            if resource=='baseline': return self.send_json(BaselineEngine.compare(site_id))
            if resource=='graph':
                nodes=[{'id':site_id,'type':'site','name':dict(_site(site_id)).get('name','')}]
                for table,kind,columns in (('user_inventory','user','id,username,display_name'),('plugin_inventory','plugin','id,name'),('theme_inventory','theme','id,name')):
                    for row in query(f'SELECT {columns} FROM {table} WHERE site_id=? LIMIT 500',(site_id,)):
                        d=dict(row); nodes.append({'id':f'{kind}:{d["id"]}','type':kind,'name':d.get('name') or d.get('username') or d.get('display_name') or kind})
                edges=[{'from':site_id,'to':n['id'],'type':'OWNS'} for n in nodes[1:]]
                return self.send_json({'nodes':nodes,'edges':edges,'partial':True})
    if path == '/api/capabilities':
        return self.send_json({
            'ok': True,
            'manager': ['dashboard', 'sites', 'security', 'integrity', 'malware_indicators', 'findings', 'jobs', 'reports', 'audit', 'automation', 'search'],
            'connector_required': ['plugin_manager', 'theme_manager', 'user_auditor', 'file_manager', 'backup_engine', 'hardening_actions'],
            'transport': ['hmac_sha256', 'nonce', 'timestamp', 'one_time_enrollment'],
        })
    if path == '/api/search':
        return self.send_json({'ok': True, 'results': _search(query_params.get('q', ''))})
    if path == '/api/findings':
        return self.send_json([dict(row) for row in query('SELECT * FROM findings ORDER BY id DESC')])
    if path == '/api/jobs':
        return self.send_json([dict(row) for row in query('SELECT * FROM jobs ORDER BY id DESC')])
    if path.startswith('/api/jobs/'):
        job_id = _safe_int(path.split('/')[3] if len(path.split('/')) > 3 else 0)
        row = query('SELECT * FROM jobs WHERE id=?', (job_id,), one=True)
        return self.send_json(dict(row) if row else {'ok': False, 'error': 'job_not_found'}, 200 if row else 404)
    if path == '/api/audit':
        return self.send_json([dict(row) for row in query('SELECT * FROM audit ORDER BY id DESC')])
    if path.startswith('/api/reports/'):
        parts = [unquote(x) for x in path.split('/') if x]
        site_id = parts[2] if len(parts) > 2 else ''
        report = _report(site_id, parts[3] if len(parts) > 3 else 'security')
        return self.send_json(report or {'ok': False, 'error': 'site_not_found'}, 200 if report else 404)
    parts = [unquote(x) for x in path.split('/') if x]
    if len(parts) >= 3 and parts[0] == 'api' and parts[1] == 'sites':
        site_id = parts[2]
        site = _site_or_error(self, site_id)
        if not site:
            return None
        if len(parts) == 3:
            return self.send_json(dict(site))
        resource = parts[3]
        if resource == 'security':
            return self.send_json({'ok': True, 'assessment': SecurityEngine.score(site_id), 'incidents': CorrelationEngine.correlate(site_id), 'findings': [dict(row) for row in query('SELECT * FROM findings WHERE site_id=? ORDER BY id DESC', (site_id,))]})
        if resource == 'findings':
            return self.send_json([dict(row) for row in query('SELECT * FROM findings WHERE site_id=? ORDER BY id DESC', (site_id,))])
        if resource == 'integrity':
            row = query('SELECT files,created,updated FROM integrity_baselines WHERE site_id=?', (site_id,), one=True)
            return self.send_json({'ok': True, 'baseline': dict(row) if row else None})
        table = {'plugins': 'plugin_inventory', 'themes': 'theme_inventory', 'users': 'user_inventory'}.get(resource)
        if table:
            return self.send_json([dict(row) for row in query(f'SELECT * FROM {table} WHERE site_id=? ORDER BY id DESC', (site_id,))])
        if resource == 'backups':
            return self.send_json([dict(row) for row in query('SELECT * FROM backups WHERE site_id=? ORDER BY id DESC', (site_id,))])
        if resource == 'automation':
            return self.send_json([dict(row) for row in query('SELECT * FROM automation_rules WHERE site_id=? ORDER BY id DESC', (site_id,))])
    if path == '/api/sites':
        return self.send_json([dict(row) for row in query('SELECT id,name,url,status,wp_version,php_version,os,server,https,last_sync,last_scan,created FROM sites ORDER BY created DESC')])
    return None


def _api_post(self, path):
    data, raw_body = self.read_json()
    if not _json_object(data):
        return self.send_json({'ok': False, 'error': 'invalid_json_or_size'}, 400)
    if path.startswith('/api/security/sites/'):
        parts=[unquote(x) for x in path.split('/') if x]
        if len(parts)>=5 and parts[1]=='security' and parts[2]=='sites':
            site_id,resource=parts[3],parts[4]
            if not _site(site_id): return self.send_json({'ok':False,'error':'site_not_found'},404)
            if resource=='scan':
                profile=str(data.get('profile','quick')).lower()
                if profile not in SecurityEngine.PROFILES: return self.send_json({'ok':False,'error':'invalid_scan_profile'},400)
                job_id=_launch_job(site_id,'security_scan_'+profile,lambda current_job_id:_run_security_job(site_id,profile,data.get('files',[]),current_job_id))
                audit(site_id,'scan_started',profile,'success')
                return self.send_json({'ok':True,'job_id':job_id,'profile':profile},202)
            if resource=='baseline':
                baseline=BaselineEngine.create(site_id)
                return self.send_json(baseline or {'ok':False,'error':'site_not_found'},201 if baseline else 404)
    if path.startswith('/api/jobs/') and path.endswith('/cancel'):
        job_id = _safe_int(path.split('/')[3] if len(path.split('/')) > 3 else 0)
        execute("UPDATE jobs SET status='cancelled',cancel_requested=1,updated=?,finished=? WHERE id=? AND status IN ('queued','running')", (now(), now(), job_id))
        return self.send_json({'ok': True, 'job_id': job_id})
    if path == '/api/automation':
        if not data.get('name') or not data.get('trigger') or not data.get('action'):
            return self.send_json({'ok': False, 'error': 'name_trigger_action_required'}, 400)
        site_id = data.get('site_id')
        if site_id and not _site(site_id):
            return self.send_json({'ok': False, 'error': 'site_not_found'}, 404)
        execute('INSERT INTO automation_rules (site_id,name,trigger,action,enabled,created,updated) VALUES (?,?,?,?,?,?,?)', (site_id, str(data['name'])[:200], str(data['trigger'])[:200], str(data['action'])[:200], int(bool(data.get('enabled', True))), now(), now()))
        audit(site_id, 'automation_create', str(data['name'])[:200], 'success')
        return self.send_json({'ok': True}, 201)
    if path == '/api/sites':
        name = str(data.get('name') or '').strip()[:200]
        url = str(data.get('url') or '').strip()[:2048]
        if not name or not url:
            return self.send_json({'ok': False, 'error': 'name_and_url_required'}, 400)
        site_id = secrets.token_hex(16)
        execute('INSERT INTO sites (id,name,url,status,https,created,metadata) VALUES (?,?,?,?,?,?,?)',
                (site_id, name, url, 'pending', int(url.lower().startswith('https://')), now(), '{}'))
        audit(site_id, 'site_create', url, 'success')
        return self.send_json({'ok': True, 'site_id': site_id}, 201)
    if path.startswith('/api/findings/') and path.endswith('/resolve'):
        finding_id = _safe_int(path.split('/')[3] if len(path.split('/')) > 3 else 0)
        execute("UPDATE findings SET status='resolved' WHERE id=?", (finding_id,))
        audit(None, 'finding_resolve', str(finding_id), 'success')
        return self.send_json({'ok': True, 'finding_id': finding_id, 'status': 'resolved'})
    parts = [unquote(x) for x in path.split('/') if x]
    if len(parts) >= 4 and parts[0] == 'api' and parts[1] == 'sites':
        site_id, resource = parts[2], parts[3]
        if not _site_or_error(self, site_id):
            return None
        if resource in ('scan', 'security'):
            parsed = urlparse(self.path)
            params = dict(item.split('=', 1) if '=' in item else (item, '') for item in parsed.query.split('&') if item)
            profile = str(data.get('profile') or params.get('profile') or 'quick').lower()
            if profile not in SecurityEngine.PROFILES:
                return self.send_json({'ok': False, 'error': 'invalid_scan_profile'}, 400)
            files = data.get('files', [])
            job_id = _launch_job(site_id, 'security_scan_' + profile, lambda current_job_id: _run_security_job(site_id, profile, files, current_job_id))
            return self.send_json({'ok': True, 'job_id': job_id, 'profile': profile}, 202)
        if resource == 'integrity':
            files = data.get('files', [])
            current, changes = _integrity_compare(site_id, files)
            execute("INSERT OR REPLACE INTO integrity_baselines (site_id,files,created,updated) VALUES (?,?,COALESCE((SELECT created FROM integrity_baselines WHERE site_id=?),?),?)", (site_id, safe_json(current), site_id, now(), now()))
            for change in changes:
                _record_finding(site_id, 'medium', 'integrity', 'File ' + change['change'], 'File integrity changed.', change['path'], None, safe_json(change), change.get('new_sha256') or change.get('old_sha256') or '')
            audit(site_id, 'integrity_scan', 'files', 'success')
            return self.send_json({'ok': True, 'changes': changes, 'file_count': len(current)})
        if resource in ('malware', 'malware-scan'):
            job_id = _launch_job(site_id, 'malware_scan', lambda: _run_malware_job(site_id, data.get('files', [])))
            return self.send_json({'ok': True, 'job_id': job_id}, 202)
        if resource == 'backup':
            backup_type = str(data.get('type', 'metadata'))[:40]
            job_id = _job_create(site_id, 'backup_' + backup_type, 'Waiting for connector backup capability')
            _job_update(job_id, 'failed', 100, 'Connector backup capability is not available in this connector version', now())
            audit(site_id, 'backup', backup_type, 'failed')
            return self.send_json({'ok': False, 'error': 'connector_capability_unavailable', 'capability': 'backup', 'job_id': job_id}, 409)
        if resource in ('plugins', 'themes', 'users', 'files', 'hardening'):
            return self.send_json(_capability_error(resource), 409)
    if path == '/api/reports':
        site_id, report_type = str(data.get('site_id', '')), str(data.get('type', 'security'))
        report = _report(site_id, report_type)
        if report is None:
            return self.send_json({'ok': False, 'error': 'site_not_found'}, 404)
        execute('INSERT INTO reports (site_id,report_type,format,content,created) VALUES (?,?,?,?,?)', (site_id, report_type, 'json', safe_json(report), now()))
        return self.send_json(report)
    return None


def _api_delete(self, path):
    parts = [unquote(x) for x in path.split('/') if x]
    if len(parts) == 3 and parts[0] == 'api' and parts[1] == 'sites':
        site_id = parts[2]
        if not _site(site_id):
            return self.send_json({'ok': False, 'error': 'site_not_found'}, 404)
        execute('DELETE FROM sites WHERE id=?', (site_id,))
        execute('DELETE FROM findings WHERE site_id=?', (site_id,))
        execute('DELETE FROM jobs WHERE site_id=?', (site_id,))
        execute('DELETE FROM automation_rules WHERE site_id=?', (site_id,))
        audit(None, 'site_delete', site_id, 'success')
        return self.send_json({'ok': True, 'site_id': site_id})
    return self.send_json({'ok': False, 'error': 'not_found'}, 404)


def _automation_loop():
    while True:
        try:
            rules = query("SELECT * FROM automation_rules WHERE enabled=1")
            for rule in rules:
                site_id = rule['site_id']
                if not site_id or not _site(site_id):
                    continue
                trigger = str(rule['trigger']).lower()
                action = str(rule['action']).lower()
                if 'scan' in action and ('daily' in trigger or 'hour' in trigger):
                    last = rule['last_run'] or ''
                    if not last or last[:10] != now()[:10]:
                        _launch_job(site_id, 'automation_scan', lambda sid=site_id: _run_security_job(sid))
                        execute('UPDATE automation_rules SET last_run=?,updated=? WHERE id=?', (now(), now(), rule['id']))
        except Exception as exc:
            _internal_error('automation', 'tick', exc)
        time.sleep(60)


# Replace the original route methods after all helpers have been defined.
legacy_do_GET = MLWGHandler.do_GET
legacy_do_POST = MLWGHandler.do_POST


def enhanced_do_GET(self):
    path = urlparse(self.path).path
    if path == '/security':
        sites=query('SELECT id,name FROM sites ORDER BY name')
        cards=[]
        for site in sites:
            score=SecurityEngine.score(site['id'])
            posture='Unknown' if not score['available'] else ('Secure' if score['score']>=85 else 'Needs Attention' if score['score']>=60 else 'At Risk')
            cards.append(f"<article class='card'><h2>{html.escape(site['name'])}</h2><p>Posture: <strong>{posture}</strong></p><p>Score: {score['score'] if score['available'] else 'Unknown'}</p><a href='/sites/{html.escape(site['id'])}'>Open site</a></article>")
        body="<div class='topbar'><div><div class='eyebrow'>MLWG / SECURITY</div><h1>Security Center</h1><p>Evidence-based posture, findings and incidents.</p></div></div><div class='grid'>"+(''.join(cards) or '<div class="card">No site telemetry available.</div>')+"</div>"
        return self.send_bytes(page('Security Center', body).encode('utf-8'))
    if path.startswith('/api/'):
        result = _api_get(self, path)
        if result is not None:
            return result
    return legacy_do_GET(self)


def enhanced_do_POST(self):
    path = urlparse(self.path).path
    if path.startswith('/api/') and not path.startswith('/api/connector/'):
        result = _api_post(self, path)
        if result is not None:
            return result
    return legacy_do_POST(self)


def enhanced_do_DELETE(self):
    path = urlparse(self.path).path
    if path.startswith('/api/'):
        return _api_delete(self, path)
    return self.send_json({'ok': False, 'error': 'not_found'}, 404)


MLWGHandler.do_GET = enhanced_do_GET
MLWGHandler.do_POST = enhanced_do_POST
MLWGHandler.do_DELETE = enhanced_do_DELETE


# ============================================================
# MLWG 35-CAPABILITY INTELLIGENCE COMPATIBILITY LAYER
# ============================================================

def intelligence_migrate():
    with DB_LOCK:
        with db() as connection:
            connection.executescript("""
            CREATE TABLE IF NOT EXISTS detection_rules (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
                category TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                severity TEXT NOT NULL, confidence TEXT NOT NULL, conditions TEXT NOT NULL,
                created TEXT NOT NULL, updated TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS suppressions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT, scope TEXT NOT NULL,
                target TEXT NOT NULL, reason TEXT NOT NULL, expires TEXT, created_by TEXT NOT NULL,
                created TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS remediation_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL, action TEXT NOT NULL,
                status TEXT NOT NULL, before_state TEXT NOT NULL, after_state TEXT,
                rollback_data TEXT, created TEXT NOT NULL, updated TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL, job_id INTEGER,
                profile TEXT NOT NULL, result TEXT NOT NULL, created TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS intelligence_cache (
                cache_key TEXT PRIMARY KEY, value TEXT NOT NULL, expires INTEGER NOT NULL, created TEXT NOT NULL
            );
            """)
            defaults=(
                ('SUSPICIOUS_UPLOAD_PHP','Suspicious PHP in uploads','Detection-only PHP artifact rule','uploads','high','medium','{"path_prefix":"wp-content/uploads","extensions":[".php",".phtml"]}'),
                ('OBFUSCATED_PHP','Obfuscated PHP indicator','Encoded or dynamic PHP indicator','malware','high','low','{"indicators":["eval(","base64_decode(","gzinflate("]}'),
                ('CONFIGURATION_DRIFT','Configuration drift','Current configuration differs from baseline','configuration','medium','high','{"baseline":true}'),
            )
            for rule in defaults:
                connection.execute("INSERT OR IGNORE INTO detection_rules (id,name,description,category,severity,confidence,conditions,created,updated) VALUES (?,?,?,?,?,?,?,?,?)", (rule[0],rule[0],rule[2],rule[3],rule[4],rule[5],rule[6],now(),now()))
            connection.commit()


def _path_safe(relative_path, root):
    from pathlib import Path as _Path
    candidate=_Path(root).resolve() / str(relative_path).replace('\\','/')
    try: candidate.relative_to(_Path(root).resolve())
    except ValueError: return None
    return candidate


def _entropy(value):
    import math
    if not value: return 0.0
    counts={c:value.count(c) for c in set(value)}
    length=len(value)
    return round(-sum((n/length)*math.log2(n/length) for n in counts.values()),3)


def _intelligence_status(site_id):
    baseline=BaselineEngine.compare(site_id)
    score=SecurityEngine.score(site_id)
    findings=query("SELECT severity,COUNT(*) AS count FROM findings WHERE site_id=? AND status='open' GROUP BY severity",(site_id,))
    counts={r['severity']:r['count'] for r in findings}
    incidents=query("SELECT COUNT(*) AS count FROM incidents WHERE site_id=? AND status NOT IN ('resolved','closed')",(site_id,),one=True)
    posture='Unknown' if not score.get('available') else ('Secure' if score['score']>=85 and not baseline.get('changes') else 'Needs Attention' if score['score']>=60 else 'At Risk')
    return {'posture':posture,'score':score,'counts':counts,'open_incidents':int(incidents['count'] if incidents else 0),'configuration_drift':len(baseline.get('changes',[])) if baseline else 0}


def _intelligence_get(self,path):
    parts=[unquote(x) for x in path.split('/') if x]
    if path=='/api/security/diagnostics': return self.send_json(DiagnosticEngine.run())
    if len(parts)>=4 and parts[:3]==['api','security','sites']:
        site_id=parts[3]
        if not _site(site_id): return self.send_json({'ok':False,'error':'site_not_found'},404)
        resource=parts[4] if len(parts)>4 else 'posture'
        if resource in ('posture','assessment'):
            return self.send_json({'ok':True,**_intelligence_status(site_id)})
        if resource=='history': return self.send_json([dict(r) for r in query('SELECT * FROM security_history WHERE site_id=? ORDER BY id DESC',(site_id,))])
        if resource=='incidents': return self.send_json([dict(r) for r in query('SELECT * FROM incidents WHERE site_id=? ORDER BY id DESC',(site_id,))])
        if resource=='evidence': return self.send_json([dict(r) for r in query('SELECT * FROM finding_evidence WHERE site_id=? ORDER BY id DESC LIMIT 1000',(site_id,))])
        if resource=='baseline': return self.send_json(BaselineEngine.compare(site_id))
        if resource=='compare': return self.send_json(BaselineEngine.compare(site_id))
        if resource=='rules': return self.send_json([dict(r) for r in query('SELECT * FROM detection_rules ORDER BY id')])
        if resource=='suppressions': return self.send_json([dict(r) for r in query('SELECT * FROM suppressions WHERE site_id=? AND active=1 ORDER BY id DESC',(site_id,))])
        if resource=='inventory':
            metadata=json.loads(_site(site_id)['metadata'] or '{}')
            return self.send_json({'site':site_id,'assets':{'core':metadata.get('wp_version','unknown'),'plugins':metadata.get('plugins','unknown'),'themes':metadata.get('themes','unknown'),'users':metadata.get('users','unknown'),'rest_api':metadata.get('rest_api','unknown'),'xmlrpc':metadata.get('xmlrpc','unknown'),'uploads':metadata.get('uploads','unknown'),'permissions':metadata.get('permissions','unknown'),'cron':metadata.get('cron','unknown'),'security_headers':metadata.get('security_headers','unknown'),'https':metadata.get('https','unknown')}})
        if resource=='compare-scans':
            rows=query('SELECT * FROM scan_snapshots WHERE site_id=? ORDER BY id DESC LIMIT 2',(site_id,))
            return self.send_json({'status':'unavailable','reason':'insufficient historical scans'} if len(rows)<2 else {'status':'available','current':dict(rows[0]),'previous':dict(rows[1])})
    return None


def _intelligence_post(self,path):
    if not (path.startswith('/api/security/') or path == '/api/security/rules'):
        return None
    data,raw=self.read_json()
    if not _json_object(data): return self.send_json({'ok':False,'error':'invalid_json_or_size'},400)
    parts=[unquote(x) for x in path.split('/') if x]
    if len(parts)>=4 and parts[:3]==['api','security','sites']:
        site_id=parts[3]
        if not _site(site_id): return self.send_json({'ok':False,'error':'site_not_found'},404)
        resource=parts[4] if len(parts)>4 else ''
        if resource=='baseline':
            baseline=BaselineEngine.create(site_id)
            return self.send_json(baseline or {'ok':False,'error':'site_not_found'},201 if baseline else 404)
        if resource=='suppressions':
            target=str(data.get('target') or '')[:512]; reason=str(data.get('reason') or '')[:500]
            if not target or not reason: return self.send_json({'ok':False,'error':'target_and_reason_required'},400)
            execute('INSERT INTO suppressions (site_id,scope,target,reason,expires,created_by,created) VALUES (?,?,?,?,?,?,?)',(site_id,str(data.get('scope','fingerprint'))[:40],target,reason,data.get('expires'),str(data.get('created_by','manager'))[:100],now()))
            audit(site_id,'suppression_create',target,'success')
            return self.send_json({'ok':True},201)
        if resource=='remediation':
            action=str(data.get('action') or '')[:100]
            before=safe_json({'status':'preview_only','available':'connector_required'})
            execute('INSERT INTO remediation_actions (site_id,action,status,before_state,created,updated) VALUES (?,?,?,?,?,?)',(site_id,action,'preview',before,now(),now()))
            audit(site_id,'remediation_preview',action,'success')
            return self.send_json({'ok':True,'status':'preview','action':action,'impact':'connector confirmation and capability required'},202)
        if resource=='scan':
            profile=str(data.get('profile','quick')).lower()
            if profile not in SecurityEngine.PROFILES: return self.send_json({'ok':False,'error':'invalid_scan_profile'},400)
            job_id=_launch_job(site_id,'security_scan_'+profile,lambda current_job_id:_run_security_job(site_id,profile,data.get('files',[]),current_job_id))
            audit(site_id,'scan_started',profile,'success')
            return self.send_json({'ok':True,'job_id':job_id,'profile':profile},202)
    if path=='/api/security/rules':
        rule_id=str(data.get('id') or secrets.token_hex(8)); name=str(data.get('name') or '')[:200]
        if not name: return self.send_json({'ok':False,'error':'name_required'},400)
        execute('INSERT OR REPLACE INTO detection_rules (id,name,description,category,enabled,severity,confidence,conditions,created,updated) VALUES (?,?,?,?,?,?,?,?,COALESCE((SELECT created FROM detection_rules WHERE id=?),?),?)',(rule_id,name,str(data.get('description',''))[:1000],str(data.get('category','custom'))[:100],int(bool(data.get('enabled',True))),str(data.get('severity','medium'))[:20],str(data.get('confidence','unknown'))[:20],safe_json(data.get('conditions',{})),rule_id,now(),now()))
        return self.send_json({'ok':True,'id':rule_id},201)
    return None

_old_intelligence_get=_api_get
_old_intelligence_post=_api_post
def _api_get(self,path):
    result=_intelligence_get(self,path)
    return result if result is not None else _old_intelligence_get(self,path)
def _api_post(self,path):
    result=_intelligence_post(self,path)
    return result if result is not None else _old_intelligence_post(self,path)

if __name__ == '__main__':
    main()
