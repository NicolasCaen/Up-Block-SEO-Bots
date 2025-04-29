<?php
/*
Plugin Name: Up Block SEO Bots - Toggle & Whitelist
Description: Bloque les bots SEO sauf IPs autorisées. Option pour activer/désactiver facilement.
Version: 1.0
Author: GEHIN Nicolas
*/

if (!defined('ABSPATH')) {
    exit; // Ne pas accéder directement
}

class Block_SEO_Bots_Plugin {

    private $whitelist_option = 'block_seo_bots_whitelist';
    private $blacklist_option = 'block_seo_bots_blacklist';
    private $enabled_option = 'block_seo_bots_enabled';

    // Liste des User-Agent de bots SEO connus
    private $blocked_agents = [
        'googlebot',
        'bingbot',
        'slurp',         // Yahoo
        'duckduckbot',
        'baiduspider',
        'yandex',
        'sogou',
        'exabot',
        'facebot',
        'ia_archiver'    // Alexa
    ];

    public function __construct() {
        add_action('init', [$this, 'check_bot_access']);
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'settings_init']);
    }

    public function check_bot_access() {
        // Désactive si l’option est désactivée
        if (!get_option($this->enabled_option, true)) {
            return;
        }

        // Ne bloque pas ces requêtes systèmes
        if (
            defined('DOING_AJAX') && DOING_AJAX ||
            defined('DOING_CRON') && DOING_CRON ||
            defined('WP_INSTALLING') || defined('WP_UNINSTALL_PLUGIN')
        ) {
            return;
        }

        $user_agent = !empty($_SERVER['HTTP_USER_AGENT']) ? strtolower($_SERVER['HTTP_USER_AGENT']) : '';
        $remote_ip = $this->get_real_ip();

        // Toujours bloqué → blacklist prioritaire
        if ($this->is_ip_in_blacklist($remote_ip)) {
            $this->deny_access();
        }

        // Vérifie si c'est un bot SEO
        foreach ($this->blocked_agents as $bot) {
            if (strpos($user_agent, $bot) !== false) {
                // Si l'IP n'est pas dans la liste blanche → bloqué
                if (!$this->is_ip_allowed($remote_ip)) {
                    $this->deny_access();
                }
                break;
            }
        }
    }

    private function get_real_ip() {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            return $_SERVER['REMOTE_ADDR'];
        }
        return 'unknown';
    }

    private function is_ip_allowed($ip) {
        $allowed_ips = $this->get_allowed_ips();

        foreach ($allowed_ips as $allowed_ip) {
            $allowed_ip = trim($allowed_ip);
            if (empty($allowed_ip)) continue;

            if (strpos($allowed_ip, '/') !== false) {
                if ($this->ip_in_cidr_range($ip, $allowed_ip)) {
                    return true;
                }
            } else {
                if ($ip === $allowed_ip) {
                    return true;
                }
            }
        }
        return false;
    }

    private function is_ip_in_blacklist($ip) {
        $blacklisted_ips = $this->get_blacklisted_ips();

        foreach ($blacklisted_ips as $blacklisted_ip) {
            $blacklisted_ip = trim($blacklisted_ip);
            if (empty($blacklisted_ip)) continue;

            if (strpos($blacklisted_ip, '/') !== false) {
                if ($this->ip_in_cidr_range($ip, $blacklisted_ip)) {
                    return true;
                }
            } else {
                if ($ip === $blacklisted_ip) {
                    return true;
                }
            }
        }
        return false;
    }

    private function ip_in_cidr_range($ip, $cidr) {
        list($range, $mask) = explode('/', $cidr);
        $ip_binary = @inet_pton($ip);
        $range_binary = @inet_pton($range);

        if ($ip_binary === false || $range_binary === false) {
            return false;
        }

        $mask_int = (int)$mask;
        $ip_unpacked = unpack('A16', $ip_binary);
        $range_unpacked = unpack('A16', $range_binary);

        $ip_num = $this->inet_to_bits($ip_unpacked[1]);
        $range_num = $this->inet_to_bits($range_unpacked[1]);

        return substr($ip_num, 0, $mask_int) === substr($range_num, 0, $mask_int);
    }

    private function inet_to_bits($inet) {
        $binary = '';
        $bits = strlen($inet);
        for ($i = 0; $i < $bits; $i++) {
            $bin = decbin(ord($inet[$i]));
            $binary .= str_pad($bin, 8, '0', STR_PAD_LEFT);
        }
        return $binary;
    }

    private function deny_access() {
        status_header(403);
        header('Content-Type: text/plain');
        die('Accès refusé aux bots SEO.');
    }

    public function get_allowed_ips() {
        $whitelist = get_option($this->whitelist_option, '');
        return array_filter(array_map('trim', explode("\n", $whitelist)));
    }

    public function get_blacklisted_ips() {
        $blacklist = get_option($this->blacklist_option, '');
        return array_filter(array_map('trim', explode("\n", $blacklist)));
    }

    public function add_admin_menu() {
        add_options_page(
            'Blocage des Bots SEO',
            'Blocage des Bots SEO',
            'manage_options',
            'block-seo-bots',
            [$this, 'render_admin_page']
        );
    }

    public function settings_init() {
        register_setting('block_seo_bots', $this->whitelist_option);
        register_setting('block_seo_bots', $this->blacklist_option);
        register_setting('block_seo_bots', $this->enabled_option);
    }

    public function render_admin_page() {
        ?>
        <div class="wrap">
            <h1>Blocage des Bots SEO</h1>
            <form method="post" action="options.php">
                <?php settings_fields('block_seo_bots'); ?>
                <?php do_settings_sections('block_seo_bots'); ?>

                <!-- Activation globale -->
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">Activer le blocage</th>
                        <td>
                            <label>
                                <input type="checkbox" name="<?php echo esc_attr($this->enabled_option); ?>" value="1" <?php checked(1, get_option($this->enabled_option, true)); ?> />
                                Activer le blocage des bots SEO
                            </label>
                            <p class="description">Quand désactivé, aucun bot ne sera bloqué.</p>
                        </td>
                    </tr>

                    <!-- Liste blanche -->
                    <tr valign="top">
                        <th scope="row">Liste blanche des IPs</th>
                        <td>
                            <textarea name="<?php echo esc_attr($this->whitelist_option); ?>" rows="10" cols="50" class="large-text code"><?php
                                echo esc_textarea(get_option($this->whitelist_option, "185.209.23.194\n185.209.23.195"));
                            ?></textarea>
                            <p class="description">Entrez une adresse IP par ligne, avec ou sans masque CIDR (ex: 192.168.0.0/24)</p>
                        </td>
                    </tr>

                    <!-- Liste noire -->
                    <tr valign="top">
                        <th scope="row">Liste noire des IPs</th>
                        <td>
                            <textarea name="<?php echo esc_attr($this->blacklist_option); ?>" rows="10" cols="50" class="large-text code"><?php
                                echo esc_textarea(get_option($this->blacklist_option, ""));
                            ?></textarea>
                            <p class="description">Entrez une adresse IP par ligne, avec ou sans masque CIDR (ex: 8.8.8.0/24)</p>
                        </td>
                    </tr>
                </table>

                <p><strong>Bots SEO bloqués :</strong></p>
                <ul>
                    <li>🔹 Googlebot</li>
                    <li>🔹 Bingbot</li>
                    <li>🔹 Slurp (Yahoo)</li>
                    <li>🔹 DuckDuckBot</li>
                    <li>🔹 BaiduSpider</li>
                    <li>🔹 Yandex Bot</li>
                    <li>🔹 Sogou Spider</li>
                    <li>🔹 ExaBot</li>
                    <li>🔹 Facebook Bot</li>
                    <li>🔹 Alexa Crawler</li>
                </ul>

                <p class="description"><strong>Note :</strong> Aucun bot ne peut indexer ce site, sauf s’il vient d’une IP autorisée. Tu peux désactiver temporairement le blocage ici.</p>

                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
}

new Block_SEO_Bots_Plugin();
