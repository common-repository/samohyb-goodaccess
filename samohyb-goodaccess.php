<?php
/*
* Plugin Name: Samohyb GoodAccess
* Description: This plugin hides your WordPress administration side of the public internet but makes it accessible from any location with GoodAccess App.
* Version: 1.0
* Author: Samohyb s.r.o.
* Author URI: https://samohyb.com
* License: GPL3
* Text Domain: samohyb-goodaccess
*/

if (!defined('ABSPATH')) {
    die('Direct access not allowed!');
}


class SamohybGoodAccess
{
    const API_VERSION = 'v1';
    const PLUGIN_TITLE = 'Samohyb GoodAccess';
    const TEXT_DOMAIN = 'samohyb-goodaccess';

    const OPTION_NAME_API_URL = 'samohyb_ga_api_url';
    const OPTION_NAME_ACCESS_TOKEN = 'samohyb_ga_access_token';
    const OPTION_NAME_REFRESH_TOKEN = 'samohyb_ga_refresh_token';
    const OPTION_NAME_TOKEN = 'samohyb_ga_token';
    const CACHE_LAST_API_RESPONSE = 'samohyb_ga_access_response';
    const CACHE_WHITELIST = 'samohyb_ga_access_whitelist';

    private $activationCode;

    private $apiUrl;
    private $accessToken;
    private $refreshToken;
    private $token;
    private $whitelist;

    private $showModalWarning = false;
    private $apiResponse = true;

    public function __construct()
    {
        add_filter(sprintf('plugin_action_links_%s', plugin_basename(__FILE__)), [$this, 'actionLinks']);

        $this->apiUrl = get_option(self::OPTION_NAME_API_URL);
        $this->accessToken = get_option(self::OPTION_NAME_ACCESS_TOKEN);
        $this->refreshToken = get_option(self::OPTION_NAME_REFRESH_TOKEN);
        $this->token = get_option(self::OPTION_NAME_TOKEN);

        $getAction = filter_input(INPUT_GET, 'action', FILTER_SANITIZE_SPECIAL_CHARS) ?? null;
        $getToken = filter_input(INPUT_GET, 'token', FILTER_SANITIZE_SPECIAL_CHARS) ?? null;
        $postActivationCode = filter_input(INPUT_POST, 'activationCode', FILTER_SANITIZE_SPECIAL_CHARS) ?? null;

        if ($getAction === 'disable' && $getToken === $this->token) {
            $this->disableProtection();
        } elseif ($postActivationCode && !$this->accessToken) {
            $this->activationCode = $postActivationCode;
            $this->activateProtection();
        } elseif ($this->accessToken) {
            add_action('login_init', [$this, 'check']);
            add_action('admin_init', [$this, 'check']);
        }

        add_action('admin_menu', [$this, 'adminMenu']);
    }

    private function getWhitelist()
    {
        $lastApiResponse = get_transient(self::CACHE_LAST_API_RESPONSE);
        $whitelist = get_transient(self::CACHE_WHITELIST);

        if ($this->apiUrl && $this->accessToken && $lastApiResponse < time() - 60) {
            $whitelistApiUrl = sprintf('%s%s/get-ip-list', $this->apiUrl, self::API_VERSION);
            $loadWhitelistFromApi = wp_remote_post(esc_url_raw($whitelistApiUrl), ['timeout' => 5, 'headers' => ['Security' => sprintf('Bearer %s', $this->accessToken)]]);
            $loadWhitelistFromApiResponseCode = $loadWhitelistFromApi['response']['code'] ?? null;
            $loadWhitelistFromApiBody = $loadWhitelistFromApi['body'] ?? null;

            if ($loadWhitelistFromApiBody && (int)$loadWhitelistFromApiResponseCode === 200) {
                $whitelist = $loadWhitelistFromApiBody;
                set_transient(self::CACHE_WHITELIST, $whitelist);
                set_transient(self::CACHE_LAST_API_RESPONSE, time());
            } elseif ((int)$loadWhitelistFromApiResponseCode === 401 && $this->refreshToken) {
                $this->getNewTokens();
            } elseif ((int)$loadWhitelistFromApiResponseCode === 500 || !$loadWhitelistFromApiResponseCode) {
                $this->apiResponse = false;
            }
        }

        $this->whitelist = json_decode($whitelist, 1);
    }

    public function getNewTokens()
    {
        $tokenApiUrl = sprintf('%s%s/token', $this->apiUrl, self::API_VERSION);
        $newTokens = wp_remote_post(esc_url_raw($tokenApiUrl), ['timeout' => 5, 'body' => ['grant_type' => 'refresh_token', 'refresh_token' => $this->refreshToken]]);
        $response = $newTokens['response']['code'] ?? null;

        if ((int)$response === 200) {
            $this->saveTokens($newTokens['body']);
        } else {
            $this->disableProtection();
        }
    }

    private function activateProtection()
    {
        $parsedActivationCode = explode(';', base64_decode($this->activationCode));

        if (count($parsedActivationCode) === 3 && wp_http_validate_url(esc_url_raw($parsedActivationCode[0]))) {
            $tokenApiUrl = sprintf('%s%s/token', $parsedActivationCode[0], self::API_VERSION);
            $initTokens = wp_remote_post(esc_url_raw($tokenApiUrl), ['timeout' => 5, 'body' => ['grant_type' => 'client_credentials', 'client_id' => $parsedActivationCode[1], 'client_secret' => $parsedActivationCode[2]]]);

            $response = $initTokens['response']['code'] ?? null;
            if ((int)$response === 200) {
                add_option(self::OPTION_NAME_API_URL, $parsedActivationCode[0]);
                $this->apiUrl = $parsedActivationCode[0];
                $this->saveTokens($initTokens['body']);
            }
        }

        if ($this->blockCurrentUser()) {
            $this->showModalWarning = true;
        }
    }

    private function saveTokens($responseBody)
    {
        $tokens = json_decode($responseBody, 1);
        $accessToken = $tokens['access_token'] ?? null;
        $refreshToken = $tokens['refresh_token'] ?? null;
        $token = md5(time());

        if ($this->accessToken) {
            update_option(self::OPTION_NAME_ACCESS_TOKEN, $accessToken);
        } else {
            add_option(self::OPTION_NAME_ACCESS_TOKEN, $accessToken);
        }

        if ($this->refreshToken) {
            update_option(self::OPTION_NAME_REFRESH_TOKEN, $refreshToken);
        } else {
            add_option(self::OPTION_NAME_REFRESH_TOKEN, $refreshToken);
        }

        if (!$this->token) {
            add_option(self::OPTION_NAME_TOKEN, $token);
        }

        $this->accessToken = $accessToken;
        $this->token = $token;

        $this->getWhitelist();
    }

    private function getUserIp()
    {
        $ip = null;
        $ip_sources = ['REMOTE_ADDR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP'];

        foreach ($ip_sources as $ip_source) {
            if (isset($_SERVER[$ip_source])) {
                $ip = filter_var($_SERVER[$ip_source], FILTER_VALIDATE_IP);
            }
        }

        return $ip;
    }

    private function disableProtection()
    {
        delete_transient(self::CACHE_WHITELIST);
        delete_transient(self::CACHE_LAST_API_RESPONSE);

        delete_option(self::OPTION_NAME_API_URL);
        delete_option(self::OPTION_NAME_ACCESS_TOKEN);
        delete_option(self::OPTION_NAME_REFRESH_TOKEN);
        delete_option(self::OPTION_NAME_TOKEN);

        $this->accessToken = null;
    }

    public function check()
    {
        $this->getWhitelist();

        if ($this->blockCurrentUser()) {
            wp_die(sprintf('<p><strong>%s</strong> %s</p>', __('Error:'), __('Access denied!')), __('Access denied!'), ['response' => 403]);
        }
    }

    public function blockCurrentUser()
    {
        $whitelist = $this->whitelist['ip-list'] ?? [];
        $ips = array_column($whitelist, 'ip');

        if (is_array($this->whitelist) && !in_array($this->getUserIp(), $ips) && count($ips)) {
            return true;
        } else {
            return false;
        }
    }

    public function actionLinks($links)
    {
        return array_merge(['settings' => sprintf('<a href="%s">%s</a>', admin_url('options-general.php?page=samohyb-goodaccess-options'), __('Settings'))], $links);
    }

    public function adminMenu()
    {
        add_submenu_page('options-general.php', self::PLUGIN_TITLE, self::PLUGIN_TITLE, 'manage_options', 'samohyb-goodaccess-options', [$this, 'adminSection']);
    }

    public function adminSection()
    {
        add_thickbox();

        $cssName = 'sga.css';
        $cssPath = sprintf('%s%s', plugin_dir_path(__FILE__), $cssName);
        $cssVersion = filemtime($cssPath);

        wp_enqueue_style(sprintf('%s_style', self::TEXT_DOMAIN), sprintf('%s%s', plugin_dir_url(__FILE__), $cssName), [], $cssVersion);

        if (!$this->apiResponse) {
            echo sprintf('<div class="notice notice-error"><p>%s</p></div>', __('No connection to API! Using cache. Please fix the API access!'));
        }

        if (!$this->accessToken) {
            $input = '<p class="text-center"><label for="activationCode">' . __('Activation Code') . '</label><br/><input type="text" id="activationCode" name="activationCode" size="50"></p><br/>';
            $state = '<p class="text-center mb-0">' . __('State') . '</p><p class="text-center state disabled">' . __('NOT PROTECTED') . '</p>';
            $button = '<p class="text-center"><input type="submit" class="button-primary" value="' . __('Activate Protection') . '"></p>';
        } else {
            $input = null;
            $state = '<p class="text-center mb-0">' . __('State') . '</p><p class="text-center state enabled">' . __('PROTECTED') . '</p>';
            $button = '<p class="text-center"><a href="?page=samohyb-goodaccess-options&amp;action=disable&amp;token=' . $this->token . '" class="button-primary">' . __('Deactivate Protection') . '</a></p>';
        }

        if ($this->showModalWarning) {
            $modalFire = '<script type="text/javascript">
                document.addEventListener("DOMContentLoaded", function () {
                    tb_show("' . __('Attention!') . '", "#TB_inline?height=205&amp;width=600&amp;inlineId=sga-modal-warning-1&amp;modal=false");
                });
            </script>';
        } else {
            $modalFire = null;
        }

        echo '<div class="wrap"><h1>' . self::PLUGIN_TITLE . '</h1>
                ' . $this->modalWarningNotOnWhitelist() . $modalFire . '
                <div id="sga-settings" class="sga-container">
                  <div class="side left">
                    <h2>' . __('General settings') . '</h2>
                    <p class="text-center">
                        <img src="' . esc_url(plugins_url('samohyb_logo_square.png', __FILE__)) . '" alt="' . self::PLUGIN_TITLE . ' banner" class="banner banner-normal">
                    </p>
                    <form method="post" action="?page=samohyb-goodaccess-options">' . $input . $state . $button . '</form>
                  </div>
                  <div class="side right">
                    <h2>' . self::PLUGIN_TITLE . '</h2>
                    ' . $this->pluginInfoBoxParagraph() . '
                  </div>
                </div>
              </div>';
    }

    private function modalWarningNotOnWhitelist()
    {
        return '<div id="sga-modal-warning-1" style="display:none;">
                  <div class="modal-content">
                    <h3 class="text-center">' . __('You are not connected using GoodAccess App!') . '</h3><br/>
                    <p class="text-center">' . __('If you activate protection now, you\'ll lost the access to your WordPress administration until you connect via GoodAccess App.') . '</p>
                    <div class="sga-container">
                      <p class="w-40 block"><a href="?page=samohyb-goodaccess-options&amp;action=keep" class="button block text-center">' . __('Activate Protection Anyway') . '</a></p>
                      <p class="w-20">&nbsp;</p>
                      <p class="w-40 text-right"><a href="?page=samohyb-goodaccess-options&amp;action=disable&amp;token=' . $this->token . '" class="button-primary block text-center">' . __('Go Back') . '</a></p>
                    </div>
                  </div>
                </div>';
    }

    private function pluginInfoBoxParagraph()
    {
        return '<p>
                  <strong>' . __('GoodAccess Introduction') . '</strong><br/>
                  ' . __('Samohyb GoodAccess is a cloud-based private gateway for your team to securely access your online back-office systems from home office and remote locations.') . '<br/><br/>
                  <strong>' . __('How does it work?') . '</strong><br/>
                  ' . __('This plugin hides your WordPress administration side of the public internet but makes it accessible from any location with GoodAccess App.') . '<br/>
                  ' . __('Read more at') . ' <a href="https://www.goodaccess.com" target="_blank">https://www.goodaccess.com</a><br/><br/>
                  <strong>' . __('Setup instructions') . '</strong><br/>
                  <ol>
                    <li>' . __('Make sure you are connected using GoodAccess App.') . '</li>
                    <li>' . sprintf(__('Add %s as a new System in GoodAccess Control Panel.'), '<a href="' . get_admin_url() . '" target="_blank">' . get_admin_url() . '</a>') . '</li>
                    <li>' . __('Paste generated Plugin Activation Code here and click Activate Protection.') . '</li>
                  </ol><br/>
                  <strong>' . __('Need help?') . '</strong><br/>
                  ' . __('Contact us at') . ' <a href="https://www.goodaccess.com" target="_blank">https://www.goodaccess.com</a>
                </p>';
    }
}

new SamohybGoodAccess();
