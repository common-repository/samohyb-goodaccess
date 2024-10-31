<?php

if (!defined('WP_UNINSTALL_PLUGIN')) {
    die('Direct access not allowed');
}


/**
 * Class SamohybGoodAccessUninstall
 */
class SamohybGoodAccessUninstall
{
    /**
     * SamohybGoodAccessUninstall constructor.
     */
    public function __construct()
    {
        delete_option('samohyb_ga_api_url');
        delete_option('samohyb_ga_access_token');
        delete_option('samohyb_ga_refresh_token');
        delete_option('samohyb_ga_token');

        delete_transient('samohyb_ga_access_response');
        delete_transient('samohyb_ga_access_whitelist');
    }
}

new SamohybGoodAccessUninstall();
