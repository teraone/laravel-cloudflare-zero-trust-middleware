<?php

return [
    /*
     |--------------------------------------------------------------------------
     | Cloudflare Team Name
     |--------------------------------------------------------------------------
     |
     | Here you should define the name of your Cloudflare Team Account.
     | Not sure? Open https://one.dash.cloudflare.com/
     | It will be the name on which you click.
     |
     */
    'cloudflare_team_name' => env('CLOUDFLARE_TEAM_NAME'),

    /*
     |--------------------------------------------------------------------------
     | Cloudflare Zero Trust / Application Audience Tag
     |--------------------------------------------------------------------------
     |
     | Please enter the Application Audience Tag which you want to protect.
     | Open the Zero Trust Dashboard at https://one.dash.cloudflare.com/:
     | Access > Applications: Select "Configure" for your application.
     | On the overview tab, copy the "Application Audience (AUD) Tag".
     |
     */
    'cloudflare_zero_trust_application_audience_tag' => env('CLOUDFLARE_ZERO_TRUST_APPLICATION_AUDIENCE_TAG'),

    /*
     |--------------------------------------------------------------------------
     | Use certificate cache
     |--------------------------------------------------------------------------
     |
     | Should it cache the cloudflare certificates.
     |
     */
    'cache' => true,

    /*
     |--------------------------------------------------------------------------
     | Certificate cache TTL
     |--------------------------------------------------------------------------
     |
     | How long should we cache your public cloudflare certificates? In seconds.
     | The certificate cache will be flushed when a new certificate is detected.
     |
     */
    'cache_ttl' => 60 * 60 * 24,

    /*
     |--------------------------------------------------------------------------
     | Disable the middleware on these environments
     |--------------------------------------------------------------------------
     |
     | Most likely you do not have cloudflare available during development.
     | Use this setting to bypass the middleware for specific environments.
     |
     */
    'disabled_environments' => [
        'local',
    ],
];
