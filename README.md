# Laravel Route Middleware For  [Cloudflare Zero Trust](https://developers.cloudflare.com/cloudflare-one/)

[![Latest Version on Packagist](https://img.shields.io/packagist/v/teraone/laravel-cloudflare-zero-trust-middleware.svg?style=flat-square)](https://packagist.org/packages/teraone/laravel-cloudflare-zero-trust-middleware)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/teraone/laravel-cloudflare-zero-trust-middleware/run-tests.yml?branch=master&label=tests&style=flat-square)](https://github.com/teraone/laravel-cloudflare-zero-trust-middleware/actions?query=workflow%3Arun-tests+branch%3Amain)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/teraone/laravel-cloudflare-zero-trust-middleware/fix-php-code-style-issues.yml?branch=master&label=code%20style&style=flat-square)](https://github.com/teraone/laravel-cloudflare-zero-trust-middleware/actions?query=workflow%3A"Fix+PHP+code+style+issues"+branch%3Amaster)
[![Total Downloads](https://img.shields.io/packagist/dt/teraone/laravel-cloudflare-zero-trust-middleware.svg?style=flat-square)](https://packagist.org/packages/teraone/laravel-cloudflare-zero-trust-middleware)





## Installation

You can install the package via composer:

```bash
composer require teraone/laravel-cloudflare-zero-trust-middleware
```


## Configuration

Publish the config file with:

```bash
php artisan vendor:publish --tag="laravel-cloudflare-zero-trust-middleware-config"
```

This is the content of the published config file:

```php
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
```

## Usage

Add the middleware to the routes you want to protect.
```php

// with shorthand alias
Route::get('/protected', function(){ return 'Protected by Cloudflare Zero trust ✅';})
    ->middleware('cloudflare-zero-trust');

// OR: Use Class directly    
Route::get('/also-secure', function(){ return 'Also protected by Cloudflare Zero trust ✅';})
    ->middleware(\Teraone\ZeroTrustMiddleware\ZeroTrustMiddleware\ZeroTrustMiddleware::class);
    
```


## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [Stefan Gotre](https://github.com/teraone)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.


## Support Spatie

[<img src="https://github-ads.s3.eu-central-1.amazonaws.com/laravel-cloudflare-zero-trust-middleware.jpg?t=1" width="419px" />](https://spatie.be/github-ad-click/laravel-cloudflare-zero-trust-middleware)

We invest a lot of resources into creating [best in class open source packages](https://spatie.be/open-source). You can support us by [buying one of our paid products](https://spatie.be/open-source/support-us).

We highly appreciate you sending us a postcard from your hometown, mentioning which of our package(s) you are using. You'll find our address on [our contact page](https://spatie.be/about-us). We publish all received postcards on [our virtual postcard wall](https://spatie.be/open-source/postcards).
