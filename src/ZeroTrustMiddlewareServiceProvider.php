<?php

namespace Teraone\ZeroTrustMiddleware;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class ZeroTrustMiddlewareServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        /*
         * This class is a Package Service Provider
         *
         * More info: https://github.com/spatie/laravel-package-tools
         */
        $package
            ->name('laravel-cloudflare-zero-trust-middleware')
            ->hasConfigFile();
    }

    public function bootingPackage()
    {
        app('router')->aliasMiddleware('cloudflare-zero-trust', ZeroTrustMiddleware::class);
    }
}
