<?php

namespace Teraone\ZeroTrustMiddleware\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \Teraone\ZeroTrustMiddleware\ZeroTrustMiddleware
 */
class ZeroTrustMiddleware extends Facade
{
    protected static function getFacadeAccessor()
    {
        return \Teraone\ZeroTrustMiddleware\ZeroTrustMiddleware::class;
    }
}
