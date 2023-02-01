<?php

use Teraone\ZeroTrustMiddleware\ZeroTrustMiddleware;

it('throws if no header given', function () {
    $this->get('/')->assertStatus(403);
});

it('throws if invalid header given', function () {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => '987654321',
    ])->get('/')->assertStatus(401);
});

it('throws an error if config is missing', function () {
    config()->set('cloudflare-zero-trust-middleware.cloudflare_team_name', null);
    config()->set('cloudflare-zero-trust-middleware.cloudflare_zero_trust_application_audience_tag', null);

    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => '987654321',
    ])
        ->getJson('/')
        ->assertStatus(500)
        ->assertSee('Server Error');
});

it('authenticates with correct jws', function () {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateJWT('aud', now()->addYear(), $this->jwk_1),
    ])
        ->getJson('/')
        ->assertStatus(200);
});

it('will not authenticate with wrong application aud', function () {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateJWT('this is wrong', now()->addYear(), $this->jwk_1),
    ])
        ->getJson('/')
        ->assertStatus(401);
});

it('will not authenticate with expired token', function () {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateJWT('aud', now()->subDay(), $this->jwk_1),
    ])
        ->getJson('/')
        ->assertStatus(401);
});

it('will authenticate with second key', function () {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateJWT('aud', now()->addHours(5), $this->jwk_2),
    ])
        ->getJson('/')
        ->assertStatus(200);
});

it('will not authenticate with an unknown key', function () {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateJwtFromUnknownKey('aud', now()->addHours(5)),
    ])
        ->getJson('/')
        ->assertStatus(401);
});
