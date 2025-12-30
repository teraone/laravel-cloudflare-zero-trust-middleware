<?php

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Teraone\ZeroTrustMiddleware\ZeroTrustMiddleware;

it('throws if no header given', function (): void {
    $this->get('/')->assertStatus(403);
});

it('throws if invalid header given', function (): void {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => '987654321',
    ])->get('/')->assertStatus(401);
});

it('throws an error if config is missing', function (): void {
    config()->set('cloudflare-zero-trust-middleware.cloudflare_team_name', null);
    config()->set('cloudflare-zero-trust-middleware.cloudflare_zero_trust_application_audience_tag', null);

    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => '987654321',
    ])
        ->getJson('/')
        ->assertStatus(500)
        ->assertSee('Server Error');
});

it('authenticates with correct jws', function (): void {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateJWT('aud', now()->addYear(), $this->jwk_1),
    ])
        ->getJson('/')
        ->assertStatus(200);
});

it('will not authenticate with wrong application aud', function (): void {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateJWT('this is wrong', now()->addYear(), $this->jwk_1),
    ])
        ->getJson('/')
        ->assertStatus(401);
});

it('will not authenticate with expired token', function (): void {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateJWT('aud', now()->subDay(), $this->jwk_1),
    ])
        ->getJson('/')
        ->assertStatus(401);
});

it('will authenticate with second key', function (): void {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateJWT('aud', now()->addHours(5), $this->jwk_2),
    ])
        ->getJson('/')
        ->assertStatus(200);
});

it('will not authenticate with an unknown key', function (): void {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateJwtFromUnknownKey('aud', now()->addHours(5)),
    ])
        ->getJson('/')
        ->assertStatus(401);
});

it('authenticates with valid user JWT containing all required user claims', function (): void {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateUserJWT('aud', now()->addYear(), $this->jwk_1),
    ])
        ->getJson('/')
        ->assertStatus(200);
});

it('authenticates with valid service token JWT', function (): void {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateServiceTokenJWT('aud', now()->addYear(), $this->jwk_1),
    ])
        ->getJson('/')
        ->assertStatus(200);
});

it('rejects user JWT missing sub claim', function (): void {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateUserJWT('aud', now()->addYear(), $this->jwk_1, ['sub' => null]),
    ])
        ->getJson('/')
        ->assertStatus(401);
});

it('rejects user JWT missing nbf claim', function (): void {
    $payload = [
        'aud' => ['aud'],
        'email' => 'user@example.com',
        'exp' => now()->addYear()->timestamp,
        'iat' => now()->subSecond()->timestamp,
        'iss' => 'https://'.config('cloudflare-zero-trust-middleware.cloudflare_team_name').'.cloudflareaccess.com',
        'type' => 'user',
        'identity_nonce' => 'nonce123',
        'sub' => 'user-sub-123',
        'country' => 'US',
    ];

    $algorithmManager = new AlgorithmManager([new RS256]);
    $jwsBuilder = new JWSBuilder($algorithmManager);

    $jws = $jwsBuilder->create()
        ->withPayload(json_encode($payload))
        ->addSignature($this->jwk_1, ['alg' => 'RS256', 'kid' => $this->jwk_1->get('kid')])
        ->build();

    $serializer = new CompactSerializer;
    $token = $serializer->serialize($jws, 0);

    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $token,
    ])
        ->getJson('/')
        ->assertStatus(401);
});

it('rejects user JWT missing country claim', function (): void {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateUserJWT('aud', now()->addYear(), $this->jwk_1, ['country' => null]),
    ])
        ->getJson('/')
        ->assertStatus(401);
});

it('allows service token without nbf claim', function (): void {
    $payload = [
        'aud' => ['aud'],
        'exp' => now()->addYear()->timestamp,
        'iat' => now()->subSecond()->timestamp,
        'iss' => 'https://'.config('cloudflare-zero-trust-middleware.cloudflare_team_name').'.cloudflareaccess.com',
        'type' => 'app',
        'sub' => '',
        'common_name' => 'test-service-token.access',
    ];

    $algorithmManager = new AlgorithmManager([new RS256]);
    $jwsBuilder = new JWSBuilder($algorithmManager);

    $jws = $jwsBuilder->create()
        ->withPayload(json_encode($payload))
        ->addSignature($this->jwk_1, ['alg' => 'RS256', 'kid' => $this->jwk_1->get('kid')])
        ->build();

    $serializer = new CompactSerializer;
    $token = $serializer->serialize($jws, 0);

    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $token,
    ])
        ->getJson('/')
        ->assertStatus(200);
});

it('allows service token without country claim', function (): void {
    $payload = [
        'aud' => ['aud'],
        'exp' => now()->addYear()->timestamp,
        'iat' => now()->subSecond()->timestamp,
        'iss' => 'https://'.config('cloudflare-zero-trust-middleware.cloudflare_team_name').'.cloudflareaccess.com',
        'type' => 'app',
        'sub' => '',
        'common_name' => 'test-service-token.access',
    ];

    $algorithmManager = new AlgorithmManager([new RS256]);
    $jwsBuilder = new JWSBuilder($algorithmManager);

    $jws = $jwsBuilder->create()
        ->withPayload(json_encode($payload))
        ->addSignature($this->jwk_1, ['alg' => 'RS256', 'kid' => $this->jwk_1->get('kid')])
        ->build();

    $serializer = new CompactSerializer;
    $token = $serializer->serialize($jws, 0);

    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $token,
    ])
        ->getJson('/')
        ->assertStatus(200);
});

it('allows service token without email claim', function (): void {
    $payload = [
        'aud' => ['aud'],
        'exp' => now()->addYear()->timestamp,
        'iat' => now()->subSecond()->timestamp,
        'iss' => 'https://'.config('cloudflare-zero-trust-middleware.cloudflare_team_name').'.cloudflareaccess.com',
        'type' => 'app',
        'sub' => '',
        'common_name' => 'test-service-token.access',
    ];

    $algorithmManager = new AlgorithmManager([new RS256]);
    $jwsBuilder = new JWSBuilder($algorithmManager);

    $jws = $jwsBuilder->create()
        ->withPayload(json_encode($payload))
        ->addSignature($this->jwk_1, ['alg' => 'RS256', 'kid' => $this->jwk_1->get('kid')])
        ->build();

    $serializer = new CompactSerializer;
    $token = $serializer->serialize($jws, 0);

    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $token,
    ])
        ->getJson('/')
        ->assertStatus(200);
});

it('allows service token without identity_nonce claim', function (): void {
    $payload = [
        'aud' => ['aud'],
        'exp' => now()->addYear()->timestamp,
        'iat' => now()->subSecond()->timestamp,
        'iss' => 'https://'.config('cloudflare-zero-trust-middleware.cloudflare_team_name').'.cloudflareaccess.com',
        'type' => 'app',
        'sub' => '',
        'common_name' => 'test-service-token.access',
    ];

    $algorithmManager = new AlgorithmManager([new RS256]);
    $jwsBuilder = new JWSBuilder($algorithmManager);

    $jws = $jwsBuilder->create()
        ->withPayload(json_encode($payload))
        ->addSignature($this->jwk_1, ['alg' => 'RS256', 'kid' => $this->jwk_1->get('kid')])
        ->build();

    $serializer = new CompactSerializer;
    $token = $serializer->serialize($jws, 0);

    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $token,
    ])
        ->getJson('/')
        ->assertStatus(200);
});

it('rejects service token missing common_name claim', function (): void {
    $this->withHeaders([
        ZeroTrustMiddleware::CF_ACCESS_JWT_HEADER_NAME => $this->generateServiceTokenJWT('aud', now()->addYear(), $this->jwk_1, ['common_name' => null]),
    ])
        ->getJson('/')
        ->assertStatus(401);
});
