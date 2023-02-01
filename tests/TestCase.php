<?php

namespace Teraone\ZeroTrustMiddleware\Tests;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Http;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Orchestra\Testbench\TestCase as Orchestra;
use Teraone\ZeroTrustMiddleware\ZeroTrustMiddleware;
use Teraone\ZeroTrustMiddleware\ZeroTrustMiddlewareServiceProvider;

class TestCase extends Orchestra
{
    public JWK $jwk_1;

    public JWK $jwk_2;

    protected function setUp(): void
    {
        parent::setUp();

        Factory::guessFactoryNamesUsing(
            fn (string $modelName) => 'Teraone\\ZeroTrustMiddleware\\Database\\Factories\\'.class_basename($modelName).'Factory'
        );

        app('router')->get('/', function () {
            return 'Hello World!';
        })->middleware(ZeroTrustMiddleware::class);

        $this->jwk_1 = JWKFactory::createRSAKey(
            2048, // Size in bits of the key. We recommend at least 2048 bits.
            [
                'alg' => 'RS256', // This key must only be used with the RSA-OAEP-256 algorithm
                'use' => 'sig',    // This key is used for encryption/decryption operations only,
                'kid' => 'KEY_ID_1',
            ]);

        $this->jwk_2 = JWKFactory::createRSAKey(
            2048, // Size in bits of the key. We recommend at least 2048 bits.
            [
                'alg' => 'RS256', // This key must only be used with the RSA-OAEP-256 algorithm
                'use' => 'sig',    // This key is used for encryption/decryption operations only
                'kid' => 'KEY_ID_2',
            ]);

        $this->fakeHttp();
    }

    protected function getPackageProviders($app)
    {
        return [
            ZeroTrustMiddlewareServiceProvider::class,
        ];
    }

    public function getEnvironmentSetUp($app): void
    {
        config()->set('database.default', 'testing');
        config()->set('cloudflare-zero-trust-middleware.cloudflare_team_name', 'test');
        config()->set('cloudflare-zero-trust-middleware.cloudflare_zero_trust_application_audience_tag', 'aud');
    }

    protected function fakeHttp(): void
    {
        $key_set = new JWKSet([$this->jwk_1->toPublic(), $this->jwk_2->toPublic()]);

        Http::fake([
            '*' => Http::response($key_set->jsonSerialize(), 200),
        ]);
    }

    protected function generateJWT(string $aud, \Carbon\Carbon $expires, JWK $key): string
    {
        $payload = json_encode([
            'aud' => [$aud],
            'email' => 'test@example.com',
            'exp' => $expires->timestamp,
            'iat' => now()->subSecond()->timestamp,
            'nbf' => now()->subSecond()->timestamp,
            'iss' => 'https://'.config('cloudflare-zero-trust-middleware.cloudflare_team_name').'.cloudflareaccess.com',
            'type' => 'app',
            'identity_nonce' => '',
            'sub' => '',
            'country' => 'DE',
        ]);

        // The algorithm manager with the HS256 algorithm.
        $algorithmManager = new AlgorithmManager([
            new RS256,
        ]);

        // We instantiate our JWS Builder.
        $jwsBuilder = new JWSBuilder($algorithmManager);

        $jws = $jwsBuilder->create()
            ->withPayload($payload)
            ->addSignature($key, ['alg' => 'RS256', 'kid' => $key->get('kid')])
            ->build();

        $serializer = new CompactSerializer; // The serializer

        return $serializer->serialize($jws, 0);
    }

    protected function generateJwtFromUnknownKey(string $aud, \Carbon\Carbon $expires)
    {
        $key = JWKFactory::createRSAKey(
            2048, // Size in bits of the key. We recommend at least 2048 bits.
            [
                'alg' => 'RS256', // This key must only be used with the RSA-OAEP-256 algorithm
                'use' => 'sig',    // This key is used for encryption/decryption operations only
                'kid' => 'KEY_ID_1',
            ]);

        return $this->generateJWT($aud, $expires, $key);
    }
}
