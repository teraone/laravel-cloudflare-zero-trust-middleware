<?php

namespace Teraone\ZeroTrustMiddleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use InvalidArgumentException;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\MissingMandatoryClaimException;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Symfony\Component\HttpFoundation\Response;
use Teraone\ZeroTrustMiddleware\Exceptions\InvalidConfigurationException;

class ZeroTrustMiddleware
{
    /**
     * The Header where Cloudflare sends us the JWT Token
     *
     * @see https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/
     */
    final public const CF_ACCESS_JWT_HEADER_NAME = 'cf-access-jwt-assertion';

    public const CERTIFICATE_CACHE_KEY = 'cloudflare-zero-trust-middleware-certificate-cache';

    final public const CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'country', 'identity_nonce', 'type'];

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(Request): (Response)  $next
     *
     * @throws InvalidConfigurationException
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (in_array(app()->environment(), config('cloudflare-zero-trust-middleware.disabled_environments', []))) {
            return $next($request);
        }

        $jwt = $request->header(self::CF_ACCESS_JWT_HEADER_NAME);

        if (! $jwt) {
            abort(403, 'Missing required CF Authorization Token Header');
        }

        $this->validateConfig();

        try {
            $valid = $this->jwtIsValid($jwt);
        } catch (MissingMandatoryClaimException $e) {
            abort(401, 'CF Authorization Token Claims missing');
        } catch (InvalidClaimException $e) {
            abort(401, 'CF Authorization Token Claims Invalid');
        } catch (InvalidArgumentException $e) {
            abort(401, 'CF Authorization Token Invalid');
        }

        if ($valid === false) {
            abort(401, 'CF Authorization Token Invalid');
        }

        return $next($request);
    }

    protected function getClaims(): array
    {
        return self::CLAIMS;
    }

    protected function getClaimCheckers(): array
    {
        return [
            new IssuedAtChecker,
            new IssuerChecker(['https://'.config('cloudflare-zero-trust-middleware.cloudflare_team_name').'.cloudflareaccess.com']),
            new NotBeforeChecker,
            new ExpirationTimeChecker,
            new AudienceChecker(config('cloudflare-zero-trust-middleware.cloudflare_zero_trust_application_audience_tag')),
        ];
    }

    /**
     * @throws MissingMandatoryClaimException
     * @throws InvalidClaimException
     * @throws InvalidArgumentException
     */
    protected function jwtIsValid(string $token): bool
    {
        // The serializer manager. We only use the JWS Compact Serialization Mode.
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer,
        ]);

        // We try to load the token.
        $jws = $serializerManager->unserialize($token);

        $headerCheckerManager = new HeaderCheckerManager(
            [
                // We want to verify that the header "alg" (algorithm)
                // is present and contains "HS256"
                new AlgorithmChecker(['RS256']),
            ],
            [
                // Adds JWS token type support
                new JWSTokenSupport,
            ]
        );

        $headerCheckerManager->check($jws, 0, ['kid', 'alg']);

        $claimCheckerManager = new ClaimCheckerManager($this->getClaimCheckers());

        $claims = json_decode($jws->getPayload(), true);
        $claimCheckerManager->check($claims, $this->getClaims());

        // We must verify the signature with the correct key
        $key_id_used_for_sig = $jws->getSignature(0)->getProtectedHeaderParameter('kid');

        $key = $this->getJWKKeySet()->selectKey('sig', new RS256, ['kid' => $key_id_used_for_sig]);

        // key not found
        if ($key === null) {
            if (config('cloudflare-zero-trust-middleware.cache')) {
                Cache::delete(self::getCacheKey());
            }

            return false;
        }

        // The algorithm manager with the HS256 algorithm.
        $algorithmManager = new AlgorithmManager([
            new RS256,
        ], );

        // We instantiate our JWS Verifier.
        $jwsVerifier = new JWSVerifier(
            $algorithmManager
        );

        return $jwsVerifier->verifyWithKey($jws, $key, 0);
    }

    /**
     * @throws InvalidConfigurationException
     */
    protected function validateConfig(): void
    {
        if (config('cloudflare-zero-trust-middleware.cloudflare_team_name') === null) {
            throw new InvalidConfigurationException('Missing config: cloudflare-zero-trust-middleware.cloudflare_team_name ');
        }
        if (config('cloudflare-zero-trust-middleware.cloudflare_zero_trust_application_audience_tag') === null) {
            throw new InvalidConfigurationException('Missing config: cloudflare-zero-trust-middleware.cloudflare_zero_trust_application_audience_tag ');
        }
    }

    /**
     * @throws InvalidArgumentException
     */
    protected function getJWKKeySet(): JWKSet
    {
        if (! config('cloudflare-zero-trust-middleware.cache')) {
            return $this->getKeysFromCloudflare();
        }

        $ttl = config('cloudflare-zero-trust-middleware.cache_ttl');

        return Cache::remember(self::getCacheKey(), $ttl, function () {
            return $this->getKeysFromCloudflare();
        });
    }

    protected static function getCacheKey(): string
    {
        // ensure a config change "updates" the cache

        return self::CERTIFICATE_CACHE_KEY.'_'.config('cloudflare-zero-trust-middleware.cloudflare_team_name');
    }

    /**
     * @throws InvalidArgumentException
     */
    protected function getKeysFromCloudflare(): JWKSet
    {
        $url = 'https://'.config('cloudflare-zero-trust-middleware.cloudflare_team_name').'.cloudflareaccess.com/cdn-cgi/access/certs';
        $res = Http::timeout(5)
            ->throw()
            ->get($url);

        return JWKSet::createFromJson($res);
    }
}
