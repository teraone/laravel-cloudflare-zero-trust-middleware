<?php

namespace Teraone\ZeroTrustMiddleware;

use Closure;
use DateTimeZone;
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
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Symfony\Component\Clock\NativeClock;
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

    final public const USER_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'country', 'identity_nonce', 'type'];

    final public const SERVICE_TOKEN_CLAIMS = ['iss', 'aud', 'exp', 'type', 'common_name'];

    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
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

    protected function getClaims(JWS $jws): array
    {
        $payload = json_decode($jws->getPayload(), true);

        // User JWTs have an email claim, service tokens have common_name
        if (isset($payload['email'])) {
            return self::USER_CLAIMS;
        }

        // Default to service token claims (includes common_name and minimal set)
        return self::SERVICE_TOKEN_CLAIMS;
    }

    /**
     * @throws \DateInvalidTimeZoneException
     */
    protected function getClaimCheckers(JWS $jws): array
    {
        $payload = json_decode($jws->getPayload(), true);
        $clock = new NativeClock(new DateTimeZone('UTC'));

        $checkers = [
            new IssuedAtChecker(clock: $clock),
            new IssuerChecker(['https://'.config('cloudflare-zero-trust-middleware.cloudflare_team_name').'.cloudflareaccess.com']),
            new ExpirationTimeChecker(clock: $clock),
            new AudienceChecker(config('cloudflare-zero-trust-middleware.cloudflare_zero_trust_application_audience_tag')),
        ];

        // Only check NotBeforeChecker for user JWTs (they have the nbf claim)
        if (isset($payload['email'])) {
            $checkers[] = new NotBeforeChecker(clock: $clock);
        }

        return $checkers;
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

        $claimCheckerManager = new ClaimCheckerManager($this->getClaimCheckers($jws));

        $claims = json_decode($jws->getPayload(), true);
        $claimCheckerManager->check($claims, $this->getClaims($jws));

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
