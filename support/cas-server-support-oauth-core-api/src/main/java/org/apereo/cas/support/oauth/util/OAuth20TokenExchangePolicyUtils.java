package org.apereo.cas.support.oauth.util;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.DefaultAuthenticationBuilder;
import org.apereo.cas.services.RegisteredServiceCipherExecutor;
import org.apereo.cas.services.RegisteredServiceProperty;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.services.DefaultRegisteredServiceOAuthTokenExchangePolicy;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.services.RegisteredServiceOAuthTokenExchangePolicy;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20ConfigurationContext;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20TokenExchangeAccessTokenDecoder;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20TokenExchangeAccessTokenDecoder.AccessToken;
import org.apereo.cas.util.cipher.BaseStringCipherExecutor;

import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import lombok.experimental.UtilityClass;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Resolves verified token identities and destinations for token exchange policies.
 *
 * @author CAS Contributors
 * @since 7.3.8
 */
@UtilityClass
public class OAuth20TokenExchangePolicyUtils {
    /**
     * Resolve an access token and check that JWT destinations match any destinations recorded on the ticket.
     *
     * @param context configuration
     * @param value encoded or opaque token
     * @return decoded access token
     * @throws Exception on invalid tokens
     */
    public AccessToken accessToken(final OAuth20ConfigurationContext context, final String value) throws Exception {
        val token = OAuth20TokenExchangeAccessTokenDecoder.decodeAccessToken(context, value);
        val storedAudience = token.ticket().getAudience();
        if (!token.audience().isEmpty() && !storedAudience.isEmpty() && !storedAudience.equals(token.audience())) {
            throw new IllegalArgumentException("CAS access JWT destinations do not match its ticket");
        }
        return token;
    }

    /**
     * Determine the audience available to policy for a verified access token.
     *
     * @param accessToken verified access token
     * @return JWT audience or the persisted audience of an opaque token
     */
    public Set<String> subjectAudience(final AccessToken accessToken) {
        return accessToken.audience().isEmpty() ? accessToken.ticket().getAudience() : accessToken.audience();
    }

    /**
     * Verify a standalone JWT using a locally registered issuer or the local global cipher.
     * Additional issuer authorities must be explicitly configured in the requesting policy.
     *
     * @param context configuration
     * @param value token
     * @param policy requesting client policy
     * @param localIssuer issuer trusted by the local configuration
     * @return verified claims
     * @throws Exception on invalid or untrusted tokens
     */
    public JWTClaimsSet standaloneJwt(final OAuth20ConfigurationContext context, final String value,
                                      final RegisteredServiceOAuthTokenExchangePolicy policy, final String localIssuer) throws Exception {
        val jwt = JWTParser.parse(value);
        if (!(jwt instanceof SignedJWT || jwt instanceof EncryptedJWT)) {
            throw new IllegalArgumentException("Standalone token exchange JWT must be authenticated");
        }
        var service = (OAuthRegisteredService) null;
        var claimedIssuer = (String) null;
        if (jwt instanceof SignedJWT) {
            try {
                claimedIssuer = jwt.getJWTClaimsSet().getIssuer();
            } catch (final ParseException e) {
                claimedIssuer = null;
            }
        }
        val authorities = policy.trustedTokenIssuers();
        if (claimedIssuer != null) {
            val serviceId = authorities.get(claimedIssuer);
            if (serviceId == null && !localIssuer.equals(claimedIssuer)) {
                throw new IllegalArgumentException("Standalone JWT issuer is not trusted by the requesting service");
            }
            service = serviceId == null ? null : context.getServicesManager().findServiceBy(serviceId, OAuthRegisteredService.class);
            if (serviceId != null && service == null) {
                throw new IllegalArgumentException("Standalone issuer verification service is not registered");
            }
        } else {
            val selector = jwt.getHeader().getCustomParam(RegisteredServiceCipherExecutor.CUSTOM_HEADER_REGISTERED_SERVICE_ID);
            val serviceId = selector == null ? null : Long.valueOf(selector.toString());
            if (serviceId != null && !authorities.containsValue(serviceId)) {
                throw new IllegalArgumentException("JWT verification service is not authorized by the requesting policy");
            }
            service = serviceId == null ? null : context.getServicesManager().findServiceBy(serviceId, OAuthRegisteredService.class);
            if (serviceId != null && service == null) {
                throw new IllegalArgumentException("Standalone issuer verification service is not registered");
            }
        }
        if (service != null && !context.getAccessTokenJwtBuilder().getRegisteredServiceCipherExecutor().supports(service)) {
            throw new IllegalArgumentException("Standalone issuer verification service has no configured JWT keys");
        }
        requireSigning(context, service);
        val claims = context.getAccessTokenJwtBuilder().unpack(Optional.ofNullable(service), value);
        verifyClaims(claims);
        val issuerAllowed = service == null
            ? localIssuer.equals(claims.getIssuer()) && !authorities.containsKey(claims.getIssuer())
            : Long.valueOf(service.getId()).equals(authorities.get(claims.getIssuer()));
        if (!issuerAllowed || (claimedIssuer != null && !claimedIssuer.equals(claims.getIssuer()))) {
            throw new IllegalArgumentException("Standalone JWT issuer does not match the configured verification authority");
        }
        return claims;
    }

    /**
     * Construct an identity from verified standalone claims rather than the requesting profile.
     * Keep token metadata available to policy without releasing it as user attributes in a new token.
     *
     * @param context configuration
     * @param claims verified claims
     * @return subject or actor authentication
     * @throws Throwable on principal construction failures
     */
    public Authentication authentication(final OAuth20ConfigurationContext context, final JWTClaimsSet claims) throws Throwable {
        val attributes = new HashMap<String, List<Object>>();
        claims.getClaims().forEach((key, value) -> {
            if (value != null) {
                attributes.put(key, value instanceof List<?> values ? new ArrayList<>(values) : List.of(value));
            }
        });
        val principalAttributes = new HashMap<>(attributes);
        for (val key : List.of("iss", "sub", "aud", "exp", "iat", "nbf", "jti", "cnf",
            OAuth20Constants.CLAIM_ACT, OAuth20Constants.CLIENT_ID, OAuth20Constants.GRANT_TYPE,
            OAuth20Constants.RESPONSE_TYPE, OAuth20Constants.SCOPE)) {
            principalAttributes.remove(key);
        }
        return DefaultAuthenticationBuilder.newInstance(context.getPrincipalFactory().createPrincipal(claims.getSubject(), principalAttributes))
            .setAttributes(attributes).build();
    }

    /**
     * Obtain the effective policy without weakening subject usability when no policy is configured.
     *
     * @param service requesting service
     * @return configured policy or the default policy
     */
    public RegisteredServiceOAuthTokenExchangePolicy policy(final OAuthRegisteredService service) {
        return service.getTokenExchangePolicy() == null ? new DefaultRegisteredServiceOAuthTokenExchangePolicy() : service.getTokenExchangePolicy();
    }

    /**
     * Check resource syntax and explicit multi-target policy support.
     *
     * @param policy effective policy
     * @param resources requested resource indicators
     * @param audience requested audience
     * @return whether target cardinality is supported
     */
    public boolean targetsAllowed(final RegisteredServiceOAuthTokenExchangePolicy policy,
                                  final Set<String> resources, final Set<String> audience) {
        if (audience.stream().anyMatch(StringUtils::isBlank)) {
            throw new IllegalArgumentException("Token exchange audience cannot be blank");
        }
        for (val resource : resources) {
            if (!validResource(resource)) {
                throw new IllegalArgumentException("Token exchange resource must be an absolute URI without a fragment");
            }
        }
        return (resources.size() <= 1 && audience.size() <= 1) || policy.isMultipleTargetsAllowed();
    }

    private boolean validResource(final String resource) {
        try {
            val uri = URI.create(resource);
            return uri.isAbsolute() && uri.getFragment() == null;
        } catch (final IllegalArgumentException e) {
            return false;
        }
    }

    private void requireSigning(final OAuth20ConfigurationContext context, final OAuthRegisteredService service) {
        val builder = context.getAccessTokenJwtBuilder();
        val serviceCipher = builder.getRegisteredServiceCipherExecutor();
        if (service != null && serviceCipher.supports(service)) {
            val property = RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_ENABLED;
            if (property.isAssignedTo(service) && !property.getPropertyBooleanValue(service)) {
                throw new IllegalArgumentException("Token exchange requires JWT signature verification");
            }
        } else if (builder.getDefaultTokenCipherExecutor() instanceof BaseStringCipherExecutor cipher
            && !cipher.isSigningEnabled()) {
            throw new IllegalArgumentException("Token exchange requires JWT signature verification");
        }
    }

    private void verifyClaims(final JWTClaimsSet claims) throws Exception {
        if (StringUtils.isBlank(claims.getIssuer()) || StringUtils.isBlank(claims.getSubject())
            || claims.getAudience().isEmpty() || claims.getAudience().stream().anyMatch(StringUtils::isBlank)) {
            throw new IllegalArgumentException("Token exchange JWT identity and audience are required");
        }
        new DefaultJWTClaimsVerifier<SimpleSecurityContext>(null, Set.of("iss", "sub", "aud", "exp", "iat"))
            .verify(claims, new SimpleSecurityContext());
    }
}
