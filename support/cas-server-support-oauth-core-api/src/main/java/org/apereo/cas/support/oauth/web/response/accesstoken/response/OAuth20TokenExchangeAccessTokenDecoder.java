package org.apereo.cas.support.oauth.web.response.accesstoken.response;

import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.RegisteredServiceAccessStrategyUtils;
import org.apereo.cas.services.RegisteredServiceCipherExecutor;
import org.apereo.cas.services.RegisteredServiceProperty;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20ConfigurationContext;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.token.JwtBuilder;
import org.apereo.cas.token.cipher.RegisteredServiceJwtTicketCipherExecutor;
import org.apereo.cas.util.cipher.BaseStringCipherExecutor;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import lombok.experimental.UtilityClass;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Resolves access tokens presented to the token exchange grant.
 *
 * @author Marco Di Sabatino Di Diodoro
 * @since 7.3.0
 */
@UtilityClass
public class OAuth20TokenExchangeAccessTokenDecoder {
    private static final DefaultJWTClaimsVerifier<SimpleSecurityContext> JWT_CLAIMS_VERIFIER =
        new DefaultJWTClaimsVerifier<>(null, Set.of("iss", "sub", "aud", "exp", "iat"));

    /**
     * Resolve an access token and its registered service for token exchange.
     *
     * @param context the token exchange configuration
     * @param value the opaque or JWT access token
     * @return the access token ticket, audience and registered service
     * @throws Exception if validation fails
     */
    public static AccessToken decodeAccessToken(final OAuth20ConfigurationContext context, final String value) throws Exception {
        val jwt = parseJwt(value);
        if (jwt == null) {
            val ticket = context.getTicketRegistry().getTicket(value, OAuth20AccessToken.class);
            val service = resolveRegisteredService(context, ticket);
            RegisteredServiceAccessStrategyUtils.ensureServiceAccessIsAllowed(service);
            return new AccessToken(ticket, Set.of(), service);
        }
        if (!(jwt instanceof SignedJWT || jwt instanceof EncryptedJWT)) {
            throw new IllegalArgumentException("Token exchange requires an authenticated JWT");
        }
        val accessTokenJwtBuilder = context.getAccessTokenJwtBuilder();
        val verificationService = resolveVerificationService(accessTokenJwtBuilder, jwt);
        requireSigningConfiguration(accessTokenJwtBuilder, verificationService);
        val claims = accessTokenJwtBuilder.unpack(Optional.ofNullable(verificationService), value);
        verifyClaims(claims);
        val id = claims.getJWTID();
        if (StringUtils.isBlank(id)) {
            throw new IllegalArgumentException("CAS access JWT must identify a ticket");
        }
        val ticket = context.getTicketRegistry().getTicket(id, OAuth20AccessToken.class);
        val service = resolveRegisteredService(context, ticket);
        if (verificationService == null) {
            val serverAudience = claims.getAudience().equals(List.of(context.getCasProperties().getServer().getPrefix()));
            if (!serverAudience && accessTokenJwtBuilder.getRegisteredServiceCipherExecutor().supports(service)) {
                throw new IllegalArgumentException("CAS access JWT verification authority does not match its ticket");
            }
            RegisteredServiceAccessStrategyUtils.ensureServiceAccessIsAllowed(service);
        } else if (verificationService.getId() != service.getId()) {
            throw new IllegalArgumentException("CAS access JWT verification authority does not match its ticket");
        }
        return new AccessToken(ticket, Set.copyOf(claims.getAudience()), service);
    }

    private static JWT parseJwt(final String value) {
        try {
            return JWTParser.parse(value);
        } catch (final ParseException e) {
            return null;
        }
    }

    private static RegisteredService resolveVerificationService(final JwtBuilder accessTokenJwtBuilder, final JWT jwt) {
        val header = jwt.getHeader();
        val decoder = new OAuth20JwtAccessTokenDecodableCipher(null, accessTokenJwtBuilder);
        val service = decoder.resolveRegisteredService(header);
        if (service == null && header.getCustomParam(RegisteredServiceCipherExecutor.CUSTOM_HEADER_REGISTERED_SERVICE_ID) != null) {
            throw new IllegalArgumentException("CAS access JWT verification service is not registered");
        }
        return service;
    }

    private static void requireSigningConfiguration(final JwtBuilder accessTokenJwtBuilder, final RegisteredService service) {
        val serviceCipher = accessTokenJwtBuilder.getRegisteredServiceCipherExecutor();
        if (service != null && serviceCipher.supports(service)) {
            val property = RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_ENABLED;
            if ((property.isAssignedTo(service) && !property.getPropertyBooleanValue(service))
                || (serviceCipher instanceof RegisteredServiceJwtTicketCipherExecutor executor
                    && executor.getSigningKey(service).filter(StringUtils::isNotBlank).isEmpty())) {
                throw new IllegalArgumentException("Token exchange requires JWT signature verification");
            }
        } else if (accessTokenJwtBuilder.getDefaultTokenCipherExecutor() instanceof BaseStringCipherExecutor cipher
            && !cipher.isSigningEnabled()) {
            throw new IllegalArgumentException("Token exchange requires JWT signature verification");
        }
    }

    private static void verifyClaims(final JWTClaimsSet claims) throws Exception {
        if (StringUtils.isAnyBlank(claims.getIssuer(), claims.getSubject())
            || claims.getAudience().isEmpty() || claims.getAudience().stream().anyMatch(StringUtils::isBlank)) {
            throw new IllegalArgumentException("Token exchange JWT identity and audience are required");
        }
        JWT_CLAIMS_VERIFIER.verify(claims, new SimpleSecurityContext());
    }

    private static OAuthRegisteredService resolveRegisteredService(final OAuth20ConfigurationContext context, final OAuth20AccessToken ticket) {
        val service = OAuth20Utils.getRegisteredOAuthServiceByClientId(context.getServicesManager(), ticket.getClientId());
        if (service == null) {
            throw new IllegalArgumentException("Access token service is not registered");
        }
        return service;
    }

    /**
     * An access token ticket, its audience and its registered service.
     *
     * @param ticket the access token ticket
     * @param audience the validated JWT audience, empty for opaque access tokens
     * @param registeredService the original registered service
     */
    public record AccessToken(OAuth20AccessToken ticket, Set<String> audience, OAuthRegisteredService registeredService) {
    }
}
