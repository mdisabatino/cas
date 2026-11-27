package org.apereo.cas.support.oauth.validator.token;

import org.apereo.cas.AbstractOAuth20Tests;
import org.apereo.cas.services.DefaultRegisteredServiceProperty;
import org.apereo.cas.services.RegisteredServiceProperty;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20TokenExchangeTypes;
import org.apereo.cas.support.oauth.authenticator.Authenticators;
import org.apereo.cas.support.oauth.services.DefaultRegisteredServiceOAuthTokenExchangePolicy;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20JwtAccessTokenEncoder;
import org.apereo.cas.ticket.InvalidTicketException;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.UniqueTicketIdGenerator;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.token.JwtBuilder;
import org.apereo.cas.util.EncodingUtils;
import org.apereo.cas.util.cipher.BaseStringCipherExecutor;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.jee.context.JEEContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import java.time.Clock;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link OAuth20TokenExchangeGrantTypeTokenRequestValidatorTests}.
 *
 * @author Misagh Moayyed
 * @since 7.1.0
 */
@Tag("OAuth")
class OAuth20TokenExchangeGrantTypeTokenRequestValidatorTests extends AbstractOAuth20Tests {
    @Autowired
    @Qualifier("oauthTokenExchangeGrantTypeTokenRequestValidator")
    private OAuth20TokenRequestValidator validator;

    private JEEContext context;
    private MockHttpServletRequest request;

    @BeforeEach
    void setup() {
        request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.USER_AGENT, "Firefox");
        val response = new MockHttpServletResponse();
        context = new JEEContext(request, response);
        val profile = new CommonProfile();
        profile.setClientName(Authenticators.CAS_OAUTH_CLIENT_BASIC_AUTHN);
        profile.setId("casuser");
        new ProfileManager(context, oauthDistributedSessionStore).save(true, profile, false);
    }

    @Test
    void verifySupports() throws Throwable {
        val service = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE), UUID.randomUUID().toString(), UUID.randomUUID().toString());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN, UUID.randomUUID().toString());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());
        request.addParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.addParameter(OAuth20Constants.CLIENT_ID, service.getClientId());
        assertTrue(validator.supports(context));
        assertEquals(Ordered.LOWEST_PRECEDENCE, validator.getOrder());
    }

    @Test
    void verifyWithoutSubjectToken() {
        val service = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE), UUID.randomUUID().toString(), UUID.randomUUID().toString());
        request.addParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.addParameter(OAuth20Constants.CLIENT_ID, service.getClientId());
        assertThrows(IllegalArgumentException.class, () -> validator.validate(context));
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());
        assertThrows(IllegalArgumentException.class, () -> validator.validate(context));
    }

    @MethodSource("contextProvider")
    @ParameterizedTest
    void verifyServicePassingWithTicket(final Object subject, final OAuth20TokenExchangeTypes type,
                                        final OAuthRegisteredService registeredService,
                                        final Boolean expectation) throws Throwable {
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, subject.toString());
        if (subject instanceof final Ticket at) {
            ticketRegistry.addTicket(at);
        }
        request.addParameter(OAuth20Constants.AUDIENCE, UUID.randomUUID().toString());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, type.getType());
        request.addParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());

        servicesManager.save(registeredService);
        if (type == OAuth20TokenExchangeTypes.ACCESS_TOKEN) {
            val profiles = new ProfileManager(context, oauthDistributedSessionStore);
            val profile = profiles.getProfile().orElseThrow();
            profile.addAttribute(OAuth20Constants.CLIENT_ID, registeredService.getClientId());
            profiles.save(true, profile, false);
        }
        assertEquals(expectation, validator.validate(context));

        if (type == OAuth20TokenExchangeTypes.JWT) {
            val claims = JWTParser.parse(subject.toString()).getJWTClaimsSet();
            val reservedId = OAuth20AccessToken.PREFIX + UniqueTicketIdGenerator.SEPARATOR + UUID.randomUUID();
            val accessTokenClaims = new JWTClaimsSet.Builder(claims).jwtID(reservedId).build();
            request.setParameter(OAuth20Constants.SUBJECT_TOKEN, JwtBuilder.buildPlain(accessTokenClaims, Optional.of(registeredService)));
            val failure = assertThrows(IllegalArgumentException.class, () -> validator.validate(context));
            assertEquals("CAS access tokens must use the access_token subject type", failure.getMessage());
        }
    }

    @Test
    void verifyServiceWithJwtAccessToken() throws Throwable {
        val service = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        service.setJwtAccessToken(true);
        service.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_KEY.getPropertyName(),
            new DefaultRegisteredServiceProperty(UUID.randomUUID().toString() + UUID.randomUUID()));
        service.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty("false"));
        servicesManager.save(service);
        val token = getAccessToken(service.getServiceId(), service.getClientId());
        ticketRegistry.addTicket(token);
        request.setParameter(OAuth20Constants.CLIENT_ID, service.getClientId());
        val profileManager = new ProfileManager(context, oauthDistributedSessionStore);
        val authenticatedProfile = profileManager.getProfile().orElseThrow();
        authenticatedProfile.addAttribute(OAuth20Constants.CLIENT_ID, service.getClientId());
        profileManager.save(true, authenticatedProfile, false);
        val cipher = OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, service, token);
        val jwt = cipher.encode(token.getId());
        assertNotEquals(token.getId(), jwt);
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, jwt);
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());
        request.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        assertTrue(validator.validate(context));

        val verifiedClaims = accessTokenJwtBuilder.unpack(Optional.of(service), jwt);
        val missingIssuer = accessTokenJwtBuilder.build(service,
            new JWTClaimsSet.Builder(verifiedClaims).issuer(null).build());
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, missingIssuer);
        assertThrows(IllegalArgumentException.class, () -> validator.validate(context));
        val expired = accessTokenJwtBuilder.build(service,
            new JWTClaimsSet.Builder(verifiedClaims).expirationTime(new Date(0)).build());
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, expired);
        assertThrows(Exception.class, () -> validator.validate(context));
        assertFalse(token.isExpired());
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, JwtBuilder.buildPlain(verifiedClaims, Optional.of(service)));
        assertThrows(IllegalArgumentException.class, () -> validator.validate(context));
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, jwt);

        service.getAudience().add("another-client");
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, cipher.encode(token.getId()));
        assertFalse(validator.validate(context));
        service.getAudience().clear();
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, jwt);

        val unregistered = getAccessToken(service.getServiceId(), "unregistered-client-" + UUID.randomUUID());
        ticketRegistry.addTicket(unregistered);
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, unregistered.getId());
        assertThrows(IllegalArgumentException.class, () -> validator.validate(context));
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN,
            OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, service, unregistered).encode(unregistered.getId()));
        assertThrows(IllegalArgumentException.class, () -> validator.validate(context));
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, jwt);

        authenticatedProfile.removeAttribute(OAuth20Constants.CLIENT_ID);
        profileManager.save(true, authenticatedProfile, false);
        assertFalse(validator.validate(context));
        authenticatedProfile.addAttribute(OAuth20Constants.CLIENT_ID, "another-client");
        profileManager.save(true, authenticatedProfile, false);
        assertFalse(validator.validate(context));
        authenticatedProfile.addAttribute(OAuth20Constants.CLIENT_ID, service.getClientId());
        profileManager.save(true, authenticatedProfile, false);

        val signature = jwt.lastIndexOf('.') + 1;
        val altered = jwt.substring(0, signature) + (jwt.charAt(signature) == 'A' ? 'B' : 'A') + jwt.substring(signature + 1);
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, altered);
        assertThrows(Exception.class, () -> validator.validate(context));
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, jwt);

        ticketRegistry.deleteTicket(token);
        assertThrows(InvalidTicketException.class, () -> validator.validate(context));
        ticketRegistry.addTicket(token);
        when(token.isExpired()).thenReturn(true);
        assertThrows(InvalidTicketException.class, () -> validator.validate(context));
    }

    @ParameterizedTest
    @EnumSource(BaseStringCipherExecutor.CipherOperationsStrategyType.class)
    void verifyNestedAccessJwt(final BaseStringCipherExecutor.CipherOperationsStrategyType strategy) throws Throwable {
        val service = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        service.setJwtAccessToken(true);
        service.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_KEY.getPropertyName(),
            new DefaultRegisteredServiceProperty(EncodingUtils.generateJsonWebKey(512)));
        service.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty("true"));
        service.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_KEY.getPropertyName(),
            new DefaultRegisteredServiceProperty(UUID.randomUUID().toString() + UUID.randomUUID()));
        service.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_CIPHER_STRATEGY_TYPE.getPropertyName(),
            new DefaultRegisteredServiceProperty(strategy.name()));
        servicesManager.save(service);
        val token = getAccessToken(service.getServiceId(), service.getClientId());
        ticketRegistry.addTicket(token);
        val profileManager = new ProfileManager(context, oauthDistributedSessionStore);
        val profile = profileManager.getProfile().orElseThrow();
        profile.addAttribute(OAuth20Constants.CLIENT_ID, service.getClientId());
        profileManager.save(true, profile, false);
        val cipher = OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, service, token);
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());
        request.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        val encoded = cipher.encode(token.getId());
        val jwt = JWTParser.parse(encoded);
        if (strategy == BaseStringCipherExecutor.CipherOperationsStrategyType.ENCRYPT_AND_SIGN) {
            val signed = assertInstanceOf(SignedJWT.class, jwt);
            assertNull(signed.getPayload().toJSONObject());
        } else {
            assertInstanceOf(EncryptedJWT.class, jwt);
        }
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, encoded);
        assertTrue(validator.validate(context));

        service.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty("false"));
        servicesManager.save(service);
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, cipher.encode(token.getId()));
        assertThrows(IllegalArgumentException.class, () -> validator.validate(context));

        service.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty("true"));
        service.getProperties().remove(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_KEY.getPropertyName());
        servicesManager.save(service);
        val unsigned = cipher.encode(token.getId());
        assertInstanceOf(EncryptedJWT.class, JWTParser.parse(unsigned));
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, unsigned);
        assertThrows(IllegalArgumentException.class, () -> validator.validate(context));
    }

    @Test
    void verifyRequestingClientPolicy() throws Throwable {
        val origin = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        val caller = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        origin.setJwtAccessToken(true);
        origin.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_KEY.getPropertyName(),
            new DefaultRegisteredServiceProperty(UUID.randomUUID().toString() + UUID.randomUUID()));
        origin.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty("false"));
        origin.getAudience().add(caller.getClientId());
        origin.setTokenExchangePolicy(new DefaultRegisteredServiceOAuthTokenExchangePolicy().setAllowedAudience(Set.of("^other$")));
        caller.setTokenExchangePolicy(new DefaultRegisteredServiceOAuthTokenExchangePolicy().setAllowedAudience(Set.of("^resource$")));
        servicesManager.save(origin);
        servicesManager.save(caller);
        val token = getAccessToken(origin.getServiceId(), origin.getClientId());
        ticketRegistry.addTicket(token);
        val profileManager = new ProfileManager(context, oauthDistributedSessionStore);
        val profile = profileManager.getProfile().orElseThrow();
        profile.addAttribute(OAuth20Constants.CLIENT_ID, caller.getClientId());
        profileManager.save(true, profile, false);
        val cipher = OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, origin, token);
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, cipher.encode(token.getId()));
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());
        request.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.setParameter(OAuth20Constants.AUDIENCE, "resource");
        assertTrue(validator.validate(context));
        request.setParameter(OAuth20Constants.AUDIENCE, "other");
        assertFalse(validator.validate(context));

        request.setParameter(OAuth20Constants.AUDIENCE, "resource");
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, token.getId());
        assertFalse(validator.validate(context));
    }

    static Stream<Arguments> contextProvider() throws Exception {
        val claims = JWTClaimsSet.parse(Map.of(
            "sub", UUID.randomUUID().toString(),
            "aud", UUID.randomUUID().toString(),
            "iat", ZonedDateTime.now(Clock.systemUTC()).toEpochSecond(),
            "nbf", ZonedDateTime.now(Clock.systemUTC()).toEpochSecond(),
            "exp", ZonedDateTime.now(Clock.systemUTC()).plusHours(2).toEpochSecond(),
            "iss", RegisteredServiceTestUtils.CONST_TEST_URL
        ));
        val jwtRegisteredService = getRegisteredService(claims.getIssuer(), claims.getSubject(),
            UUID.randomUUID().toString(), Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        val jwt = JwtBuilder.buildPlain(claims, Optional.of(jwtRegisteredService));

        val accessToken = getAccessToken(UUID.randomUUID().toString(), UUID.randomUUID().toString(), UUID.randomUUID().toString());
        val accessTokenRegisteredService = getRegisteredService(accessToken.getService().getId(),
            accessToken.getClientId(), UUID.randomUUID().toString(), Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        
        val accessTokenBadGrant = getAccessToken(UUID.randomUUID().toString(), UUID.randomUUID().toString(), UUID.randomUUID().toString());
        val accessTokenBadGrantService = getRegisteredService(accessTokenBadGrant.getService().getId(),
            accessTokenBadGrant.getClientId(), UUID.randomUUID().toString(), Set.of());

        return Stream.of(
            Arguments.of(accessToken, OAuth20TokenExchangeTypes.ACCESS_TOKEN, accessTokenRegisteredService, true),
            Arguments.of(accessTokenBadGrant, OAuth20TokenExchangeTypes.ACCESS_TOKEN, accessTokenBadGrantService, false),
            Arguments.of(jwt, OAuth20TokenExchangeTypes.JWT, jwtRegisteredService, true)
        );
    }
}
