package org.apereo.cas.support.oauth.validator.token;

import module java.base;
import org.apereo.cas.AbstractOAuth20Tests;
import org.apereo.cas.services.DefaultRegisteredServiceProperty;
import org.apereo.cas.services.RegisteredServiceCipherExecutor;
import org.apereo.cas.services.RegisteredServiceProperty.RegisteredServiceProperties;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20TokenExchangeTypes;
import org.apereo.cas.support.oauth.profile.DefaultOAuth20UserProfile;
import org.apereo.cas.support.oauth.services.DefaultRegisteredServiceOAuthTokenExchangePolicy;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20JwtAccessTokenEncoder;
import org.apereo.cas.ticket.InvalidTicketException;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.util.EncodingUtils;
import org.apereo.cas.util.RandomUtils;
import org.apereo.cas.util.cipher.BaseStringCipherExecutor.CipherOperationsStrategyType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
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
    private static final String GLOBAL_SIGNING_KEY = EncodingUtils.generateJsonWebKey(512);

    @Autowired
    @Qualifier("oauthTokenExchangeGrantTypeTokenRequestValidator")
    private OAuth20TokenRequestValidator validator;


    private MockHttpServletRequest request;

    private MockHttpServletResponse response;

    @BeforeEach
    void setup() {
        request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.USER_AGENT, "Firefox");
        response = new MockHttpServletResponse();
        authenticateClient("casuser");
    }

    @DynamicPropertySource
    static void configureGlobalSigning(final DynamicPropertyRegistry registry) {
        registry.add("cas.authn.oauth.access-token.crypto.enabled", () -> true);
        registry.add("cas.authn.oauth.access-token.crypto.signing-enabled", () -> true);
        registry.add("cas.authn.oauth.access-token.crypto.encryption-enabled", () -> false);
        registry.add("cas.authn.oauth.access-token.crypto.signing.key", () -> GLOBAL_SIGNING_KEY);
    }

    private void authenticateClient(final String clientId) {
        val profile = new DefaultOAuth20UserProfile(clientId);
        profile.addAttribute(OAuth20Constants.CLIENT_ID, clientId);
        storeProfileIntoSession(request, profile);
    }

    @Test
    void verifySupports() throws Throwable {
        val service = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE), UUID.randomUUID().toString(), UUID.randomUUID().toString());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN, UUID.randomUUID().toString());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());
        request.addParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.addParameter(OAuth20Constants.CLIENT_ID, service.getClientId());
        assertTrue(validator.supports(request, response));
        assertEquals(Ordered.LOWEST_PRECEDENCE, validator.getOrder());
    }

    @Test
    void verifyWithoutSubjectToken() {
        val service = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE), UUID.randomUUID().toString(), UUID.randomUUID().toString());
        request.addParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.addParameter(OAuth20Constants.CLIENT_ID, service.getClientId());
        assertThrows(IllegalArgumentException.class, () -> validator.validate(request, response));
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());
        assertThrows(IllegalArgumentException.class, () -> validator.validate(request, response));
    }

    @Test
    void verifyJwtSignedByAnotherKey() throws Throwable {
        val service = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE), UUID.randomUUID().toString(), UUID.randomUUID().toString());
        val claims = new JWTClaimsSet.Builder()
            .subject(service.getClientId())
            .issuer(RegisteredServiceTestUtils.CONST_TEST_URL)
            .build();
        val jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        jwt.sign(new MACSigner(RandomUtils.randomAlphanumeric(256).getBytes(StandardCharsets.UTF_8)));
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN, jwt.serialize());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.JWT.getType());
        request.addParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.addParameter(OAuth20Constants.CLIENT_ID, service.getClientId());
        assertThrows(IllegalArgumentException.class, () -> validator.validate(request, response));

        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, new PlainJWT(claims).serialize());
        assertThrows(IllegalArgumentException.class, () -> validator.validate(request, response));
    }

    @MethodSource("contextProvider")
    @ParameterizedTest
    void verifyServicePassingWithTicket(final Object subject, final OAuth20TokenExchangeTypes type,
                                        final OAuthRegisteredService registeredService,
                                        final Boolean expectation)
            throws Throwable {
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, subject instanceof final JWTClaimsSet claims
            ? configurationContext.getAccessTokenJwtBuilder().build(registeredService, claims)
            : subject.toString());
        if (subject instanceof final Ticket at) {
            ticketRegistry.addTicket(at);
        }
        request.addParameter(OAuth20Constants.AUDIENCE, UUID.randomUUID().toString());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, type.getType());
        request.addParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.addParameter(OAuth20Constants.CLIENT_ID, registeredService.getClientId());

        servicesManager.save(registeredService);
        authenticateClient(registeredService.getClientId());
        assertEquals(expectation, validator.validate(request, response));
    }

    @Test
    void verifyPolicyIsSelectedFromAuthenticatedRequester() throws Throwable {
        val subjectService = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE),
            UUID.randomUUID().toString(), UUID.randomUUID().toString());
        val requestingService = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE),
            UUID.randomUUID().toString(), UUID.randomUUID().toString());
        subjectService.setTokenExchangePolicy(new DefaultRegisteredServiceOAuthTokenExchangePolicy()
            .setAllowedTokenTypes(Set.of(OAuth20TokenExchangeTypes.JWT.getType())));
        requestingService.setTokenExchangePolicy(new DefaultRegisteredServiceOAuthTokenExchangePolicy()
            .setAllowedTokenTypes(Set.of(OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType())));
        servicesManager.save(subjectService);
        servicesManager.save(requestingService);
        val subjectToken = getAccessToken(subjectService.getServiceId(), subjectService.getClientId());
        ticketRegistry.addTicket(subjectToken);

        authenticateClient(requestingService.getClientId());
        request.addParameter(OAuth20Constants.CLIENT_ID, requestingService.getClientId());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN, subjectToken.getId());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());
        request.addParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        assertTrue(validator.validate(request, response));

        request.setParameter(OAuth20Constants.CLIENT_ID, subjectService.getClientId());
        assertFalse(validator.validate(request, response));
    }

    @Test
    void verifyServiceAllowedResources() throws Throwable {
        val requestingService = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE),
            UUID.randomUUID().toString(), UUID.randomUUID().toString());
        requestingService.setAllowedResources(Set.of("https://api\\.example\\.org/.+"));
        servicesManager.save(requestingService);
        val subjectToken = getAccessToken(requestingService.getServiceId(), requestingService.getClientId());
        ticketRegistry.addTicket(subjectToken);

        authenticateClient(requestingService.getClientId());
        request.addParameter(OAuth20Constants.CLIENT_ID, requestingService.getClientId());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN, subjectToken.getId());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());
        request.addParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.addParameter(OAuth20Constants.RESOURCE, "https://api.example.org/backend");
        assertTrue(validator.validate(request, response));

        request.setParameter(OAuth20Constants.RESOURCE, "https://other.example.org/backend");
        assertThrows(OAuth20InvalidTargetException.class, () -> validator.validate(request, response));

        request.setParameter(OAuth20Constants.RESOURCE, "https://cas.example.org/cas/mcp");
        assertTrue(validator.validate(request, response));
    }

    @ParameterizedTest
    @EnumSource(CipherOperationsStrategyType.class)
    @NullSource
    void verifyCasIssuedAccessTokenJwt(final CipherOperationsStrategyType strategy) throws Throwable {
        val grants = Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE);
        val owner = addRegisteredService(grants, UUID.randomUUID().toString(), randomServiceUrl());
        val requester = addRegisteredService(grants, UUID.randomUUID().toString(), randomServiceUrl());
        owner.setJwtAccessToken(true);
        owner.getProperties().put(RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_KEY.getPropertyName(),
            new DefaultRegisteredServiceProperty(EncodingUtils.generateJsonWebKey(512)));
        owner.getProperties().put(RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty(Boolean.toString(strategy != null)));
        if (strategy != null) {
            owner.getProperties().put(RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_KEY.getPropertyName(),
                new DefaultRegisteredServiceProperty(EncodingUtils.generateJsonWebKey(512)));
            owner.getProperties().put(RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_CIPHER_STRATEGY_TYPE.getPropertyName(),
                new DefaultRegisteredServiceProperty(strategy.name()));
        }
        servicesManager.save(owner);

        val subject = getAccessToken(owner.getServiceId(), owner.getClientId());
        ticketRegistry.addTicket(subject);
        authenticateClient(requester.getClientId());
        request.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());

        val encoder = OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, owner, subject);
        val jwt = encoder.encode(subject.getId());
        assertNotEquals(subject.getId(), jwt);
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, jwt);
        assertTrue(validator.validate(request, response));

        val claims = accessTokenJwtBuilder.unpack(Optional.of(owner), jwt);
        assertFalse(claims.getAudience().contains(requester.getClientId()));
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN,
            accessTokenJwtBuilder.build(owner, new JWTClaimsSet.Builder(claims).jwtID(" ").build()));
        assertThrows(IllegalArgumentException.class, () -> validator.validate(request, response));
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, new PlainJWT(claims).serialize());
        assertThrows(IllegalArgumentException.class, () -> validator.validate(request, response));

        val signatureOrTag = jwt.lastIndexOf('.') + 1;
        val tampered = jwt.substring(0, signatureOrTag)
            + (jwt.charAt(signatureOrTag) == 'A' ? 'B' : 'A') + jwt.substring(signatureOrTag + 1);
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, tampered);
        assertThrows(Exception.class, () -> validator.validate(request, response));

        val refreshToken = getRefreshToken();
        ticketRegistry.addTicket(refreshToken);
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, accessTokenJwtBuilder.build(owner,
            new JWTClaimsSet.Builder(claims).jwtID(refreshToken.getId()).build()));
        assertThrows(ClassCastException.class, () -> validator.validate(request, response));

        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, jwt);
        ticketRegistry.deleteTicket(subject);
        assertThrows(InvalidTicketException.class, () -> validator.validate(request, response));
        ticketRegistry.addTicket(subject);
        when(subject.isExpired()).thenReturn(true);
        assertThrows(InvalidTicketException.class, () -> validator.validate(request, response));
    }

    @Test
    void verifyCasIssuedJwtWithNativeGlobalFallback() throws Throwable {
        val service = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE), UUID.randomUUID().toString(), randomServiceUrl());
        service.setJwtAccessToken(true);
        val signingKey = RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_KEY.getPropertyName();
        service.getProperties().put(signingKey, new DefaultRegisteredServiceProperty(GLOBAL_SIGNING_KEY));
        servicesManager.save(service);
        val subject = getAccessToken(service.getServiceId(), service.getClientId());
        ticketRegistry.addTicket(subject);
        val encoder = OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, service, subject);
        val serviceJwt = encoder.encode(subject.getId());
        val serviceHeader = RegisteredServiceCipherExecutor.CUSTOM_HEADER_REGISTERED_SERVICE_ID;
        assertEquals(Long.toString(service.getId()), JWTParser.parse(serviceJwt).getHeader().getCustomParam(serviceHeader).toString());

        service.getProperties().remove(signingKey);
        servicesManager.save(service);
        assertFalse(accessTokenJwtBuilder.getRegisteredServiceCipherExecutor().supports(service));

        authenticateClient(service.getClientId());
        request.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, serviceJwt);
        val decoder = OAuth20JwtAccessTokenEncoder.toDecodableCipher(accessTokenJwtBuilder);
        assertEquals(subject.getId(), decoder.decode(serviceJwt));
        assertTrue(validator.validate(request, response));

        val globalJwt = encoder.encode(subject.getId());
        assertNull(JWTParser.parse(globalJwt).getHeader().getCustomParam(serviceHeader));
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, globalJwt);
        assertTrue(validator.validate(request, response));
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

        val accessToken = getAccessToken(UUID.randomUUID().toString(), UUID.randomUUID().toString(), UUID.randomUUID().toString());
        val accessTokenRegisteredService = getRegisteredService(accessToken.getService().getId(),
            accessToken.getClientId(), UUID.randomUUID().toString(), Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        
        val accessTokenBadGrant = getAccessToken(UUID.randomUUID().toString(), UUID.randomUUID().toString(), UUID.randomUUID().toString());
        val accessTokenBadGrantService = getRegisteredService(accessTokenBadGrant.getService().getId(),
            accessTokenBadGrant.getClientId(), UUID.randomUUID().toString(), Set.of());

        return Stream.of(
            Arguments.of(accessToken, OAuth20TokenExchangeTypes.ACCESS_TOKEN, accessTokenRegisteredService, true),
            Arguments.of(accessTokenBadGrant, OAuth20TokenExchangeTypes.ACCESS_TOKEN, accessTokenBadGrantService, false),
            Arguments.of(claims, OAuth20TokenExchangeTypes.JWT, jwtRegisteredService, true)
        );
    }
}
