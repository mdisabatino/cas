package org.apereo.cas.support.oauth.validator.token;

import org.apereo.cas.AbstractOAuth20Tests;
import org.apereo.cas.services.DefaultRegisteredServiceProperty;
import org.apereo.cas.services.RegisteredServiceCipherExecutor;
import org.apereo.cas.services.RegisteredServiceProperty;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.OAuth20TokenExchangeTypes;
import org.apereo.cas.support.oauth.services.DefaultRegisteredServiceOAuthTokenExchangePolicy;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20ConfigurationContext;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20IntrospectionEndpointController;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20UserProfileEndpointController;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20JwtAccessTokenCipherExecutor;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20JwtAccessTokenEncoder;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20TokenExchangeAccessTokenDecoder;
import org.apereo.cas.support.oauth.web.response.introspection.OAuth20IntrospectionAccessTokenResponse;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessTokenFactory;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.jee.context.JEEContext;
import org.pac4j.jee.context.session.JEESessionStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * This is {@link OAuth20TokenExchangeGlobalKeysTests}.
 *
 * @since 7.3.0
 */
@Slf4j
@Tag("OAuth")
@TestPropertySource(properties = {
    "cas.authn.oidc.discovery.scopes=openid,profile,create,email,read,update",
    "cas.authn.oauth.access-token.crypto.enabled=true",
    "cas.authn.oauth.access-token.crypto.encryption-enabled=true",
    "cas.authn.oauth.access-token.crypto.signing-enabled=true",
    "cas.authn.oauth.access-token.crypto.strategy-type=ENCRYPT_AND_SIGN",
    "cas.authn.oauth.access-token.crypto.alg=A128CBC-HS256",
    "cas.authn.oauth.access-token.crypto.encryption.key=3RXtt06xYUAli7uU-Z915ZGe0MRBFw3uDjWgOEf1GT8",
    "cas.authn.oauth.access-token.crypto.signing.key=jIFR-fojN0vOIUcT0hDRXHLVp07CV-YeU8GnjICsXpu65lfkJbiKP028pT74Iurkor38xDGXNcXk_Y1V4rNDqw"
})
class OAuth20TokenExchangeGlobalKeysTests extends AbstractOAuth20Tests {
    @Autowired
    @Qualifier("oauthAccessTokenAuthenticator")
    private Authenticator authenticator;

    @Autowired
    @Qualifier("oauthProfileController")
    private OAuth20UserProfileEndpointController<OAuth20ConfigurationContext> profileController;

    @Autowired
    @Qualifier("introspectionEndpointController")
    private OAuth20IntrospectionEndpointController<OAuth20ConfigurationContext> introspectionController;

    @Test
    void verifyServerAudienceWithGlobalKeys() throws Throwable {
        val service = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        val audience = configurationContext.getCasProperties().getServer().getPrefix();
        service.setJwtAccessToken(true);
        service.setAudience(Set.of(audience));
        service.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_KEY.getPropertyName(),
            new DefaultRegisteredServiceProperty(UUID.randomUUID().toString() + UUID.randomUUID()));
        service.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty("false"));
        servicesManager.save(service);
        assertTrue(accessTokenJwtBuilder.getRegisteredServiceCipherExecutor().supports(service));
        assertTrue(accessTokenJwtBuilder.getDefaultTokenCipherExecutor().isEnabled());

        val token = getAccessToken(service.getServiceId(), service.getClientId());
        ticketRegistry.addTicket(token);
        val opaque = OAuth20TokenExchangeAccessTokenDecoder.decodeAccessToken(configurationContext, token.getId());
        assertEquals(Set.of(), opaque.audience());

        val cipher = OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, service, token);
        val jwt = cipher.encode(token.getId());
        assertNull(JWTParser.parse(jwt).getHeader().getCustomParam(RegisteredServiceCipherExecutor.CUSTOM_HEADER_REGISTERED_SERVICE_ID));
        val verified = OAuth20TokenExchangeAccessTokenDecoder.decodeAccessToken(configurationContext, jwt);
        assertEquals(token.getId(), verified.ticket().getId());
        assertEquals(service.getId(), verified.registeredService().getId());
        assertEquals(Set.of(audience), verified.audience());

        val claims = accessTokenJwtBuilder.unpack(jwt);
        val wrongAudience = accessTokenJwtBuilder.build(null,
            new JWTClaimsSet.Builder(claims).audience(service.getClientId()).build());
        assertThrows(IllegalArgumentException.class,
            () -> OAuth20TokenExchangeAccessTokenDecoder.decodeAccessToken(configurationContext, wrongAudience));
    }

    @Test
    void verifyEncryptedAccessTokenAcrossNativeAndExchangeFlows() throws Throwable {
        val fixture = createEncryptedAccessToken();
        val ticket = fixture.ticket();
        val jwe = fixture.jwe();
        val principalId = ticket.getAuthentication().getPrincipal().getId();
        val service = fixture.service();

        assertEquals(ticket.getId(), accessTokenJwtBuilder.unpack(jwe).getJWTID());
        val decoder = OAuth20JwtAccessTokenEncoder.toDecodableCipher(accessTokenJwtBuilder);
        assertEquals(ticket.getId(), decoder.decode(jwe));

        val credentials = new TokenCredentials(jwe);
        val context = new JEEContext(new MockHttpServletRequest(), new MockHttpServletResponse());
        assertTrue(authenticator.validate(new CallContext(context, new JEESessionStore()), credentials).isPresent());
        assertEquals(principalId, credentials.getUserProfile().getId());

        val profileRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.PROFILE_URL);
        profileRequest.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + jwe);
        val profile = profileController.handleGetRequest(profileRequest, new MockHttpServletResponse());
        assertEquals(HttpStatus.OK, profile.getStatusCode());
        assertEquals(principalId, assertInstanceOf(Map.class, profile.getBody()).get("id"));

        val introspectionRequest = new MockHttpServletRequest();
        introspectionRequest.addParameter(OAuth20Constants.TOKEN, jwe);
        val clientCredentials = service.getClientId() + ':' + service.getClientSecret();
        introspectionRequest.addHeader(HttpHeaders.AUTHORIZATION,
            "Basic " + Base64.getEncoder().encodeToString(clientCredentials.getBytes(StandardCharsets.UTF_8)));
        val introspection = introspectionController.handleRequest(introspectionRequest, new MockHttpServletResponse());
        assertEquals(HttpStatus.OK, introspection.getStatusCode());
        val body = assertInstanceOf(OAuth20IntrospectionAccessTokenResponse.class, introspection.getBody());
        assertTrue(body.isActive());
        assertEquals(service.getClientId(), body.getClientId());
        assertEquals(principalId, body.getSub());

        val resource = "https://api.example.org/allowed";
        service.setTokenExchangePolicy(new DefaultRegisteredServiceOAuthTokenExchangePolicy()
            .setAllowedResources(Set.of("^https://api[.]example[.]org/allowed$")));
        servicesManager.save(service);
        val mvc = MockMvcBuilders.webAppContextSetup(applicationContext).build();

        mvc.perform(exchangeRequest(fixture, fixture.signedJwt(), resource))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.scope").value("update"))
            .andExpect(jsonPath("$.issued_token_type").value(OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType()))
            .andExpect(jsonPath("$.access_token").isString());

        val response = mvc.perform(exchangeRequest(fixture, jwe, resource));
        val issuedToken = response.andReturn().getResponse();
        val exchangeAccepted = issuedToken.getStatus() == HttpStatus.OK.value();
        mvc.perform(exchangeRequest(fixture, jwe, "https://api.example.org/denied"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value(exchangeAccepted ? OAuth20Constants.INVALID_GRANT : OAuth20Constants.INVALID_REQUEST))
            .andExpect(jsonPath("$.access_token").doesNotExist());

        if (exchangeAccepted) {
            response.andExpect(jsonPath("$.access_token").isString())
                .andExpect(jsonPath("$.issued_token_type").value(OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType()));
            val issued = JsonPath.parse(issuedToken.getContentAsString()).read("$.access_token", String.class);
            val issuedId = decoder.decode(issued);
            assertNotEquals(ticket.getId(), issuedId);
            val exchanged = ticketRegistry.getTicket(issuedId, OAuth20AccessToken.class);
            assertEquals(principalId, exchanged.getAuthentication().getPrincipal().getId());
            assertEquals(service.getClientId(), exchanged.getClientId());
            assertEquals(resource, exchanged.getService().getId());
            assertEquals(ticket.getScopes(), exchanged.getScopes());

            val decoded = OAuth20TokenExchangeAccessTokenDecoder.decodeAccessToken(configurationContext, jwe);
            assertEquals(ticket.getId(), decoded.ticket().getId());
            assertEquals(service.getId(), decoded.registeredService().getId());
        } else {
            response.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(OAuth20Constants.INVALID_REQUEST))
                .andExpect(jsonPath("$.access_token").doesNotExist());
            assertThrows(IllegalArgumentException.class,
                () -> OAuth20TokenExchangeAccessTokenDecoder.decodeAccessToken(configurationContext, jwe));
        }
        LOGGER.info("Token Exchange issued a new access token for the encryption-only fixture: [{}]", exchangeAccepted);
    }

    private EncryptedAccessTokenFixture createEncryptedAccessToken() throws Throwable {
        val service = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE),
            UUID.randomUUID().toString(), randomServiceUrl());
        service.setJwtAccessToken(true);
        service.setScopes(Set.of("update"));
        servicesManager.save(service);

        val factory = (OAuth20AccessTokenFactory) configurationContext.getTicketFactory().get(OAuth20AccessToken.class);
        val tokenService = configurationContext.getWebApplicationServiceServiceFactory().createService(service.getServiceId());
        val ticket = factory.create(tokenService, getAuthentication(createPrincipal()), service.getScopes(), service.getClientId(),
            OAuth20ResponseTypes.CODE, OAuth20GrantTypes.AUTHORIZATION_CODE);
        ticketRegistry.addTicket(ticket);
        val issuer = OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, service, ticket);
        val signedJwt = issuer.encode(ticket.getId());
        assertInstanceOf(SignedJWT.class, JWTParser.parse(signedJwt));
        val claims = accessTokenJwtBuilder.unpack(signedJwt);

        val crypto = configurationContext.getCasProperties().getAuthn().getOauth().getAccessToken().getCrypto();
        assertTrue(crypto.isSigningEnabled());
        assertNotNull(accessTokenJwtBuilder.getDefaultTokenCipherExecutor().getSigningKey());
        val encryptionOnly = new OAuth20JwtAccessTokenCipherExecutor(
            crypto.getEncryption().getKey(), null, crypto.getAlg(), true, false, 0, crypto.getEncryption().getKeySize());
        val jwe = encryptionOnly.encode(claims.toString());
        assertInstanceOf(EncryptedJWT.class, JWTParser.parse(jwe));
        return new EncryptedAccessTokenFixture(service, ticket, signedJwt, jwe);
    }

    private static MockHttpServletRequestBuilder exchangeRequest(final EncryptedAccessTokenFixture fixture,
                                                                final String subjectToken,
                                                                final String resource) {
        return post("/cas" + CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL)
            .contextPath("/cas")
            .param(OAuth20Constants.CLIENT_ID, fixture.service().getClientId())
            .param(OAuth20Constants.CLIENT_SECRET, fixture.service().getClientSecret())
            .param(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType())
            .param(OAuth20Constants.SUBJECT_TOKEN, subjectToken)
            .param(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType())
            .param(OAuth20Constants.REQUESTED_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType())
            .param(OAuth20Constants.RESOURCE, resource)
            .param(OAuth20Constants.SCOPE, "update");
    }

    private record EncryptedAccessTokenFixture(
        OAuthRegisteredService service, OAuth20AccessToken ticket, String signedJwt, String jwe) {
    }
}
