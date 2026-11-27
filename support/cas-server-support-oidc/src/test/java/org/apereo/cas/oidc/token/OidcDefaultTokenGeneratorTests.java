package org.apereo.cas.oidc.token;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.DefaultAuthenticationBuilder;
import org.apereo.cas.oidc.AbstractOidcTests;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.services.DefaultRegisteredServiceProperty;
import org.apereo.cas.services.OidcBackchannelTokenDeliveryModes;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.RegisteredServiceAttributeReleasePolicy;
import org.apereo.cas.services.RegisteredServiceAttributeReleasePolicyContext;
import org.apereo.cas.services.RegisteredServiceProperty.RegisteredServiceProperties;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.OAuth20TokenExchangeTypes;
import org.apereo.cas.support.oauth.authenticator.Authenticators;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.AccessTokenRequestContext;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20JwtAccessTokenEncoder;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20TokenExchangeAccessTokenDecoder;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.ticket.accesstoken.OAuth20DefaultAccessToken;
import org.apereo.cas.ticket.idtoken.IdTokenGenerationContext;
import org.apereo.cas.ticket.refreshtoken.OAuth20RefreshToken;
import org.apereo.cas.util.serialization.JacksonObjectMapperFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.pac4j.core.profile.CommonProfile;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link OidcDefaultTokenGeneratorTests}.
 *
 * @author Misagh Moayyed
 * @since 7.1.0
 */
@Tag("OIDC")
class OidcDefaultTokenGeneratorTests extends AbstractOidcTests {
    @Test
    void verifyCibaAuthRequestClaim() throws Throwable {
        val registeredService = getOidcRegisteredService(UUID.randomUUID().toString());
        registeredService.setBackchannelTokenDeliveryMode(OidcBackchannelTokenDeliveryModes.PUSH.getMode());
        registeredService.setSupportedGrantTypes(Set.of(OAuth20GrantTypes.CIBA.getType()));
        registeredService.setBackchannelClientNotificationEndpoint("https://localhost:1234");
        servicesManager.save(registeredService);

        val cibaRequest = newCibaRequest(registeredService, RegisteredServiceTestUtils.getPrincipal(UUID.randomUUID().toString()));
        val accessTokenContext = AccessTokenRequestContext.builder()
            .grantType(OAuth20GrantTypes.CIBA)
            .responseType(OAuth20ResponseTypes.NONE)
            .registeredService(registeredService)
            .generateRefreshToken(true)
            .cibaRequestId(cibaRequest.getEncodedId())
            .authentication(cibaRequest.getAuthentication())
            .service(RegisteredServiceTestUtils.getService())
            .scopes(Set.of(OidcConstants.StandardScopes.OPENID.getScope()))
            .build();
        val result = oauthTokenGenerator.generate(accessTokenContext);
        assertNotNull(result);
        val accessToken = (OAuth20AccessToken) result.getAccessToken().orElseThrow();
        assertEquals(cibaRequest.getEncodedId(), accessToken.getAuthentication().getSingleValuedAttribute(OidcConstants.AUTH_REQ_ID).toString());

        val profile = new CommonProfile();
        profile.setClientName(Authenticators.CAS_OAUTH_CLIENT_BASIC_AUTHN);
        profile.setId(registeredService.getClientId());
        profile.addAttribute(OAuth20Constants.CLIENT_ID, registeredService.getClientId());

        val idTokenContext = IdTokenGenerationContext.builder()
            .accessToken(accessToken)
            .userProfile(profile)
            .responseType(accessTokenContext.getResponseType())
            .grantType(accessTokenContext.getGrantType())
            .registeredService(registeredService)
            .refreshToken((OAuth20RefreshToken) result.getRefreshToken().orElseThrow())
            .build();
        
        val oidcIdToken = oidcIdTokenGenerator.generate(idTokenContext);
        assertNotNull(oidcIdToken);
        assertEquals(cibaRequest.getEncodedId(), oidcIdToken.claims().getStringClaimValue(OidcConstants.CLAIM_AUTH_REQ_ID));
        assertTrue(oidcIdToken.claims().hasClaim(OidcConstants.CLAIM_AT_HASH));
        assertTrue(oidcIdToken.claims().hasClaim(OidcConstants.CLAIM_RT_HASH));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void verifyAccessTokenExchangeActorSurvivesTicketPersistence(final boolean jwt) throws Throwable {
        val service = registerActorExchangeService();
        val subject = getAccessToken(service.getClientId());
        val actor = RegisteredServiceTestUtils.getAuthentication("first-actor");
        val issued = exchangeAccessToken(service, subject, actor);
        val firstActor = Map.of(OAuth20Constants.CLAIM_SUB, "first-actor");
        assertEquals(firstActor, encodeAccessTokenClaims(service, issued).getJSONObjectClaim(OAuth20Constants.CLAIM_ACT));

        val mapper = JacksonObjectMapperFactory.builder().defaultTypingEnabled(true).build().toObjectMapper();
        val restored = mapper.readValue(mapper.writeValueAsString(issued), OAuth20DefaultAccessToken.class);
        ticketRegistry.updateTicket(restored);
        val presented = jwt ? encodeAccessToken(service, restored) : restored.getId();
        val recovered = OAuth20TokenExchangeAccessTokenDecoder.decodeAccessToken(oidcConfigurationContext, presented).ticket();
        assertEquals(firstActor, recovered.getAuthentication().getSingleValuedAttribute(OAuth20Constants.TOKEN_EXCHANGE_ACTOR_CHAIN_ATTRIBUTE));

        val next = exchangeAccessToken(service, recovered, RegisteredServiceTestUtils.getAuthentication("second-actor"));
        val history = Map.of(OAuth20Constants.CLAIM_SUB, "second-actor", OAuth20Constants.CLAIM_ACT, firstActor);
        assertEquals(history, encodeAccessTokenClaims(service, next).getJSONObjectClaim(OAuth20Constants.CLAIM_ACT));
        val carriedForward = exchangeAccessToken(service, next, null);
        assertEquals(history, encodeAccessTokenClaims(service, carriedForward).getJSONObjectClaim(OAuth20Constants.CLAIM_ACT));
        assertEquals(subject.getAuthentication().getPrincipal().getId(), carriedForward.getAuthentication().getPrincipal().getId());
    }

    @Test
    void verifyAccessTokenExchangeIgnoresUntrustedActorAttributes() throws Throwable {
        val service = registerActorExchangeService();
        val untrusted = Map.of(OAuth20Constants.CLAIM_SUB, "untrusted-actor");
        val principal = RegisteredServiceTestUtils.getPrincipal("casuser", Map.of(
            OAuth20Constants.CLAIM_ACT, List.of(untrusted), OAuth20Constants.TOKEN_EXCHANGE_ACTOR_CHAIN_ATTRIBUTE, List.of(untrusted)));
        val authentication = DefaultAuthenticationBuilder.newInstance(principal)
            .addAttribute(OAuth20Constants.CLAIM_ACT, untrusted)
            .addAttribute(OAuth20Constants.TOKEN_EXCHANGE_ACTOR_CHAIN_ATTRIBUTE, untrusted)
            .build();
        val subjectContext = AccessTokenRequestContext.builder()
            .grantType(OAuth20GrantTypes.AUTHORIZATION_CODE)
            .responseType(OAuth20ResponseTypes.CODE)
            .registeredService(service)
            .service(RegisteredServiceTestUtils.getService(service.getServiceId()))
            .authentication(authentication)
            .claims(Map.of(OAuth20Constants.CLAIMS_USERINFO, Map.of(OAuth20Constants.TOKEN_EXCHANGE_ACTOR_CHAIN_ATTRIBUTE, untrusted)))
            .build();
        val subject = (OAuth20AccessToken) oauthTokenGenerator.generate(subjectContext).getAccessToken().orElseThrow();
        assertFalse(subject.getAuthentication().containsAttribute(OAuth20Constants.TOKEN_EXCHANGE_ACTOR_CHAIN_ATTRIBUTE));
        val issued = exchangeAccessToken(service, subject, null);
        issued.markTicketStateless();

        val releasePolicy = mock(RegisteredServiceAttributeReleasePolicy.class);
        when(releasePolicy.getAttributes(any(RegisteredServiceAttributeReleasePolicyContext.class))).thenReturn(Map.of(
            OAuth20Constants.CLAIM_ACT, List.of(untrusted), OAuth20Constants.TOKEN_EXCHANGE_ACTOR_CHAIN_ATTRIBUTE, List.of(untrusted)));
        service.setAttributeReleasePolicy(releasePolicy);
        val claims = encodeAccessTokenClaims(service, issued);

        verify(releasePolicy, atLeastOnce()).getAttributes(any(RegisteredServiceAttributeReleasePolicyContext.class));
        assertNull(claims.getClaim(OAuth20Constants.CLAIM_ACT));
        assertNull(claims.getClaim(OAuth20Constants.TOKEN_EXCHANGE_ACTOR_CHAIN_ATTRIBUTE));
        assertEquals(issued.getId(), claims.getJWTID());
    }

    private OidcRegisteredService registerActorExchangeService() {
        val service = getOidcRegisteredService(UUID.randomUUID().toString());
        service.setSupportedGrantTypes(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE.getType()));
        service.setScopes(Set.of(OidcConstants.StandardScopes.OPENID.getScope()));
        service.setJwtAccessToken(true);
        service.getProperties().put(RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_KEY.getPropertyName(),
            new DefaultRegisteredServiceProperty(UUID.randomUUID().toString() + UUID.randomUUID()));
        service.getProperties().put(RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty("false"));
        servicesManager.save(service);
        return service;
    }

    private OAuth20AccessToken exchangeAccessToken(final OidcRegisteredService service, final OAuth20AccessToken subject,
                                                    final Authentication actor) throws Throwable {
        val context = AccessTokenRequestContext.builder()
            .grantType(OAuth20GrantTypes.TOKEN_EXCHANGE)
            .subjectTokenType(OAuth20TokenExchangeTypes.ACCESS_TOKEN)
            .requestedTokenType(OAuth20TokenExchangeTypes.ACCESS_TOKEN)
            .responseType(OAuth20ResponseTypes.NONE)
            .registeredService(service)
            .service(subject.getService())
            .subjectToken(subject)
            .actorToken(actor)
            .scopes(service.getScopes())
            .build();
        return (OAuth20AccessToken) oauthTokenGenerator.generate(context).getAccessToken().orElseThrow();
    }

    private String encodeAccessToken(final OidcRegisteredService service, final OAuth20AccessToken token) {
        return OAuth20JwtAccessTokenEncoder.toEncodableCipher(oidcConfigurationContext, service, token).encode(token.getId());
    }

    private JWTClaimsSet encodeAccessTokenClaims(final OidcRegisteredService service, final OAuth20AccessToken token) {
        return oidcConfigurationContext.getAccessTokenJwtBuilder().unpack(Optional.of(service), encodeAccessToken(service, token));
    }
}
