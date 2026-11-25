package org.apereo.cas.oidc.token;

import org.apereo.cas.authentication.DefaultAuthenticationBuilder;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.oidc.AbstractOidcTests;
import org.apereo.cas.services.DefaultRegisteredServiceProperty;
import org.apereo.cas.services.RegisteredServiceAttributeReleasePolicy;
import org.apereo.cas.services.RegisteredServiceProperty;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.util.OAuth20TokenExchangeActorUtils;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20JwtAccessTokenEncoder;
import org.apereo.cas.token.JwtBuilder;

import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Regression coverage for the RFC 8693 actor claim in OIDC JWT access tokens.
 * Protocol provenance is independent of user and authentication attributes.
 *
 * @since 7.3.8
 */
@Tag("OIDC")
@TestPropertySource(properties = {
    "cas.authn.oauth.access-token.crypto.encryption-enabled=false",
    "cas.authn.oauth.access-token.include-claims-in-jwt=true"
})
class OidcTokenExchangeActorJwtRegressionTests extends AbstractOidcTests {

    @Test
    void verifyTokenExchangeActorIsPresentInJwt() throws Throwable {
        val principal = RegisteredServiceTestUtils.getPrincipal("casuser");
        val jwt = issueJwt(principal, OAuth20GrantTypes.TOKEN_EXCHANGE,
            Map.of(OAuth20Constants.CLAIM_SUB, "service-a"));
        val claims = JwtBuilder.parse(jwt);
        assertEquals("casuser", claims.getSubject());
        assertEquals("service-a",
            claims.getJSONObjectClaim(OAuth20Constants.CLAIM_ACT).get(OAuth20Constants.CLAIM_SUB));
    }

    @Test
    void verifyTokenExchangeWithoutActorHasNoActorClaim() throws Throwable {
        val principal = RegisteredServiceTestUtils.getPrincipal("casuser");
        val claims = JwtBuilder.parse(issueJwt(principal, OAuth20GrantTypes.TOKEN_EXCHANGE, null));
        assertFalse(claims.getClaims().containsKey(OAuth20Constants.CLAIM_ACT));
    }

    @Test
    void verifyOrdinaryGrantCannotEmitActorClaim() throws Throwable {
        val principal = RegisteredServiceTestUtils.getPrincipal("casuser");
        val claims = JwtBuilder.parse(issueJwt(principal, OAuth20GrantTypes.AUTHORIZATION_CODE,
            Map.of(OAuth20Constants.CLAIM_SUB, "forged_actor")));
        assertFalse(claims.getClaims().containsKey(OAuth20Constants.CLAIM_ACT));
    }

    @Test
    void verifyPrincipalAttributeCannotBePromotedToActorClaim() throws Throwable {
        val principal = RegisteredServiceTestUtils.getPrincipal("casuser", Map.of(
            OAuth20Constants.CLAIM_ACT, List.<Object>of(Map.of(OAuth20Constants.CLAIM_SUB, "forged_actor"))));
        val claims = JwtBuilder.parse(issueJwt(principal, OAuth20GrantTypes.TOKEN_EXCHANGE, null));
        assertFalse(claims.getClaims().containsKey(OAuth20Constants.CLAIM_ACT));
    }

    @Test
    void verifyCyclicActorHistoryIsRejected() {
        val actor = new HashMap<String, Object>();
        actor.put(OAuth20Constants.CLAIM_SUB, "service-a");
        actor.put(OAuth20Constants.CLAIM_ACT, actor);
        assertThrows(IllegalArgumentException.class, () -> OAuth20TokenExchangeActorUtils.copyActor(actor));
    }

    private String issueJwt(final Principal principal, final OAuth20GrantTypes requestGrant,
                            final Map<String, String> actor) throws Throwable {
        val clientId = "actor-regression-" + UUID.randomUUID();
        val registeredService = getOidcRegisteredService(clientId);
        registeredService.setJwtAccessToken(true);
        registeredService.setProperties(Map.of(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty("false"),
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty("false")));
        servicesManager.save(registeredService);
        val releasePolicy = mock(RegisteredServiceAttributeReleasePolicy.class);
        when(releasePolicy.getAttributes(any())).thenReturn(Map.of(
            OAuth20Constants.CLAIM_ACT, List.of(Map.of(OAuth20Constants.CLAIM_SUB, "forged-actor"))));
        registeredService.setAttributeReleasePolicy(releasePolicy);

        val builder = DefaultAuthenticationBuilder.newInstance(RegisteredServiceTestUtils.getAuthentication(principal))
            .addAttribute(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        if (actor != null) {
            builder.addAttribute(OAuth20Constants.CLAIM_ACT, actor);
        }
        val accessToken = getAccessToken(builder.build(), clientId);
        when(accessToken.getGrantType()).thenReturn(requestGrant);
        when(accessToken.isStateless()).thenReturn(true);
        if (actor != null) {
            when(accessToken.getActor()).thenReturn(Map.copyOf(actor));
        }
        return OAuth20JwtAccessTokenEncoder.toEncodableCipher(oidcConfigurationContext,
            registeredService, accessToken, accessToken.getService(), false).encode(accessToken.getId());
    }
}
