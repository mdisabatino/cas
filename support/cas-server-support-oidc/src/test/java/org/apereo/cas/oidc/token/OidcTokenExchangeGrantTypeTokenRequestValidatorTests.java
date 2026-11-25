package org.apereo.cas.oidc.token;

import org.apereo.cas.oidc.AbstractOidcTests;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.services.DefaultRegisteredServiceProperty;
import org.apereo.cas.services.RegisteredServiceProperty.RegisteredServiceProperties;
import org.apereo.cas.support.oauth.OAuth20ClientAuthenticationMethods;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.OAuth20TokenExchangeTypes;
import org.apereo.cas.support.oauth.authenticator.Authenticators;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.validator.token.OAuth20TokenRequestValidator;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.ticket.idtoken.IdTokenGenerationContext;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.jee.context.JEEContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * This is {@link OidcTokenExchangeGrantTypeTokenRequestValidatorTests}.
 *
 * @author Misagh Moayyed
 * @since 7.3.0
 */
@Tag("OIDC")
class OidcTokenExchangeGrantTypeTokenRequestValidatorTests extends AbstractOidcTests {
    @Autowired
    @Qualifier("oauthTokenExchangeGrantTypeTokenRequestValidator")
    private OAuth20TokenRequestValidator validator;

    private JEEContext context;
    private MockHttpServletRequest request;
    private ProfileManager profileManager;

    @BeforeEach
    void setup() {
        request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.USER_AGENT, "Firefox");
        val response = new MockHttpServletResponse();
        context = new JEEContext(request, response);
        val profile = new CommonProfile();
        profile.setClientName(Authenticators.CAS_OAUTH_CLIENT_BASIC_AUTHN);
        profile.setId("casuser");
        profileManager = new ProfileManager(context, oauthDistributedSessionStore);
        profileManager.save(true, profile, false);
    }


    @Test
    void verifyEndpointIssuanceAndExchangeWithDistinctIssuers() throws Exception {
        val oauthService = getOAuthRegisteredService(UUID.randomUUID().toString(), "https://oauth.example.org/callback");
        val oidcService = getOidcRegisteredService(UUID.randomUUID().toString()).setEncryptIdToken(false);
        val oauthIssuer = oidcConfigurationContext.getCasProperties().getServer().getPrefix();
        val oidcIssuer = oidcIssuerService.determineIssuer(Optional.of(oidcService));
        assertNotEquals(oauthIssuer, oidcIssuer);

        val baseUrl = "https://sso.example.org:443/cas";
        val oauthUrl = baseUrl + OAuth20Constants.BASE_OAUTH20_URL + '/' + OAuth20Constants.TOKEN_URL;
        val oidcUrl = baseUrl + '/' + OidcConstants.BASE_OIDC_URL + '/' + OAuth20Constants.TOKEN_URL;
        verifyEndpointAccessTokenExchange(oauthUrl, oauthService, oauthIssuer);
        val oidcJwt = verifyEndpointAccessTokenExchange(oidcUrl, oidcService, oidcIssuer);

        mockMvc.perform(exchangeRequest(oauthUrl, oidcService, oidcJwt))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.issued_token_type").value(OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType()))
            .andExpect(jsonPath("$.access_token").isString());
    }

    @Test
    void verifySubjectTokenAsIdToken() throws Throwable {
        val registeredService = getOidcRegisteredService(UUID.randomUUID().toString()).setEncryptIdToken(false);
        registeredService.setSupportedGrantTypes(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE.getType()));
        servicesManager.save(registeredService);
        val authenticated = profileManager.getProfile().orElseThrow();
        authenticated.addAttribute(OAuth20Constants.CLIENT_ID, registeredService.getClientId());
        profileManager.save(true, authenticated, false);
        request.setParameter(OAuth20Constants.CLIENT_ID, registeredService.getClientId());

        request.addParameter(OAuth20Constants.AUDIENCE, UUID.randomUUID().toString());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ID_TOKEN.getType());
        request.addParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());

        val accessToken = getAccessToken(registeredService.getClientId());
        when(accessToken.getScopes()).thenReturn(
            Set.of(OidcConstants.StandardScopes.DEVICE_SSO.getScope(),
                OidcConstants.StandardScopes.PROFILE.getScope(),
                OidcConstants.StandardScopes.OPENID.getScope()));

        val idTokenContext = IdTokenGenerationContext.builder()
            .accessToken(accessToken)
            .userProfile(profileManager.getProfile().orElseThrow())
            .responseType(OAuth20ResponseTypes.CODE)
            .grantType(OAuth20GrantTypes.AUTHORIZATION_CODE)
            .registeredService(registeredService)
            .build();
        val idToken = oidcIdTokenGenerator.generate(idTokenContext);
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, idToken.token());
        assertTrue(validator.validate(context));
    }

    private String verifyEndpointAccessTokenExchange(final String url, final OAuthRegisteredService service,
                                                     final String issuer) throws Exception {
        service.setJwtAccessToken(true);
        service.setSupportedGrantTypes(Set.of(OAuth20GrantTypes.CLIENT_CREDENTIALS.getType(), OAuth20GrantTypes.TOKEN_EXCHANGE.getType()));
        service.setTokenEndpointAuthenticationMethod(OAuth20ClientAuthenticationMethods.CLIENT_SECRET_POST.getType());
        service.getProperties().put(RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_KEY.getPropertyName(),
            new DefaultRegisteredServiceProperty(UUID.randomUUID().toString() + UUID.randomUUID()));
        service.getProperties().put(RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty("false"));
        servicesManager.save(service);

        val issued = mockMvc.perform(tokenRequest(url, service, OAuth20GrantTypes.CLIENT_CREDENTIALS))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").isString())
            .andReturn().getResponse();
        val jwt = JsonPath.parse(issued.getContentAsString()).read("$.access_token", String.class);
        assertInstanceOf(SignedJWT.class, JWTParser.parse(jwt));
        val claims = oidcAccessTokenJwtBuilder.unpack(Optional.of(service), jwt);
        assertEquals(issuer, claims.getIssuer());

        val exchanged = mockMvc.perform(exchangeRequest(url, service, jwt))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").isString())
            .andExpect(jsonPath("$.issued_token_type").value(OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType()))
            .andReturn().getResponse();
        val exchangedJwt = JsonPath.parse(exchanged.getContentAsString()).read("$.access_token", String.class);
        val exchangedClaims = oidcAccessTokenJwtBuilder.unpack(Optional.of(service), exchangedJwt);
        assertNotEquals(claims.getJWTID(), exchangedClaims.getJWTID());
        assertEquals(issuer, exchangedClaims.getIssuer());
        val exchangedTicket = ticketRegistry.getTicket(exchangedClaims.getJWTID(), OAuth20AccessToken.class);
        assertEquals(service.getClientId(), exchangedTicket.getClientId());

        return jwt;
    }

    private static MockHttpServletRequestBuilder exchangeRequest(final String url, final OAuthRegisteredService service, final String jwt) {
        return tokenRequest(url, service, OAuth20GrantTypes.TOKEN_EXCHANGE)
            .param(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType())
            .param(OAuth20Constants.SUBJECT_TOKEN, jwt);
    }

    private static MockHttpServletRequestBuilder tokenRequest(final String url, final OAuthRegisteredService service,
                                                              final OAuth20GrantTypes grantType) {
        return post(url)
            .contextPath("/cas")
            .secure(true)
            .param(OAuth20Constants.CLIENT_ID, service.getClientId())
            .param(OAuth20Constants.CLIENT_SECRET, service.getClientSecret())
            .param(OAuth20Constants.GRANT_TYPE, grantType.getType());
    }
}
