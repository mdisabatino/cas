package org.apereo.cas.support.oauth.web.response.accesstoken.ext;

import org.apereo.cas.AbstractOAuth20Tests;
import org.apereo.cas.services.DefaultRegisteredServiceProperty;
import org.apereo.cas.services.RegisteredServiceProperty;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.OAuth20TokenExchangeTypes;
import org.apereo.cas.support.oauth.services.DefaultRegisteredServiceOAuthTokenExchangePolicy;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20JwtAccessTokenEncoder;
import org.apereo.cas.ticket.InvalidTicketException;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.ticket.accesstoken.OAuth20DefaultAccessToken;
import org.apereo.cas.token.JwtBuilder;
import org.apereo.cas.util.serialization.JacksonObjectMapperFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.jee.context.JEEContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link AccessTokenTokenExchangeGrantRequestExtractorTests}.
 *
 * @author Misagh Moayyed
 * @since 7.1.0
 */
@Tag("OAuth")
class AccessTokenTokenExchangeGrantRequestExtractorTests extends AbstractOAuth20Tests {
    @Autowired
    @Qualifier("accessTokenTokenExchangeGrantRequestExtractor")
    private AccessTokenGrantRequestExtractor extractor;

    @Test
    void verifyExtractionWithJwtType() throws Throwable {
        val registeredService = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        val request = new MockHttpServletRequest();

        registeredService.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_KEY.getPropertyName(),
            new DefaultRegisteredServiceProperty(UUID.randomUUID().toString() + UUID.randomUUID()));
        registeredService.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty("false"));
        registeredService.setTokenExchangePolicy(new DefaultRegisteredServiceOAuthTokenExchangePolicy()
            .setTrustedTokenIssuers(Map.of(registeredService.getClientId(), registeredService.getId())));
        servicesManager.save(registeredService);
        val payload = JwtBuilder.JwtRequest
            .builder()
            .registeredService(Optional.of(registeredService))
            .serviceAudience(Set.of(UUID.randomUUID().toString()))
            .issuer(registeredService.getClientId())
            .jwtId(UUID.randomUUID().toString())
            .subject(UUID.randomUUID().toString())
            .issueDate(new Date())
            .validUntilDate(new Date(System.currentTimeMillis() + 3600_000))
            .build();

        val jwtString = accessTokenJwtBuilder.build(payload);

        val subjectToken = getAccessToken(registeredService.getServiceId(), registeredService.getClientId());
        ticketRegistry.addTicket(subjectToken);

        request.addParameter(OAuth20Constants.SUBJECT_TOKEN, subjectToken.getId());
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());

        request.addParameter(OAuth20Constants.ACTOR_TOKEN, jwtString);
        request.addParameter(OAuth20Constants.ACTOR_TOKEN_TYPE, OAuth20TokenExchangeTypes.JWT.getType());

        request.setParameter(OAuth20Constants.CLIENT_ID, registeredService.getClientId());
        request.addParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.addParameter(OAuth20Constants.AUDIENCE, registeredService.getClientId());

        val response = new MockHttpServletResponse();
        val context = new JEEContext(request, response);

        val userProfile = new CommonProfile();
        userProfile.setId("casuser");
        userProfile.addAttributes((Map) RegisteredServiceTestUtils.getTestAttributes());
        userProfile.addAttribute(OAuth20Constants.CLIENT_ID, registeredService.getClientId());
        new ProfileManager(context, oauthDistributedSessionStore).save(true, userProfile, false);

        val tokenContext = extractor.extract(context);
        assertNotNull(tokenContext);
    }

    @ParameterizedTest
    @CsvSource({"false,false", "true,false", "false,true", "true,true"})
    void verifyExtractionWithAccessTokenType(final boolean jwtSubject, final boolean jwtActor) throws Throwable {
        val service = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        val request = new MockHttpServletRequest();

        service.setTokenExchangePolicy(new DefaultRegisteredServiceOAuthTokenExchangePolicy()
            .setRequiredActorTokenAttributes(Map.of(OAuth20Constants.CLIENT_ID, List.of("^" + service.getClientId() + "$"))));
        service.setJwtAccessToken(true);
        service.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_KEY.getPropertyName(),
            new DefaultRegisteredServiceProperty(UUID.randomUUID().toString() + UUID.randomUUID()));
        service.getProperties().put(
            RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_ENABLED.getPropertyName(),
            new DefaultRegisteredServiceProperty("false"));
        servicesManager.save(service);
        val subjectToken = getAccessToken(service.getServiceId(), service.getClientId());
        ticketRegistry.addTicket(subjectToken);

        val actorToken = getAccessToken(randomServiceUrl(), service.getClientId());
        ticketRegistry.addTicket(actorToken);

        val subject = jwtSubject
            ? OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, service, subjectToken).encode(subjectToken.getId())
            : subjectToken.getId();
        assertEquals(!jwtSubject, subject.equals(subjectToken.getId()));
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN, subject);
        request.addParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());

        val actor = jwtActor
            ? OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, service, actorToken).encode(actorToken.getId())
            : actorToken.getId();
        assertEquals(!jwtActor, actor.equals(actorToken.getId()));
        request.addParameter(OAuth20Constants.ACTOR_TOKEN, actor);
        request.addParameter(OAuth20Constants.ACTOR_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());

        request.setParameter(OAuth20Constants.CLIENT_ID, service.getClientId());
        request.addParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.addParameter(OAuth20Constants.AUDIENCE, service.getClientId());

        val response = new MockHttpServletResponse();
        val context = new JEEContext(request, response);
        val authenticatedProfile = new CommonProfile();
        authenticatedProfile.setId("casuser");
        authenticatedProfile.addAttribute(OAuth20Constants.CLIENT_ID, service.getClientId());
        new ProfileManager(context, oauthDistributedSessionStore).save(true, authenticatedProfile, false);
        assertEquals(OAuth20ResponseTypes.NONE, extractor.getResponseType());
        assertTrue(extractor.supports(context));
        val tokenContext = extractor.extract(context);
        assertNotNull(tokenContext);
        assertNotNull(tokenContext.getSubjectToken());
        assertFalse(tokenContext.getTokenExchangeAudience().isEmpty());
        assertNull(tokenContext.getTokenExchangeResource());
        assertEquals(OAuth20TokenExchangeTypes.ACCESS_TOKEN, tokenContext.getSubjectTokenType());
        assertEquals(OAuth20TokenExchangeTypes.ACCESS_TOKEN, tokenContext.getRequestedTokenType());
        assertEquals(subjectToken, tokenContext.getSubjectToken());
        assertEquals(actorToken.getAuthentication().getPrincipal().getId(), tokenContext.getActorToken().getPrincipal().getId());
        assertEquals(List.of(service.getClientId()), tokenContext.getActorToken().getAttributes().get(OAuth20Constants.CLIENT_ID));
        val unrelatedActor = getAccessToken(randomServiceUrl(), UUID.randomUUID().toString());
        ticketRegistry.addTicket(unrelatedActor);
        request.setParameter(OAuth20Constants.ACTOR_TOKEN, unrelatedActor.getId());
        assertThrows(IllegalArgumentException.class, () -> extractor.extract(context));
        request.setParameter(OAuth20Constants.ACTOR_TOKEN, actor);

        when(actorToken.isExpired()).thenReturn(true);
        assertThrows(InvalidTicketException.class, () -> extractor.extract(context));
        when(actorToken.isExpired()).thenReturn(false);
        ticketRegistry.addTicket(actorToken);

        if (jwtSubject) {
            val cipher = OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, service, subjectToken);
            service.getAudience().add("another-client");
            request.setParameter(OAuth20Constants.SUBJECT_TOKEN, cipher.encode(subjectToken.getId()));
            assertThrows(IllegalArgumentException.class, () -> extractor.extract(context));
            service.getAudience().clear();
            request.setParameter(OAuth20Constants.SUBJECT_TOKEN, subject);
        }
        if (jwtActor) {
            val signature = actor.lastIndexOf('.') + 1;
            val altered = actor.substring(0, signature) + (actor.charAt(signature) == 'A' ? 'B' : 'A') + actor.substring(signature + 1);
            request.setParameter(OAuth20Constants.ACTOR_TOKEN, altered);
            assertThrows(Exception.class, () -> extractor.extract(context));
            request.setParameter(OAuth20Constants.ACTOR_TOKEN, actor);
            ticketRegistry.deleteTicket(actorToken);
            assertThrows(InvalidTicketException.class, () -> extractor.extract(context));
        }
    }
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void verifyThreeHopExchange(final boolean jwt) throws Throwable {
        val clients = new ArrayList<OAuthRegisteredService>();
        for (val id : List.of("service-a", "service-b", "service-c", "service-d")) {
            val service = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE), id + "-" + UUID.randomUUID(), "https://" + id + ".example.org");
            service.setJwtAccessToken(jwt);
            clients.add(service);
            servicesManager.save(service);
        }
        val initial = getAccessToken(clients.getFirst().getServiceId(), clients.getFirst().getClientId());
        when(initial.getActor()).thenReturn(Map.of("sub", "untrusted-history"));
        ticketRegistry.addTicket(initial);
        var subject = initial.getId();
        var history = Map.<String, Object>of();
        for (var hop = 0; hop < 3; hop++) {
            val caller = clients.get(hop);
            val target = clients.get(hop + 1).getClientId();
            val actor = getAccessToken(RegisteredServiceTestUtils.getAuthentication(caller.getClientId()), caller.getServiceId(), caller.getClientId());
            ticketRegistry.addTicket(actor);
            val context = exchangeContext(caller, subject, actor.getId(), Set.of(target));
            val extracted = extractor.extract(context);
            val result = oauthTokenGenerator.generate(extracted);
            val token = (OAuth20AccessToken) result.getAccessToken().orElseThrow();
            assertEquals(initial.getAuthentication().getPrincipal().getId(), token.getAuthentication().getPrincipal().getId());
            assertEquals(caller.getClientId(), token.getClientId());
            assertEquals(Set.of(target), token.getAudience());
            assertEquals(OAuth20GrantTypes.TOKEN_EXCHANGE, token.getGrantType());
            val expected = new LinkedHashMap<String, Object>();
            expected.put("sub", caller.getClientId());
            expected.put("iss", configurationContext.getCasProperties().getServer().getPrefix());
            if (!history.isEmpty()) {
                expected.put("act", history);
            }
            assertEquals(expected, token.getActor());
            history = token.getActor();
            val mapper = JacksonObjectMapperFactory.builder().defaultTypingEnabled(true).build().toObjectMapper();
            val restored = mapper.readValue(mapper.writeValueAsString(token), OAuth20DefaultAccessToken.class);
            assertEquals(expected, restored.getActor());
            assertEquals(Set.of(target), restored.getAudience());
            ticketRegistry.updateTicket(restored);
            assertThrows(UnsupportedOperationException.class, () -> token.getAudience().add("unapproved"));
            subject = jwt ? OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, caller, token).encode(token.getId()) : token.getId();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void verifyStandaloneSubjectAndIndependentActor(final boolean serviceKeys) throws Throwable {
        val caller = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        val issuer = serviceKeys ? addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE)) : null;
        if (issuer != null) {
            issuer.getProperties().put(
                RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_SIGNING_KEY.getPropertyName(),
                new DefaultRegisteredServiceProperty(UUID.randomUUID().toString() + UUID.randomUUID()));
            issuer.getProperties().put(
                RegisteredServiceProperty.RegisteredServiceProperties.ACCESS_TOKEN_AS_JWT_ENCRYPTION_ENABLED.getPropertyName(),
                new DefaultRegisteredServiceProperty("false"));
            servicesManager.save(issuer);
        }
        val callerPolicy = new DefaultRegisteredServiceOAuthTokenExchangePolicy();
        if (issuer != null) {
            callerPolicy.setTrustedTokenIssuers(Map.of(issuer.getClientId(), issuer.getId()));
        }
        caller.setTokenExchangePolicy(callerPolicy);
        caller.setJwtAccessToken(true);
        servicesManager.save(caller);
        val issuerId = issuer == null
            ? configurationContext.getCasProperties().getServer().getPrefix() : issuer.getClientId();
        val claims = new JWTClaimsSet.Builder().issuer(issuerId).subject("resource-owner")
            .audience(caller.getClientId()).issueTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 3600_000)).build();
        val subject = accessTokenJwtBuilder.build(issuer, claims);
        val actorClaims = new JWTClaimsSet.Builder(claims).subject("independent-delegate")
            .claim(OAuth20Constants.CLIENT_ID, "independent-client").build();
        val actor = accessTokenJwtBuilder.build(issuer, actorClaims);
        val context = exchangeContext(caller, subject, actor, Set.of("resource-server"));
        ((MockHttpServletRequest) context.getNativeRequest()).setParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.JWT.getType());
        ((MockHttpServletRequest) context.getNativeRequest()).setParameter(OAuth20Constants.ACTOR_TOKEN_TYPE, OAuth20TokenExchangeTypes.JWT.getType());
        val extracted = extractor.extract(context);
        assertEquals("resource-owner", extracted.getAuthentication().getPrincipal().getId());
        assertEquals("independent-delegate", extracted.getActorToken().getPrincipal().getId());
        val token = (OAuth20AccessToken) oauthTokenGenerator.generate(extracted).getAccessToken().orElseThrow();
        assertEquals("resource-owner", token.getAuthentication().getPrincipal().getId());
        assertEquals("independent-delegate", token.getActor().get("sub"));
        assertEquals(issuerId, token.getActor().get("iss"));
        val encoded = OAuth20JwtAccessTokenEncoder.toEncodableCipher(configurationContext, caller, token).encode(token.getId());
        val emitted = accessTokenJwtBuilder.unpack(Optional.of(caller), encoded);
        assertEquals(configurationContext.getCasProperties().getServer().getPrefix(), emitted.getIssuer());
        assertEquals(List.of("resource-server"), emitted.getAudience());
        assertEquals("resource-owner", emitted.getSubject());
        assertEquals(token.getId(), emitted.getJWTID());
        assertEquals(token.getActor(), emitted.getJSONObjectClaim("act"));
        assertEquals(OAuth20GrantTypes.TOKEN_EXCHANGE.getType(), emitted.getStringClaim(OAuth20Constants.GRANT_TYPE));
        ((MockHttpServletRequest) context.getNativeRequest()).setParameter(OAuth20Constants.ACTOR_TOKEN,
            accessTokenJwtBuilder.build(issuer, new JWTClaimsSet.Builder(actorClaims).expirationTime(new Date(0)).build()));
        assertThrows(Exception.class, () -> extractor.extract(context));
        ((MockHttpServletRequest) context.getNativeRequest()).setParameter(OAuth20Constants.ACTOR_TOKEN, actor);
        ((MockHttpServletRequest) context.getNativeRequest()).removeParameter(OAuth20Constants.ACTOR_TOKEN_TYPE);
        assertThrows(IllegalArgumentException.class, () -> extractor.extract(context));
        ((MockHttpServletRequest) context.getNativeRequest()).setParameter(OAuth20Constants.ACTOR_TOKEN_TYPE, OAuth20TokenExchangeTypes.JWT.getType());
        callerPolicy.setRequiredActorTokenAttributes(Map.of(OAuth20Constants.CLIENT_ID, List.of("^" + caller.getClientId() + "$")));
        servicesManager.save(caller);
        assertThrows(IllegalArgumentException.class, () -> extractor.extract(context));
    }

    @Test
    void verifyMultiTargetAuthorizationAndPersistence() throws Throwable {
        val caller = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        val policy = new DefaultRegisteredServiceOAuthTokenExchangePolicy()
            .setAllowedAudience(Set.of("^resource-[ab]$"));
        caller.setTokenExchangePolicy(policy);
        servicesManager.save(caller);
        val subject = getAccessToken(caller.getServiceId(), caller.getClientId());
        ticketRegistry.addTicket(subject);
        val context = exchangeContext(caller, subject.getId(), null, Set.of("resource-a", "resource-b"));
        assertThrows(IllegalArgumentException.class, () -> extractor.extract(context));
        policy.setRequireAllTargets(true);
        servicesManager.save(caller);
        val token = (OAuth20AccessToken) oauthTokenGenerator.generate(extractor.extract(context)).getAccessToken().orElseThrow();
        assertEquals(Set.of("resource-a", "resource-b"), token.getAudience());
        val mapper = JacksonObjectMapperFactory.builder().defaultTypingEnabled(true).build().toObjectMapper();
        val json = mapper.writeValueAsString(token);
        val restored = mapper.readValue(json, OAuth20DefaultAccessToken.class);
        assertEquals(token.getAudience(), restored.getAudience());
        val legacy = (ObjectNode) mapper.readTree(json);
        legacy.remove("audience");
        legacy.remove("actor");
        val old = mapper.treeToValue(legacy, OAuth20DefaultAccessToken.class);
        assertTrue(old.getAudience().isEmpty());
        assertTrue(old.getActor().isEmpty());
        ((MockHttpServletRequest) context.getNativeRequest()).setParameter(OAuth20Constants.AUDIENCE, "resource-a", "unapproved");
        assertThrows(IllegalArgumentException.class, () -> extractor.extract(context));
        ((MockHttpServletRequest) context.getNativeRequest()).setParameter(OAuth20Constants.AUDIENCE, "resource-a");
        ((MockHttpServletRequest) context.getNativeRequest()).setParameter(OAuth20Constants.RESOURCE, "https://api.example.org/records");
        policy.setAllowedResources(Set.of(Pattern.quote("https://api.example.org/records")));
        servicesManager.save(caller);
        val resourceToken = (OAuth20AccessToken) oauthTokenGenerator.generate(extractor.extract(context)).getAccessToken().orElseThrow();
        assertEquals(Set.of("resource-a", "https://api.example.org/records"), resourceToken.getAudience());
        val secondResource = "https://api.example.org/audit";
        policy.setAllowedResources(Set.of(Pattern.quote("https://api.example.org/records"), Pattern.quote(secondResource)));
        servicesManager.save(caller);
        val request = (MockHttpServletRequest) context.getNativeRequest();
        request.setParameter(OAuth20Constants.RESOURCE, "https://api.example.org/records", secondResource);
        val multiple = (OAuth20AccessToken) oauthTokenGenerator.generate(extractor.extract(context)).getAccessToken().orElseThrow();
        assertEquals(Set.of("resource-a", "https://api.example.org/records", secondResource), multiple.getAudience());
        request.setParameter(OAuth20Constants.RESOURCE, "https://api.example.org/records", "https://api.example.org/unapproved");
        assertThrows(IllegalArgumentException.class, () -> extractor.extract(context));
        request.setParameter(OAuth20Constants.RESOURCE, "relative-resource");
        assertThrows(IllegalArgumentException.class, () -> extractor.extract(context));
        request.setParameter(OAuth20Constants.RESOURCE, " ");
        assertThrows(IllegalArgumentException.class, () -> extractor.extract(context));
    }


    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void verifyRequestObjectTargets(final boolean array) throws Throwable {
        val caller = addRegisteredService(Set.of(OAuth20GrantTypes.TOKEN_EXCHANGE));
        val subject = getAccessToken(caller.getServiceId(), caller.getClientId());
        ticketRegistry.addTicket(subject);
        caller.setTokenExchangePolicy(new DefaultRegisteredServiceOAuthTokenExchangePolicy()
            .setAllowedAudience(Set.of("^api-[ab]$")).setRequireAllTargets(true));
        servicesManager.save(caller);
        val context = exchangeContext(caller, subject.getId(), null, Set.of("ignored-form-target"));
        val request = (MockHttpServletRequest) context.getNativeRequest();
        request.setParameter(OAuth20Constants.CLIENT_ID, caller.getClientId());
        val claims = new JWTClaimsSet.Builder().issuer(configurationContext.getCasProperties().getServer().getPrefix())
            .subject("client-request").claim(OAuth20Constants.AUDIENCE, array ? List.of("api-a", "api-b") : "api-a")
            .issueTime(new Date()).expirationTime(new Date(System.currentTimeMillis() + 3600_000)).build();
        request.setParameter(OAuth20Constants.REQUEST, accessTokenJwtBuilder.build(null, claims));
        val extracted = extractor.extract(context);
        assertEquals(array ? Set.of("api-a", "api-b") : Set.of("api-a"), extracted.getTokenExchangeAudiences());
    }

    private JEEContext exchangeContext(final OAuthRegisteredService caller,
                                       final String subject, final String actor, final Set<String> audience) {
        val request = new MockHttpServletRequest();
        request.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.TOKEN_EXCHANGE.getType());
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN, subject);
        request.setParameter(OAuth20Constants.SUBJECT_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());
        request.setParameter(OAuth20Constants.AUDIENCE, audience.toArray(String[]::new));
        if (actor != null) {
            request.setParameter(OAuth20Constants.ACTOR_TOKEN, actor);
            request.setParameter(OAuth20Constants.ACTOR_TOKEN_TYPE, OAuth20TokenExchangeTypes.ACCESS_TOKEN.getType());
        }
        val context = new JEEContext(request, new MockHttpServletResponse());
        val profile = new CommonProfile();
        profile.setId("mapped-client-principal");
        profile.addAttribute(OAuth20Constants.CLIENT_ID, caller.getClientId());
        new ProfileManager(context, oauthDistributedSessionStore).save(true, profile, false);
        return context;
    }

}
