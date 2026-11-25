package org.apereo.cas.support.oauth.services;

import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.serialization.JacksonObjectMapperFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.val;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link DefaultRegisteredServiceOAuthTokenExchangePolicyTests}.
 *
 * @author Misagh Moayyed
 * @since 7.1.0
 */
@Tag("OAuth")
class DefaultRegisteredServiceOAuthTokenExchangePolicyTests {
    private static final File JSON_FILE = new File(FileUtils.getTempDirectoryPath(), "RegisteredServiceOAuthTokenExchangePolicyTests.json");

    private static final ObjectMapper MAPPER = JacksonObjectMapperFactory.builder()
        .defaultTypingEnabled(true).build().toObjectMapper();

    @Test
    void verifyOperation() throws Exception {
        val policy = new DefaultRegisteredServiceOAuthTokenExchangePolicy()
            .setAllowedAudience(CollectionUtils.wrapSet(".*"))
            .setAllowedTokenTypes(Set.of(".*access-token.*"))
            .setAllowedActorTokenTypes(Set.of(".*"));
        assertTrue(policy.isTokenExchangeAllowed(new OAuthRegisteredService(), Set.of("resource"),
            Set.of("audience"), "access-token"));
        MAPPER.writeValue(JSON_FILE, policy);
        val strategyRead = MAPPER.readValue(JSON_FILE, DefaultRegisteredServiceOAuthTokenExchangePolicy.class);
        assertEquals(policy, strategyRead);
    }

    @Test
    void verifyActorToken() {
        val policy = new DefaultRegisteredServiceOAuthTokenExchangePolicy()
            .setAllowedActorTokenTypes(Set.of(".*"))
            .setRequiredActorTokenAttributes(Map.of("common-name", List.of("nothing|.*cas")));
        val actor = CoreAuthenticationTestUtils.getAuthentication(
            CoreAuthenticationTestUtils.getPrincipal(UUID.randomUUID().toString(), Map.of("common-name", List.of("anything-cas"))));
        val subject = CoreAuthenticationTestUtils.getAuthentication(CoreAuthenticationTestUtils.getPrincipal(UUID.randomUUID().toString()));
        assertTrue(policy.canSubjectTokenActAs(subject, actor, "anything"));
    }
    @Test
    void verifyExplicitAllTargetSemantics() throws Exception {
        val service = new OAuthRegisteredService();
        val policy = new DefaultRegisteredServiceOAuthTokenExchangePolicy().setAllowedAudience(Set.of("^api-a$"));
        assertTrue(policy.isTokenExchangeAllowed(service, Set.of(), Set.of("api-a", "api-b"), "jwt"));
        assertFalse(policy.isMultipleTargetsAllowed());
        policy.setRequireAllTargets(true);
        assertTrue(policy.isMultipleTargetsAllowed());
        assertFalse(policy.isTokenExchangeAllowed(service, Set.of(), Set.of("api-a", "api-b"), "jwt"));
        assertTrue(policy.isTokenExchangeAllowed(service, Set.of(), Set.of("api-a"), "jwt"));
        policy.setTrustedTokenIssuers(Map.of("https://issuer.example.org", 7L));
        val restored = MAPPER.readValue(MAPPER.writeValueAsString(policy), DefaultRegisteredServiceOAuthTokenExchangePolicy.class);
        assertEquals(Map.of("https://issuer.example.org", 7L), restored.trustedTokenIssuers());
        assertEquals(policy, restored);
    }

    @Test
    void verifySubjectDestinationsAndIndependentActor() {
        val service = new OAuthRegisteredService();
        service.setClientId("requesting-client");
        val subject = CoreAuthenticationTestUtils.getAuthentication(CoreAuthenticationTestUtils.getPrincipal("resource-owner"));
        val actor = CoreAuthenticationTestUtils.getAuthentication(CoreAuthenticationTestUtils.getPrincipal("independent-delegate"));
        val context = new OAuth20TokenExchangeContext(service, subject, "original-client", Set.of("requesting-client"),
            actor, "access-token", Set.of(), Set.of("api"), "jwt");
        val policy = new DefaultRegisteredServiceOAuthTokenExchangePolicy();
        assertTrue(policy.isTokenExchangeAllowed(context));
        policy.setRequiredActorTokenAttributes(Map.of("client_id", List.of("^requesting-client$")));
        assertFalse(policy.isTokenExchangeAllowed(context));
        assertFalse(policy.isSubjectTokenUsable(new OAuth20TokenExchangeContext(service, subject, "original-client", Set.of(),
            null, null, Set.of(), Set.of("api"), "jwt")));
    }

}
