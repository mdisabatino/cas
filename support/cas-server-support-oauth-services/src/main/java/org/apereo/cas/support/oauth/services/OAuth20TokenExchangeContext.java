package org.apereo.cas.support.oauth.services;

import org.apereo.cas.authentication.Authentication;

import java.util.Set;

/**
 * Verified identities and destinations used to authorize a token exchange.
 * No encoded tokens or credentials are retained in this context.
 *
 * @author CAS Contributors
 * @param requestingService authenticated requesting service
 * @param subject subject authentication
 * @param subjectClientId client associated with the subject token, if any
 * @param subjectAudience verified or server-stored subject destinations
 * @param actor actor authentication, if supplied
 * @param actorTokenType actor token type, if supplied
 * @param resources requested resources
 * @param audience requested audience
 * @param requestedType requested output token type
 * @since 7.3.8
 */
public record OAuth20TokenExchangeContext(OAuthRegisteredService requestingService,
                                          Authentication subject, String subjectClientId,
                                          Set<String> subjectAudience, Authentication actor,
                                          String actorTokenType, Set<String> resources,
                                          Set<String> audience, String requestedType) {
    /** Snapshot target identifiers before invoking policy code. */
    public OAuth20TokenExchangeContext {
        subjectAudience = Set.copyOf(subjectAudience);
        resources = Set.copyOf(resources);
        audience = Set.copyOf(audience);
    }
}
