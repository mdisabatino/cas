package org.apereo.cas.support.oauth.services;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.services.RegisteredService;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;

/**
 * This is {@link RegisteredServiceOAuthTokenExchangePolicy}.
 *
 * @author Misagh Moayyed
 * @since 7.1.0
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
public interface RegisteredServiceOAuthTokenExchangePolicy extends Serializable {

    /**
     * Is token exchange allowed?
     *
     * @param registeredService the registered service
     * @param resources         the resources
     * @param audience          the audience
     * @param requestedType     the requested token type
     * @return true /false
     */
    boolean isTokenExchangeAllowed(RegisteredService registeredService, Set<String> resources,
                                   Set<String> audience, String requestedType);

    /**
     * Authorize the complete exchange while preserving existing policy implementations.
     *
     * @param context verified exchange context
     * @return whether the exchange is authorized
     */
    default boolean isTokenExchangeAllowed(final OAuth20TokenExchangeContext context) {
        return isSubjectTokenUsable(context)
            && isTokenExchangeAllowed(context.requestingService(), context.resources(), context.audience(), context.requestedType())
            && (context.actor() == null || canSubjectTokenActAs(context.subject(), context.actor(), context.actorTokenType()));
    }



    /**
     * Authorize a verified subject token for the authenticated requesting client.
     * Older opaque tickets without destination metadata remain owner-bound.
     *
     * @param context verified exchange context
     * @return whether the subject is usable by the requester
     */
    default boolean isSubjectTokenUsable(final OAuth20TokenExchangeContext context) {
        return context.subjectAudience().isEmpty()
            ? context.requestingService().getClientId().equals(context.subjectClientId())
            : context.subjectAudience().contains(context.requestingService().getClientId());
    }

    /**
     * Whether this policy explicitly supports issuing a token for multiple targets.
     *
     * @return whether multiple targets are supported
     */
    @JsonIgnore
    default boolean isMultipleTargetsAllowed() {
        return false;
    }

    /**
     * Can subject token act.
     *
     * @param subject        the subject
     * @param actor          the actor
     * @param actorTokenType the actor token type
     * @return true/false
     */
    boolean canSubjectTokenActAs(Authentication subject, Authentication actor, String actorTokenType);
    /**
     * Explicitly trusted standalone issuers and their local verification services.
     * Configuring JWT keys on a relying party alone does not grant issuer authority.
     *
     * @return issuer to registered-service identifier mappings
     */
    default Map<String, Long> trustedTokenIssuers() {
        return Map.of();
    }

}
