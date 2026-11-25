package org.apereo.cas.support.oauth.util;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.DefaultAuthenticationBuilder;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20ConfigurationContext;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import lombok.experimental.UtilityClass;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Normalizes actor identities and copies actor delegation claims for token exchange.
 *
 * @author Marco Di Sabatino Di Diodoro
 * @since 7.3.0
 */
@UtilityClass
public class OAuth20TokenExchangeActorUtils {
    /**
     * Normalize token-bound client metadata independently of principal attributes.
     *
     * @param context configuration
     * @param ticket access ticket
     * @param issuer local issuer for the actor identity
     * @return authentication with authoritative client metadata
     * @throws Throwable on principal construction failures
     */
    public Authentication authentication(final OAuth20ConfigurationContext context, final OAuth20AccessToken ticket,
                                         final String issuer) throws Throwable {
        val source = ticket.getAuthentication();
        val attributes = new HashMap<>(source.getAttributes());
        val principalAttributes = new HashMap<>(source.getPrincipal().getAttributes());
        attributes.put(OAuth20Constants.CLIENT_ID, List.of(ticket.getClientId()));
        attributes.put("iss", List.of(issuer));
        principalAttributes.put("iss", List.of(issuer));
        principalAttributes.put(OAuth20Constants.CLIENT_ID, List.of(ticket.getClientId()));
        attributes.put(OAuth20Constants.CLAIM_SUB, List.of(source.getPrincipal().getId()));
        principalAttributes.put(OAuth20Constants.CLAIM_SUB, List.of(source.getPrincipal().getId()));
        attributes.put(OAuth20Constants.GRANT_TYPE, List.of(ticket.getGrantType().getType()));
        principalAttributes.put(OAuth20Constants.GRANT_TYPE, List.of(ticket.getGrantType().getType()));
        return DefaultAuthenticationBuilder.newInstance(source)
            .setPrincipal(context.getPrincipalFactory().createPrincipal(source.getPrincipal().getId(), principalAttributes))
            .setAttributes(attributes).build();
    }

    /**
     * Normalize a verified session actor without inventing an OAuth client identity.
     *
     * @param context configuration
     * @param source verified session authentication
     * @param issuer verified issuer of the session proof
     * @return actor authentication
     * @throws Throwable on principal construction failures
     */
    public Authentication authentication(final OAuth20ConfigurationContext context, final Authentication source,
                                         final String issuer) throws Throwable {
        val attributes = new HashMap<>(source.getAttributes());
        val principalAttributes = new HashMap<>(source.getPrincipal().getAttributes());
        for (val key : List.of(OAuth20Constants.CLIENT_ID, OAuth20Constants.GRANT_TYPE)) {
            attributes.remove(key);
            principalAttributes.remove(key);
        }
        attributes.put("iss", List.of(issuer));
        principalAttributes.put("iss", List.of(issuer));
        attributes.put(OAuth20Constants.CLAIM_SUB, List.of(source.getPrincipal().getId()));
        principalAttributes.put(OAuth20Constants.CLAIM_SUB, List.of(source.getPrincipal().getId()));
        return DefaultAuthenticationBuilder.newInstance(source)
            .setPrincipal(context.getPrincipalFactory().createPrincipal(source.getPrincipal().getId(), principalAttributes))
            .setAttributes(attributes).build();
    }

    /**
     * Copy identity claims and the complete actor history without a fixed depth limit.
     *
     * @param actor source actor
     * @return immutable protocol actor chain
     */
    public Map<String, Object> copyActor(final Map<?, ?> actor) {
        if (actor.isEmpty()) {
            return Map.of();
        }
        val history = new ArrayList<Map<String, Object>>();
        val visited = new IdentityHashMap<Map<?, ?>, Boolean>();
        Map<?, ?> current = actor;
        while (current != null) {
            if (visited.put(current, Boolean.TRUE) != null) {
                throw new IllegalArgumentException("Actor history cannot contain cycles");
            }
            if (!(current.get(OAuth20Constants.CLAIM_SUB) instanceof String subject) || StringUtils.isBlank(subject)) {
                throw new IllegalArgumentException("Actor identity must contain a subject");
            }
            val identity = new LinkedHashMap<String, Object>();
            identity.put(OAuth20Constants.CLAIM_SUB, subject);
            if (current.containsKey("iss")) {
                if (!(current.get("iss") instanceof String issuer) || StringUtils.isBlank(issuer)) {
                    throw new IllegalArgumentException("Actor issuer must be an identifier");
                }
                identity.put("iss", issuer);
            }
            history.add(identity);
            val previous = current.get(OAuth20Constants.CLAIM_ACT);
            if (previous != null && !(previous instanceof Map<?, ?>)) {
                throw new IllegalArgumentException("Actor history must contain an object");
            }
            current = (Map<?, ?>) previous;
        }
        Map<String, Object> result = Map.of();
        for (var i = history.size() - 1; i >= 0; i--) {
            val identity = history.get(i);
            if (!result.isEmpty()) {
                identity.put(OAuth20Constants.CLAIM_ACT, result);
            }
            result = Map.copyOf(identity);
        }
        return result;
    }
}
