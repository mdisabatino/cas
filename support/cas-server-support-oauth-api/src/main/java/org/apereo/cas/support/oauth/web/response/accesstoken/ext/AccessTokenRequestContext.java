package org.apereo.cas.support.oauth.web.response.accesstoken.ext;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseModeTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.OAuth20TokenExchangeTypes;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.ticket.OAuth20Token;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.code.OAuth20Code;
import org.apereo.cas.ticket.refreshtoken.OAuth20RefreshToken;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.With;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;
import net.minidev.json.annotate.JsonIgnore;
import org.pac4j.core.profile.UserProfile;

import java.io.Serial;
import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * This is {@link AccessTokenRequestContext}.
 *
 * @author Misagh Moayyed
 * @since 5.1.0
 */
@ToString
@Getter
@SuperBuilder
@Jacksonized
@With
@AllArgsConstructor
public class AccessTokenRequestContext implements Serializable {

    @Serial
    private static final long serialVersionUID = 1428887534614525042L;

    private final Service service;

    private final Authentication authentication;

    private final Authentication actorToken;

    private final OAuth20Token token;

    private final boolean generateRefreshToken;

    private final boolean expireOldRefreshToken;

    private final OAuthRegisteredService registeredService;

    private final Ticket ticketGrantingTicket;

    @Builder.Default
    private final OAuth20GrantTypes grantType = OAuth20GrantTypes.NONE;

    @Builder.Default
    private final Set<String> scopes = new LinkedHashSet<>();

    @Builder.Default
    private final Map<String, Map<String, Object>> claims = new HashMap<>();

    @Builder.Default
    private final Map<String, Object> parameters = new HashMap<>();

    @Builder.Default
    private final OAuth20ResponseModeTypes responseMode = OAuth20ResponseModeTypes.NONE;

    @Builder.Default
    private final OAuth20ResponseTypes responseType = OAuth20ResponseTypes.NONE;

    private final String deviceCode;

    private final String codeChallenge;

    private final OAuth20TokenExchangeTypes subjectTokenType;

    private final OAuth20TokenExchangeTypes requestedTokenType;

    private final Serializable subjectToken;

    private final Service tokenExchangeResource;

    private final String tokenExchangeAudience;

    @Builder.Default
    private final Set<String> tokenExchangeAudiences = new LinkedHashSet<>();

    @Builder.Default
    private final Set<String> tokenExchangeResources = new LinkedHashSet<>();

    @Builder.Default
    private final String codeChallengeMethod = "plain";

    private final String codeVerifier;

    private final String clientId;

    private final String redirectUri;

    @Setter
    private UserProfile userProfile;

    @Setter
    private String dpopConfirmation;

    @Setter
    private String dpop;

    private final String cibaRequestId;
    
    /**
     * Retain the release constructor descriptor for existing OAuth extensions.
     *
     * @param service service
     * @param authentication authentication
     * @param actorToken actor token
     * @param token token
     * @param generateRefreshToken generate refresh token
     * @param expireOldRefreshToken expire old refresh token
     * @param registeredService registered service
     * @param ticketGrantingTicket ticket granting ticket
     * @param grantType grant type
     * @param scopes scopes
     * @param claims claims
     * @param parameters parameters
     * @param responseMode response mode
     * @param responseType response type
     * @param deviceCode device code
     * @param codeChallenge code challenge
     * @param subjectTokenType subject token type
     * @param requestedTokenType requested token type
     * @param subjectToken subject token
     * @param tokenExchangeResource token exchange resource
     * @param tokenExchangeAudience token exchange audience
     * @param codeChallengeMethod code challenge method
     * @param codeVerifier code verifier
     * @param clientId client id
     * @param redirectUri redirect uri
     * @param userProfile user profile
     * @param dpopConfirmation dpop confirmation
     * @param dpop dpop
     * @param cibaRequestId ciba request id
     */
    //CHECKSTYLE:OFF
    public AccessTokenRequestContext(final Service service,
                                     final Authentication authentication,
                                     final Authentication actorToken,
                                     final OAuth20Token token,
                                     final boolean generateRefreshToken,
                                     final boolean expireOldRefreshToken,
                                     final OAuthRegisteredService registeredService,
                                     final Ticket ticketGrantingTicket,
                                     final OAuth20GrantTypes grantType,
                                     final Set<String> scopes,
                                     final Map<String, Map<String, Object>> claims,
                                     final Map<String, Object> parameters,
                                     final OAuth20ResponseModeTypes responseMode,
                                     final OAuth20ResponseTypes responseType,
                                     final String deviceCode,
                                     final String codeChallenge,
                                     final OAuth20TokenExchangeTypes subjectTokenType,
                                     final OAuth20TokenExchangeTypes requestedTokenType,
                                     final Serializable subjectToken,
                                     final Service tokenExchangeResource,
                                     final String tokenExchangeAudience,
                                     final String codeChallengeMethod,
                                     final String codeVerifier,
                                     final String clientId,
                                     final String redirectUri,
                                     final UserProfile userProfile,
                                     final String dpopConfirmation,
                                     final String dpop,
                                     final String cibaRequestId) {
        this(service, authentication, actorToken, token, generateRefreshToken, expireOldRefreshToken, registeredService, ticketGrantingTicket,
            grantType, scopes, claims, parameters, responseMode, responseType, deviceCode, codeChallenge,
            subjectTokenType, requestedTokenType, subjectToken, tokenExchangeResource, tokenExchangeAudience, Set.of(), Set.of(), codeChallengeMethod,
            codeVerifier, clientId, redirectUri, userProfile, dpopConfirmation, dpop, cibaRequestId);
    }

    //CHECKSTYLE:ON

    public Set<String> getTokenExchangeAudiences() {
        return tokenExchangeAudiences == null ? Set.of() : tokenExchangeAudiences;
    }

    public Set<String> getTokenExchangeResources() {
        return tokenExchangeResources == null ? Set.of() : tokenExchangeResources;
    }

    @JsonIgnore
    public boolean isCodeToken() {
        return token instanceof OAuth20Code;
    }

    @JsonIgnore
    public boolean isRefreshToken() {
        return token instanceof OAuth20RefreshToken;
    }
}
