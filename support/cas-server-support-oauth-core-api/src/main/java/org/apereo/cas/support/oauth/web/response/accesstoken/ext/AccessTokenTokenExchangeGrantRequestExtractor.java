package org.apereo.cas.support.oauth.web.response.accesstoken.ext;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.OAuth20TokenExchangeTypes;
import org.apereo.cas.support.oauth.services.OAuth20TokenExchangeContext;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.services.RegisteredServiceOAuthTokenExchangePolicy;
import org.apereo.cas.support.oauth.util.OAuth20TokenExchangeActorUtils;
import org.apereo.cas.support.oauth.util.OAuth20TokenExchangePolicyUtils;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20ConfigurationContext;
import org.apereo.cas.util.function.FunctionUtils;

import com.nimbusds.jwt.JWTClaimsSet;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.springframework.beans.factory.ObjectProvider;

import java.io.Serializable;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;

/**
 * This is {@link AccessTokenTokenExchangeGrantRequestExtractor}.
 *
 * @author Misagh Moayyed
 * @since 7.1.0
 */
@Slf4j
public class AccessTokenTokenExchangeGrantRequestExtractor<T extends OAuth20ConfigurationContext> extends BaseAccessTokenGrantRequestExtractor<T> {
    public AccessTokenTokenExchangeGrantRequestExtractor(final ObjectProvider<T> configurationContext) {
        super(configurationContext);
    }

    @Override
    public boolean supports(final WebContext context) {
        val grantType = getConfigurationContext().getObject().getRequestParameterResolver()
            .resolveRequestParameter(context, OAuth20Constants.GRANT_TYPE).orElse(StringUtils.EMPTY);
        return OAuth20Utils.isGrantType(grantType, getGrantType());
    }

    @Override
    public OAuth20GrantTypes getGrantType() {
        return OAuth20GrantTypes.TOKEN_EXCHANGE;
    }

    @Override
    public OAuth20ResponseTypes getResponseType() {
        return OAuth20ResponseTypes.NONE;
    }

    @Override
    protected AccessTokenRequestContext extractRequest(final WebContext webContext) throws Throwable {
        val configurationContext = getConfigurationContext().getObject();

        val requestParameterResolver = configurationContext.getRequestParameterResolver();
        val scopes = requestParameterResolver.resolveRequestScopes(webContext);

        val requestedTokenType = requestParameterResolver.resolveRequestParameter(webContext, OAuth20Constants.REQUESTED_TOKEN_TYPE)
            .orElseGet(OAuth20TokenExchangeTypes.ACCESS_TOKEN::getType);
        val subjectTokenType = requestParameterResolver.resolveRequestParameter(webContext, OAuth20Constants.SUBJECT_TOKEN_TYPE)
            .map(OAuth20TokenExchangeTypes::from)
            .orElseThrow(() -> new IllegalArgumentException("Subject token type cannot be undefined"));
        val resources = requestParameterResolver.resolveTokenExchangeTargets(webContext, OAuth20Constants.RESOURCE);
        val audiences = requestParameterResolver.resolveTokenExchangeTargets(webContext, OAuth20Constants.AUDIENCE);
        val resource = resources.stream().findFirst();
        val audience = audiences.stream().findFirst().orElse(null);
        val requestingClientId = requestingClientId(webContext);
        val requestingService = Objects.requireNonNull(OAuth20Utils.getRegisteredOAuthServiceByClientId(
            configurationContext.getServicesManager(), requestingClientId));
        val extractedRequest = extractSubjectTokenExchangeRequest(webContext);
        val actor = getActorTokenAuthentication(webContext, extractedRequest);
        val actorType = requestParameterResolver.resolveRequestParameter(webContext, OAuth20Constants.ACTOR_TOKEN_TYPE)
            .map(OAuth20TokenExchangeTypes::from).map(OAuth20TokenExchangeTypes::getType).orElse(null);
        var subjectClientId = requestingClientId;
        val subjectAudience = new LinkedHashSet<String>();
        if (subjectTokenType == OAuth20TokenExchangeTypes.ACCESS_TOKEN) {
            val rawSubject = requestParameterResolver.resolveRequestParameter(webContext, OAuth20Constants.SUBJECT_TOKEN).orElseThrow();
            val verified = OAuth20TokenExchangePolicyUtils.accessToken(configurationContext, rawSubject);
            subjectClientId = verified.ticket().getClientId();
            subjectAudience.addAll(OAuth20TokenExchangePolicyUtils.subjectAudience(verified));
        } else if (extractedRequest.token() instanceof JWTClaimsSet claims) {
            subjectClientId = claims.getStringClaim(OAuth20Constants.CLIENT_ID);
            subjectAudience.addAll(claims.getAudience());
        } else {
            subjectAudience.add(requestingClientId);
        }
        val policy = OAuth20TokenExchangePolicyUtils.policy(requestingService);
        val exchangeContext = new OAuth20TokenExchangeContext(requestingService, extractedRequest.authentication(),
            subjectClientId, subjectAudience, actor, actorType, resources, audiences, requestedTokenType);
        if (!OAuth20TokenExchangePolicyUtils.targetsAllowed(policy, resources, audiences) || !policy.isTokenExchangeAllowed(exchangeContext)) {
            throw new IllegalArgumentException("Token exchange is not authorized by policy");
        }
        val resourceService = resource
            .map(res -> {
                val service = configurationContext.getWebApplicationServiceServiceFactory().createService(res);
                service.getAttributes().put(OAuth20Constants.CLIENT_ID, List.of(requestingService.getClientId()));
                return service;
            })
            .orElse(null);

        return AccessTokenRequestContext
            .builder()
            .scopes(scopes)
            .grantType(getGrantType())
            .subjectTokenType(subjectTokenType)
            .requestedTokenType(OAuth20TokenExchangeTypes.from(requestedTokenType))
            .subjectToken(extractedRequest.token())
            .tokenExchangeResource(resourceService)
            .tokenExchangeAudience(audience)
            .service(extractedRequest.service())
            .registeredService(requestingService)
            .authentication(extractedRequest.authentication())
            .tokenExchangeAudiences(audiences)
            .tokenExchangeResources(resources)
            .actorToken(actor)
            .build();
    }

    protected TokenExchangeRequest extractSubjectTokenExchangeRequest(final WebContext webContext) throws Throwable {
        val configurationContext = getConfigurationContext().getObject();
        val requestParameterResolver = configurationContext.getRequestParameterResolver();
        val subjectTokenType = requestParameterResolver.resolveRequestParameter(webContext, OAuth20Constants.SUBJECT_TOKEN_TYPE)
            .map(OAuth20TokenExchangeTypes::from)
            .orElseThrow();

        val subjectToken = requestParameterResolver.resolveRequestParameter(webContext, OAuth20Constants.SUBJECT_TOKEN)
            .orElseThrow(() -> new IllegalArgumentException("Subject token cannot be undefined"));
        return switch (subjectTokenType) {
            case ACCESS_TOKEN -> {
                val accessToken = OAuth20TokenExchangePolicyUtils.accessToken(configurationContext, subjectToken);
                val token = accessToken.ticket();
                yield new TokenExchangeRequest(token, token.getService(), accessToken.registeredService(), token.getAuthentication());
            }
            case JWT -> {
                val policy = requestingPolicy(webContext);
                val claims = OAuth20TokenExchangePolicyUtils.standaloneJwt(configurationContext, subjectToken, policy, resolveAccessTokenActorIssuer(null));
                val service = configurationContext.getWebApplicationServiceServiceFactory().createService(claims.getIssuer());
                val verificationServiceId = policy.trustedTokenIssuers().get(claims.getIssuer());
                val registeredService = verificationServiceId == null ? null
                    : configurationContext.getServicesManager().findServiceBy(verificationServiceId, OAuthRegisteredService.class);
                yield new TokenExchangeRequest(claims, service, registeredService, OAuth20TokenExchangePolicyUtils.authentication(configurationContext, claims));
            }
            default -> throw new IllegalArgumentException("Subject token type %s is not supported".formatted(subjectTokenType));
        };
    }

    protected Authentication getActorTokenAuthentication(final WebContext webContext, final TokenExchangeRequest extractedRequest) throws Throwable {
        val configurationContext = getConfigurationContext().getObject();
        val actorToken = configurationContext.getRequestParameterResolver().resolveRequestParameter(webContext, OAuth20Constants.ACTOR_TOKEN);
        val actorTokenType = configurationContext.getRequestParameterResolver().resolveRequestParameter(webContext, OAuth20Constants.ACTOR_TOKEN_TYPE)
            .map(OAuth20TokenExchangeTypes::from);
        FunctionUtils.throwIf(actorToken.isPresent() != actorTokenType.isPresent(),
            () -> new IllegalArgumentException("Actor token and actor token type must be supplied together"));
        if (actorToken.isPresent()) {
            return extractActorTokenAuthentication(webContext);
        }
        return null;
    }

    protected Authentication extractActorTokenAuthentication(final WebContext webContext) throws Throwable {
        val configurationContext = getConfigurationContext().getObject();
        val actorToken = configurationContext.getRequestParameterResolver().resolveRequestParameter(webContext, OAuth20Constants.ACTOR_TOKEN).orElseThrow();
        val actorTokenType = configurationContext.getRequestParameterResolver().resolveRequestParameter(webContext, OAuth20Constants.ACTOR_TOKEN_TYPE)
            .map(OAuth20TokenExchangeTypes::from)
            .orElseThrow();
        return switch (actorTokenType) {
            case ACCESS_TOKEN -> {
                val accessToken = OAuth20TokenExchangePolicyUtils.accessToken(configurationContext, actorToken);
                val issuer = resolveAccessTokenActorIssuer(accessToken.registeredService());
                yield OAuth20TokenExchangeActorUtils.authentication(configurationContext, accessToken.ticket(), issuer);
            }
            case JWT -> buildActorTokenAuthenticationFromJwt(actorToken, webContext);
            default -> throw new IllegalArgumentException("Actor token type %s is not supported".formatted(actorTokenType));
        };
    }

    /**
     * Determine the local issuer for an access token actor or standalone JWT.
     *
     * @param registeredService the service bound to the actor ticket, or null for a standalone JWT
     * @return the issuer identifier
     */
    protected String resolveAccessTokenActorIssuer(final OAuthRegisteredService registeredService) {
        return getConfigurationContext().getObject().getCasProperties().getServer().getPrefix();
    }

    protected Authentication buildActorTokenAuthenticationFromJwt(final String actorToken, final WebContext webContext) throws Throwable {
        val configurationContext = getConfigurationContext().getObject();
        val claims = OAuth20TokenExchangePolicyUtils.standaloneJwt(configurationContext, actorToken,
            requestingPolicy(webContext), resolveAccessTokenActorIssuer(null));
        return OAuth20TokenExchangePolicyUtils.authentication(configurationContext, claims);
    }

    private RegisteredServiceOAuthTokenExchangePolicy requestingPolicy(final WebContext webContext) {
        val configuration = getConfigurationContext().getObject();
        val clientId = requestingClientId(webContext);
        return OAuth20TokenExchangePolicyUtils.policy(Objects.requireNonNull(OAuth20Utils.getRegisteredOAuthServiceByClientId(
            configuration.getServicesManager(), clientId)));
    }

    private String requestingClientId(final WebContext webContext) {
        val configurationContext = getConfigurationContext().getObject();
        val requestParameterResolver = configurationContext.getRequestParameterResolver();
        val profile = extractUserProfile(webContext)
            .orElseThrow(() -> new IllegalArgumentException("Authenticated OAuth client identity is required"));
        if (!(profile.getAttribute(OAuth20Constants.CLIENT_ID) instanceof String requestingClientId) || StringUtils.isBlank(requestingClientId)) {
            throw new IllegalArgumentException("Authenticated OAuth client identity is required");
        }
        val suppliedId = requestParameterResolver
            .resolveClientIdAndClientSecret(new CallContext(webContext, configurationContext.getSessionStore())).getKey();
        if (StringUtils.isNotBlank(suppliedId) && !requestingClientId.equals(suppliedId)) {
            throw new IllegalArgumentException("Authenticated OAuth client identity is required");
        }
        return requestingClientId;
    }

    public record TokenExchangeRequest(Serializable token, Service service,
        OAuthRegisteredService registeredService, Authentication authentication) {
    }
}
