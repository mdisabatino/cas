package org.apereo.cas.support.oauth.validator.token;

import org.apereo.cas.audit.AuditableContext;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20TokenExchangeTypes;
import org.apereo.cas.support.oauth.services.DefaultRegisteredServiceOAuthTokenExchangePolicy;
import org.apereo.cas.support.oauth.services.OAuth20TokenExchangeContext;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20TokenExchangePolicyUtils;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20ConfigurationContext;
import org.apereo.cas.util.function.FunctionUtils;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.springframework.beans.factory.ObjectProvider;

import java.util.Objects;
import java.util.Set;

/**
 * This is {@link OAuth20TokenExchangeGrantTypeTokenRequestValidator}.
 *
 * @author Misagh Moayyed
 * @since 7.1.0
 */
@Slf4j
public class OAuth20TokenExchangeGrantTypeTokenRequestValidator<T extends OAuth20ConfigurationContext> extends BaseOAuth20TokenRequestValidator<T> {
    public OAuth20TokenExchangeGrantTypeTokenRequestValidator(final ObjectProvider<T> configurationContext) {
        super(configurationContext);
    }

    @Override
    protected boolean validateInternal(final WebContext webContext, final String grantType,
                                       final ProfileManager manager, final UserProfile uProfile) throws Throwable {
        val configurationContext = getConfigurationContext().getObject();
        val requestParameterResolver = configurationContext.getRequestParameterResolver();
        val subjectTokenType = requestParameterResolver.resolveRequestParameter(webContext, OAuth20Constants.SUBJECT_TOKEN_TYPE)
            .orElseThrow(() -> new IllegalArgumentException("Subject token type cannot be undefined"));
        val subjectToken = requestParameterResolver.resolveRequestParameter(webContext, OAuth20Constants.SUBJECT_TOKEN)
            .orElseThrow(() -> new IllegalArgumentException("Subject token cannot be undefined"));
        val requestedTokenType = requestParameterResolver.resolveRequestParameter(webContext, OAuth20Constants.REQUESTED_TOKEN_TYPE)
            .orElseGet(OAuth20TokenExchangeTypes.ACCESS_TOKEN::getType);

        if (!(uProfile.getAttribute(OAuth20Constants.CLIENT_ID) instanceof String clientId) || StringUtils.isBlank(clientId)) {
            return false;
        }
        val suppliedId = requestParameterResolver
            .resolveClientIdAndClientSecret(new CallContext(webContext, configurationContext.getSessionStore())).getKey();
        if (StringUtils.isNotBlank(suppliedId) && !clientId.equals(suppliedId)) {
            return false;
        }
        val registeredService = OAuth20Utils.getRegisteredOAuthServiceByClientId(configurationContext.getServicesManager(), clientId);
        if (registeredService == null) {
            return false;
        }
        val originalService = extractRegisteredService(subjectTokenType, subjectToken, registeredService);
        val policy = OAuth20TokenExchangePolicyUtils.policy(registeredService);
        val type = OAuth20TokenExchangeTypes.from(subjectTokenType);
        if (originalService == null && type != OAuth20TokenExchangeTypes.JWT) {
            return false;
        }
        val subjectContext = switch (type) {
            case ACCESS_TOKEN -> {
                val token = OAuth20TokenExchangePolicyUtils.accessToken(configurationContext, subjectToken);
                yield new OAuth20TokenExchangeContext(registeredService, token.ticket().getAuthentication(),
                    token.ticket().getClientId(), OAuth20TokenExchangePolicyUtils.subjectAudience(token), null, null, Set.of(), Set.of(), requestedTokenType);
            }
            case JWT -> {
                val claims = OAuth20TokenExchangePolicyUtils.standaloneJwt(configurationContext, subjectToken, policy, resolveLocalIssuer());
                yield new OAuth20TokenExchangeContext(registeredService,
                    OAuth20TokenExchangePolicyUtils.authentication(configurationContext, claims), claims.getStringClaim(OAuth20Constants.CLIENT_ID),
                    Set.copyOf(claims.getAudience()), null, null, Set.of(), Set.of(), requestedTokenType);
            }
            default -> null;
        };
        if (subjectContext != null && !policy.isSubjectTokenUsable(subjectContext)) {
            return false;
        }

        val audit = AuditableContext.builder().registeredService(registeredService).build();
        val accessResult = configurationContext.getRegisteredServiceAccessStrategyEnforcer().execute(audit);
        accessResult.throwExceptionIfNeeded();

        if (!isGrantTypeSupportedBy(registeredService, getGrantType().getType(), true)) {
            LOGGER.warn("Requested grant type [{}] is not authorized by service definition [{}]",
                grantType, Objects.requireNonNull(registeredService).getServiceId());
            return false;
        }

        val actorToken = requestParameterResolver.resolveRequestParameter(webContext, OAuth20Constants.ACTOR_TOKEN);
        val actorTokenType = requestParameterResolver.resolveRequestParameter(webContext, OAuth20Constants.ACTOR_TOKEN_TYPE).map(OAuth20TokenExchangeTypes::from);
        FunctionUtils.throwIf(actorToken.isPresent() != actorTokenType.isPresent(),
            () -> new IllegalArgumentException("Actor token and actor token type must be supplied together"));

        val resources = requestParameterResolver.resolveTokenExchangeTargets(webContext, OAuth20Constants.RESOURCE);
        val audience = requestParameterResolver.resolveTokenExchangeTargets(webContext, OAuth20Constants.AUDIENCE);
        return OAuth20TokenExchangePolicyUtils.targetsAllowed(policy, resources, audience)
            && policy.isTokenExchangeAllowed(registeredService, resources, audience, requestedTokenType);
    }

    /**
     * Resolve standalone issuer authority using the authenticated requester's policy.
     * Other token types retain the existing service-resolution extension point.
     *
     * @param type subject token type
     * @param value encoded subject token
     * @param requester authenticated service
     * @return original verification service, if applicable
     * @throws Exception on invalid tokens
     */
    protected OAuthRegisteredService extractRegisteredService(final String type, final String value,
                                                              final OAuthRegisteredService requester) throws Exception {
        if (OAuth20TokenExchangeTypes.from(type) == OAuth20TokenExchangeTypes.JWT) {
            val configuration = getConfigurationContext().getObject();
            val policy = OAuth20TokenExchangePolicyUtils.policy(requester);
            val claims = OAuth20TokenExchangePolicyUtils.standaloneJwt(configuration, value, policy, resolveLocalIssuer());
            val serviceId = policy.trustedTokenIssuers().get(claims.getIssuer());
            return serviceId == null ? null : configuration.getServicesManager().findServiceBy(serviceId, OAuthRegisteredService.class);
        }
        return extractRegisteredService(type, value);
    }

    protected OAuthRegisteredService extractRegisteredService(final String subjectTokenType,
                                                              final String subjectToken) throws Exception {
        val configurationContext = getConfigurationContext().getObject();
        return switch (OAuth20TokenExchangeTypes.from(subjectTokenType)) {
            case ACCESS_TOKEN -> OAuth20TokenExchangePolicyUtils.accessToken(configurationContext, subjectToken).registeredService();
            case JWT -> {
                val claims = OAuth20TokenExchangePolicyUtils.standaloneJwt(configurationContext, subjectToken,
                    new DefaultRegisteredServiceOAuthTokenExchangePolicy(), resolveLocalIssuer());
                yield OAuth20Utils.getRegisteredOAuthServiceByClientId(configurationContext.getServicesManager(), claims.getIssuer());
            }
            default -> throw new IllegalArgumentException("Subject token type %s is not supported".formatted(subjectTokenType));
        };
    }

    /**
     * Determine the local authority for standalone JWTs.
     *
     * @return local issuer identifier
     */
    protected String resolveLocalIssuer() {
        return getConfigurationContext().getObject().getCasProperties().getServer().getPrefix();
    }

    @Override
    protected OAuth20GrantTypes getGrantType() {
        return OAuth20GrantTypes.TOKEN_EXCHANGE;
    }
}
