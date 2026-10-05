package dev.andyur.curity;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Set;

import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;

import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.attribute.MapAttributeValue;
import se.curity.identityserver.sdk.attribute.token.AccessTokenAttributes;
import se.curity.identityserver.sdk.data.tokens.TokenIssuerException;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.procedure.token.OAuthTokenExchangeTokenProcedure;
import se.curity.identityserver.sdk.procedure.token.context.OAuthTokenExchangeTokenProcedurePluginContext;
import se.curity.identityserver.sdk.procedure.token.context.OAuthTokenExchangeUnInitializedTokenProcedurePluginContext;
import se.curity.identityserver.sdk.service.issuer.AccessTokenIssuer;
import se.curity.identityserver.sdk.web.ResponseModel;

public final class SpiffeActorTokenProcedure implements OAuthTokenExchangeTokenProcedure {
    private final SpiffeActorConfig configuration;
    private final ActorAssertionValidator actorValidator;

    public SpiffeActorTokenProcedure(SpiffeActorConfig configuration) throws JoseException {
        this.configuration = configuration;
        this.actorValidator = new ActorAssertionValidator(
                configuration.getActorIssuer(), configuration.getActorAudience(),
                configuration.getActorJwks(), configuration.getMaxActorLifetimeSeconds(),
                configuration.getClockSkewSeconds());
    }

    @Override
    public ResponseModel run(OAuthTokenExchangeUnInitializedTokenProcedurePluginContext context) {
        var subjectToken = context.getPresentedSubjectToken();
        String actorToken = context.getActorTokenValue();
        if (subjectToken == null || !subjectToken.isActive() || actorToken == null) {
            throw refused("a live subject token and SPIFFE actor token are required");
        }

        Set<String> subjectScopes = stringSet(
                attributeValue(subjectToken.getTokenData().get("scope")), true);
        Set<String> subjectAudiences = stringSet(
                attributeValue(subjectToken.getTokenData().get("aud")), false);
        Set<String> requestedScopes = context.getRequestedScopes();
        Set<String> requestedAudiences = context.getRequestedAudiences();
        if (requestedScopes.isEmpty() || requestedAudiences.isEmpty()
                || !subjectScopes.containsAll(requestedScopes)
                || !subjectAudiences.containsAll(requestedAudiences)) {
            throw refused("requested scope and audience must be non-empty subject-token subsets");
        }

        final String actor;
        try {
            actor = actorValidator.validate(actorToken);
        } catch (InvalidJwtException | ActorAssertionValidator.InvalidActorClaimException exception) {
            throw refused("the SPIFFE actor token is invalid");
        }

        var initialized = context.getInitializedContext(
                context.subjectAttributes(), context.contextAttributes(),
                requestedAudiences, requestedScopes);
        var tokenData = initialized.getDefaultAccessTokenData()
                .with(Attribute.of("act", MapAttributeValue.of(
                        java.util.Map.of("sub", actor))));
        var delegation = initialized.getDefaultDelegationData();

        try {
            @Nullable AccessTokenIssuer issuer = configuration.getJwtAccessTokenIssuerProvider()
                    .getDefaultJwtAccessTokenIssuer();
            if (issuer == null) {
                throw refused("JWT access-token issuance is not configured");
            }
            @Nullable String token = issuer.issue(
                    AccessTokenAttributes.of(tokenData), initialized.issueDelegation(delegation));
            if (token == null) {
                throw refused("access-token issuance failed");
            }
            var response = new HashMap<String, Object>();
            response.put("access_token", token);
            response.put("issued_token_type", "urn:ietf:params:oauth:token-type:access_token");
            response.put("token_type", tokenData.contains("cnf") ? "DPoP" : "bearer");
            response.put("scope", tokenData.get("scope").getValue());
            response.put("expires_in", Long.parseLong(tokenData.get("exp").getValue().toString())
                    - Instant.now().getEpochSecond());
            return ResponseModel.mapResponseModel(response);
        } catch (TokenIssuerException exception) {
            return ResponseModel.problemResponseModel(
                    "token_issuer_exception", "Could not issue access token");
        }
    }

    private RuntimeException refused(String message) {
        return configuration.getExceptionFactory().badRequestException(
                ErrorCode.TOKEN_ISSUANCE_ERROR, message);
    }

    private static Set<String> stringSet(Object value, boolean splitSpaces) {
        var result = new LinkedHashSet<String>();
        if (value instanceof String text) {
            if (splitSpaces) {
                for (String item : text.trim().split("\\s+")) {
                    if (!item.isBlank()) result.add(item);
                }
            } else if (!text.isBlank()) {
                result.add(text);
            }
        } else if (value instanceof Collection<?> values) {
            for (Object item : values) {
                if (item instanceof String text && !text.isBlank()) result.add(text);
            }
        }
        return Set.copyOf(result);
    }

    private static Object attributeValue(Attribute attribute) {
        return attribute == null ? null : attribute.getValue();
    }
}
