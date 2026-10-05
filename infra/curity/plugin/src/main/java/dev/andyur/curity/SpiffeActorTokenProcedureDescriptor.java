package dev.andyur.curity;

import se.curity.identityserver.sdk.plugin.descriptor.TokenProcedurePluginDescriptor;
import se.curity.identityserver.sdk.procedure.token.OAuthTokenExchangeTokenProcedure;

public final class SpiffeActorTokenProcedureDescriptor
        implements TokenProcedurePluginDescriptor<SpiffeActorConfig> {
    @Override
    public Class<? extends OAuthTokenExchangeTokenProcedure>
            getOAuthTokenEndpointOAuthTokenExchangeTokenProcedure() {
        return SpiffeActorTokenProcedure.class;
    }

    @Override
    public String getPluginImplementationType() {
        return "andyur-spiffe-actor-token-exchange";
    }

    @Override
    public Class<? extends SpiffeActorConfig> getConfigurationType() {
        return SpiffeActorConfig.class;
    }
}
