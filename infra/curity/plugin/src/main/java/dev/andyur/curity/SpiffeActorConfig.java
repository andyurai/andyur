package dev.andyur.curity;

import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.annotation.DefaultLong;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.issuer.DefaultJwtAccessTokenIssuerProvider;
import se.curity.identityserver.sdk.config.annotation.DefaultService;

public interface SpiffeActorConfig extends Configuration {
    ExceptionFactory getExceptionFactory();

    @DefaultService
    DefaultJwtAccessTokenIssuerProvider getJwtAccessTokenIssuerProvider();

    @Description("Exact SPIFFE JWT-SVID issuer URI")
    String getActorIssuer();

    @Description("Exact audience required in the SPIFFE JWT-SVID")
    String getActorAudience();

    @Description("Source-controlled SPIRE bundle JWKS; rotate by versioned plugin configuration")
    String getActorJwks();

    @Description("Maximum original exp-minus-iat lifetime in seconds")
    @DefaultLong(300)
    Long getMaxActorLifetimeSeconds();

    @Description("Allowed clock skew in seconds")
    @DefaultLong(2)
    Long getClockSkewSeconds();
}
