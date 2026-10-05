package dev.andyur.curity;

import java.time.Instant;
import java.util.Objects;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;

final class ActorAssertionValidator {
    private final JwtConsumer consumer;
    private final long maxLifetimeSeconds;
    private final long clockSkewSeconds;

    ActorAssertionValidator(String issuer, String audience, String jwks,
                            long maxLifetimeSeconds, long clockSkewSeconds)
            throws JoseException {
        if (maxLifetimeSeconds <= 0 || maxLifetimeSeconds > 300) {
            throw new IllegalArgumentException("actor lifetime ceiling must be 1..300 seconds");
        }
        if (clockSkewSeconds < 0 || clockSkewSeconds > 30) {
            throw new IllegalArgumentException("actor clock skew must be 0..30 seconds");
        }
        Objects.requireNonNull(issuer, "actor issuer");
        Objects.requireNonNull(audience, "actor audience");
        var keys = new JsonWebKeySet(Objects.requireNonNull(jwks, "actor JWKS"))
                .getJsonWebKeys();
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("actor JWKS is empty");
        }
        this.maxLifetimeSeconds = maxLifetimeSeconds;
        this.clockSkewSeconds = clockSkewSeconds;
        this.consumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setRequireIssuedAt()
                .setRequireJwtId()
                .setRequireSubject()
                .setExpectedIssuer(issuer)
                .setExpectedAudience(audience)
                .setAllowedClockSkewInSeconds(Math.toIntExact(clockSkewSeconds))
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(keys))
                .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                        AlgorithmIdentifiers.RSA_USING_SHA256)
                .build();
    }

    String validate(String assertion) throws InvalidJwtException {
        JwtClaims claims = consumer.processToClaims(assertion);
        try {
            long issuedAt = claims.getIssuedAt().getValue();
            long expiresAt = claims.getExpirationTime().getValue();
            long now = Instant.now().getEpochSecond();
            if (expiresAt <= issuedAt || expiresAt - issuedAt > maxLifetimeSeconds) {
                throw new InvalidActorLifetimeException();
            }
            if (issuedAt > now + clockSkewSeconds) {
                throw new InvalidActorLifetimeException();
            }
            String subject = claims.getSubject();
            if (!subject.startsWith("spiffe://")) {
                throw new InvalidActorSubjectException();
            }
            return subject;
        } catch (InvalidActorClaimException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new InvalidActorClaimException(exception);
        }
    }

    static class InvalidActorClaimException extends RuntimeException {
        InvalidActorClaimException() { super("invalid actor assertion claim"); }
        InvalidActorClaimException(Throwable cause) { super("invalid actor assertion claim", cause); }
    }
    static final class InvalidActorLifetimeException extends InvalidActorClaimException {}
    static final class InvalidActorSubjectException extends InvalidActorClaimException {}
}
