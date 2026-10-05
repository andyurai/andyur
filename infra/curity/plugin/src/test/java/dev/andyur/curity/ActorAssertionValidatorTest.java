package dev.andyur.curity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.UUID;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

final class ActorAssertionValidatorTest {
    private static final String ISSUER = "spiffe://andyur.test";
    private static final String AUDIENCE = "https://curity.andyur.test/oauth/token";
    private static final String SUBJECT = "spiffe://andyur.test/agent/run/123";
    private static RsaJsonWebKey trusted;
    private static RsaJsonWebKey attacker;
    private static ActorAssertionValidator validator;

    @BeforeAll
    static void setup() throws Exception {
        trusted = RsaJwkGenerator.generateJwk(2048);
        trusted.setKeyId("trusted-v1");
        attacker = RsaJwkGenerator.generateJwk(2048);
        attacker.setKeyId("attacker");
        String jwks = new JsonWebKeySet(java.util.List.of(trusted))
                .toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        validator = new ActorAssertionValidator(ISSUER, AUDIENCE, jwks, 300, 2);
    }

    @Test
    void acceptsOnlyTheExactFreshSignedSpiffeActor() throws Exception {
        assertEquals(SUBJECT, validator.validate(assertion(
                trusted, ISSUER, AUDIENCE, SUBJECT, -1, 120)));
    }

    @Test
    void deniesAnAttackerSignature() throws Exception {
        assertThrows(Exception.class, () -> validator.validate(assertion(
                attacker, ISSUER, AUDIENCE, SUBJECT, -1, 120)));
    }

    @Test
    void deniesWrongIssuerAudienceAndNonSpiffeSubject() throws Exception {
        assertThrows(Exception.class, () -> validator.validate(assertion(
                trusted, "spiffe://other.test", AUDIENCE, SUBJECT, -1, 120)));
        assertThrows(Exception.class, () -> validator.validate(assertion(
                trusted, ISSUER, "https://other.test/token", SUBJECT, -1, 120)));
        assertThrows(Exception.class, () -> validator.validate(assertion(
                trusted, ISSUER, AUDIENCE, "ordinary-user", -1, 120)));
    }

    @Test
    void deniesExpiredFutureAndOverlongOriginalLifetimes() throws Exception {
        assertThrows(Exception.class, () -> validator.validate(assertion(
                trusted, ISSUER, AUDIENCE, SUBJECT, -180, -60)));
        assertThrows(Exception.class, () -> validator.validate(assertion(
                trusted, ISSUER, AUDIENCE, SUBJECT, 60, 120)));
        assertThrows(ActorAssertionValidator.InvalidActorLifetimeException.class,
                () -> validator.validate(assertion(
                        trusted, ISSUER, AUDIENCE, SUBJECT, -1, 301)));
    }

    @Test
    void refusesUnsafeConfigurationCeilingsAndEmptyKeys() {
        String emptyJwks = "{\"keys\":[]}";
        assertThrows(IllegalArgumentException.class,
                () -> new ActorAssertionValidator(ISSUER, AUDIENCE, emptyJwks, 300, 2));
        assertThrows(IllegalArgumentException.class,
                () -> new ActorAssertionValidator(ISSUER, AUDIENCE, emptyJwks, 301, 2));
        assertThrows(IllegalArgumentException.class,
                () -> new ActorAssertionValidator(ISSUER, AUDIENCE, emptyJwks, 300, 31));
    }

    private static String assertion(RsaJsonWebKey key, String issuer, String audience,
                                    String subject, long issuedOffset, long expiryOffset)
            throws Exception {
        long now = Instant.now().getEpochSecond();
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setAudience(audience);
        claims.setSubject(subject);
        claims.setIssuedAt(NumericDate.fromSeconds(now + issuedOffset));
        claims.setExpirationTime(NumericDate.fromSeconds(now + expiryOffset));
        claims.setJwtId(UUID.randomUUID().toString());
        JsonWebSignature signature = new JsonWebSignature();
        signature.setPayload(claims.toJson());
        signature.setKey(key.getPrivateKey());
        signature.setKeyIdHeaderValue(key.getKeyId());
        signature.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        signature.setHeader("typ", "JWT");
        return signature.getCompactSerialization();
    }
}
