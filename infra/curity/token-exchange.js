/* Andyur-specific Curity OAuth token-exchange procedure.
 *
 * Curity performs both token introspections before this procedure runs.  The
 * subject is the user's Curity access token.  The actor is a short-lived
 * Curity access token minted from the run's externally verified JWT-SVID via
 * RFC 7523.  This procedure only preserves the verified actor in RFC 8693
 * `act`; it does not parse or trust either raw credential itself.
 */
function result(context) {
  var subjectToken = context.getPresentedSubjectToken();
  var actorToken = context.getPresentedActorToken(null);
  if (subjectToken === null) {
    throw exceptionFactory.badRequestException(
      "invalid_request", "A verified subject_token is required");
  }
  if (actorToken === null || !actorToken.get("sub")) {
    throw exceptionFactory.badRequestException(
      "invalid_request", "A verified actor_token subject is required");
  }

  var rawScope = subjectToken.get("scope");
  if (typeof rawScope !== "string" || rawScope.length === 0) {
    throw exceptionFactory.badRequestException(
      "invalid_request", "The verified subject_token has no scope");
  }
  var rawAudience = subjectToken.get("aud");
  var audiences = typeof rawAudience === "string"
    ? [rawAudience] : rawAudience;
  if (audiences === null || audiences.length === 0) {
    throw exceptionFactory.badRequestException(
      "invalid_request", "The verified subject_token has no audience");
  }

  var initialized = context.getInitializedContext(
    context.subjectAttributes(), context.contextAttributes(),
    audiences, rawScope.split(" "));
  var delegationData = initialized.getDefaultDelegationData();
  var delegation = initialized.delegationIssuer.issue(delegationData);
  var accessTokenData = initialized.getDefaultAccessTokenData();
  accessTokenData.act = {sub: actorToken.get("sub")};
  var accessToken = initialized.accessTokenIssuer.issue(
    accessTokenData, delegation);
  return {
    access_token: accessToken,
    issued_token_type:
      "urn:ietf:params:oauth:token-type:access_token",
    token_type: accessTokenData.cnf ? "DPoP" : "bearer",
    scope: accessTokenData.scope,
    expires_in: secondsUntil(accessTokenData.exp)
  };
}
