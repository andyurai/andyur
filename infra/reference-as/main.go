// A REFERENCE authorization server for Andyur's authority tests.
//
// Why this exists: `docs/decisions.md` #5 says the delegated token carries
// `sub` = the user and `act` = the run; O1 discusses the resource constraint as
// RFC 9396; O2 requires `cnf`. Keycloak can do NONE of those -- proven with a
// positive control by `infra/keycloak/verify-act-delegation.sh`. Without a server
// that can, there is no way to demonstrate the design end to end, and no way to
// tell a flaw in the design apart from a limitation of one product.
//
// This is the REFERENCE IMPLEMENTATION: the design is specified and verified
// against it, and correctness for Andyur's authority path is defined by it.
// Whether an ADOPTER runs go-oidc as their corporate IdP is a separate question
// and not one this file answers -- an adopter with their own AS points at theirs,
// and Andyur degrades to whatever that AS can carry.
//
// Built on go-oidc v0.25.0 (MIT, OpenID Certified).
//
// WHAT IT DELIBERATELY DOES NOT DO: narrow. The exchange callback returns the
// subject and the actor chain and carries the client's requested authorization
// details unchanged. That is not an oversight -- `verify.sh` asserts it. A token
// exchange has no prior granted set to compare against, so the AS allow-lists
// the RAR *type* and never its *content*. Narrowing is Andyur's four-term
// intersection, computed BEFORE it asks.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andyur/reference-as/policy"
	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// RS256, not the PS256 the upstream FAPI examples use. `demos/authority-tool/pep.py`
// pins algorithms=["RS256"], and a resource server that pins its algorithm is
// correct -- so the AS matches the resource server rather than the other way
// round. Changing this breaks every PEP in the demos.
const sigAlg = goidc.SigAlgRS256

// The tool resources the SRE demo calls, as RFC 8707 resource indicators. These
// double as the audience: `resource` becomes `aud`, which is the standard's
// answer to the question docs/adr-002-audience-identifiers.md was opened to
// settle. An unregistered value is refused with 400 invalid_target.
var toolResources = []goidc.ResourceIndicator{
	"https://telemetry.internal/teams/checkout",
	"https://telemetry.internal/teams/payments",
	"https://tickets.internal/incidents",
}

// The deployment's ACTION vocabulary, registered as scopes.
//
// Without these, go-oidc rejects any resource action with `invalid_scope`
// BEFORE the policy handler runs, so the entitlement and ceiling terms over
// scope never execute at all -- term 4 was dead in the shipped configuration
// and the tests could not tell, because they only ever sent `openid`.
//
// Registering an action here does NOT grant it. It makes the request
// expressible, so that policy is the thing that decides. `tickets:delete` and
// `telemetry:write` are deliberately present and granted to nobody in
// data/users.json, which is what makes a denial-by-policy testable.
var actionScopes = []string{
	"telemetry:read", "telemetry:write",
	"tickets:read", "tickets:write", "tickets:delete",
}

func allScopes() []goidc.Scope {
	out := append([]goidc.Scope{}, authutil.Scopes...)
	for _, a := range actionScopes {
		out = append(out, goidc.NewScope(a))
	}
	return out
}

func main() {
	// The policy engine lives INSIDE this process. One binary gives you the
	// login page, JWKS, the exchange, the 8707/9396/9449 checks, and the
	// decision -- so a demo needs no second service, and the seam an adopter
	// replaces is one struct rather than a deployment.
	dataDir := envOr("ANDYUR_REFAS_DATA", "data")
	pdata, err := policy.Load(dataDir)
	if err != nil {
		log.Fatalf("policy data: %v (set ANDYUR_REFAS_DATA)", err)
	}
	// Andyur itself is a registered resource, because the LOGIN token is
	// addressed to Andyur -- it is the party that validates it, and a consumer
	// must check that `aud` names itself. Without this registration
	// `andyur auth login` is refused invalid_target.
	//
	// Read from the environment rather than guessed. The default was wrong the
	// first time: Andyur's SERVER_URL is not the port I assumed, and the AS said
	// invalid_target rather than silently issuing a misaddressed token.
	andyurURL := envOr("ANDYUR_REFAS_ANDYUR_URL", "http://127.0.0.1:8642")
	toolResources = append(toolResources, goidc.ResourceIndicator(andyurURL))
	log.Printf("registered Andyur as an audience: %s", andyurURL)

	// The audiences a REAL deployment computes, which are the tool servers' own
	// canonical MCP urls -- not the illustrative telemetry.internal names above.
	// Without this the AS refuses every audience Andyur can actually produce
	// (invalid_target), which is a fixture that cannot meet the system it is a
	// fixture for.
	for _, r := range strings.Split(os.Getenv("ANDYUR_REFAS_RESOURCES"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			toolResources = append(toolResources, goidc.ResourceIndicator(r))
			log.Printf("registered tool resource: %s", r)
		}
	}

	engine := policy.NewStatic(pdata)
	// Prefer Andyur's agent registry as the ONE definition of an agent's ceiling.
	// Without it the configured ceilings.json is used, which is the right choice
	// for an adopter who does not want this server depending on the harness.
	if reg := os.Getenv("ANDYUR_REFAS_REGISTRY_URL"); reg != "" {
		engine = engine.WithCeilingSource(policy.NewRegistryCeilings(
			reg, os.Getenv("ANDYUR_REFAS_REGISTRY_TOKEN"), 30*time.Second))
		log.Printf("agent ceilings read from the Andyur registry at %s", reg)
	} else {
		log.Printf("agent ceilings read from %s/ceilings.json", dataDir)
	}

	addr := envOr("ANDYUR_REFAS_ADDR", ":8099")
	issuer := envOr("ANDYUR_REFAS_ISSUER", "http://localhost"+addr)
	issuerURL = issuer
	actorProof, err := loadActorVerifier()
	if err != nil {
		log.Fatalf("actor proof configuration: %v", err)
	}
	if actorProof != nil {
		log.Printf("actor JWT-SVID verification enabled: audience=%s expected=%s",
			actorProof.audience, actorProof.expectedID)
	} else {
		log.Printf("WARNING: actor JWT validation disabled; legacy reference-fixture mode only")
	}

	// authutil embeds the keypairs, so client ids must be ones it ships.
	// A fixture concern only.
	gateway := authutil.ClientSecretPost("client_one", "gateway-secret", allScopes()...)
	gateway.GrantTypes = append(gateway.GrantTypes, goidc.GrantTokenExchange)

	// `andyur auth login` is a PUBLIC client: a CLI cannot keep a secret, so it
	// authenticates with PKCE alone (RFC 8252 sec 8.5, RFC 9700 sec 2.1.1).
	//
	// The redirect URIs are a fixed candidate list rather than one ephemeral
	// port, because this AS matches redirect_uri EXACTLY and does not implement
	// the variable-port allowance RFC 8252 sec 7.3 grants loopback clients. The
	// CLI tries these in order and fails clearly if all are busy. Exact matching
	// is the stricter behaviour, so this is a CLI constraint and not a weakness.
	cli := &goidc.Client{
		ID: "andyur-cli",
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodNone,
			ScopeIDs:         scopeIDs(),
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode, goidc.GrantRefreshToken,
			},
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
			RedirectURIs:  loopbackRedirects(),
		},
	}

	op, err := provider.New(
		provider.Config{
			Issuer:      issuer,
			JWKS:        authutil.PrivateJWKSFunc(),
			IDTokenAlgs: []goidc.SignatureAlgorithm{sigAlg},
		},
		provider.WithScopes(allScopes()...),
		provider.WithStaticClients(gateway, cli),
		// BOTH methods, explicitly. These options APPEND to an allow-list that is
		// empty by default, and an empty list means "the built-in default" -- so
		// enabling `none` alone silently switched OFF client_secret_post and every
		// exchange started failing invalid_client. Naming both is also the honest
		// configuration: a reader can see exactly which methods are accepted.
		//   none              -> andyur-cli, a public client with no secret to keep
		//   client_secret_post-> the gateway, a confidential client
		provider.WithNoneAuthn(),
		provider.WithSecretPostAuthn(),
		// The interactive login. PKCE is REQUIRED, not merely supported: a public
		// client without it is vulnerable to code injection (RFC 9700 sec 2.1.1).
		provider.WithAuthCodeGrant(
			provider.AuthCodeGrantConfig{
				ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
			},
			provider.WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256},
				provider.WithPKCERequired()),
			provider.WithAuthPolicies(loginPolicy()),
		),
		provider.WithRefreshTokenGrant(nil),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(sigAlg)),

		// RFC 9449 -- DPoP. This is what puts `cnf.jkt` in the issued token.
		// The proof is made by whoever calls the token endpoint, which in Andyur
		// is the PER-RUN agentgateway, so the binding is per-run in practice and
		// the agent holds neither the token nor the key.
		provider.WithDPoP([]goidc.SignatureAlgorithm{
			goidc.SigAlgRS256, goidc.SigAlgES256, goidc.SigAlgPS256},
			dpopOptions()...),
		// RFC 9449 sec 11.1: a proof SHOULD be single-use. Without a consumer the
		// server logs "JTI replay protection is disabled" at startup and means it
		// -- the same proof replayed three times issued three tokens. go-oidc
		// enforces the time window; this is the other half.
		provider.WithJTIConsumer(consumeJTI),

		// RFC 9396 -- the pin. TYPE allow-listed; content is NOT checked.
		provider.WithRAR([]goidc.AuthDetailType{"andyur_pin"},
			// The exchange callback cannot see authorization_details, so the
			// RFC 9396 half is enforced here. Shape only -- this hook receives
			// the detail and nothing else, so who may reach what is decided from
			// the resource indicator in policy.Evaluate.
			provider.WithRARDetailValidator(func(_ context.Context, d goidc.AuthDetail) error {
				return policy.ValidateDetail(policy.Detail{
					Type:       string(d.Type()),
					Identifier: strOf(d["identifier"]),
					Actions:    strsOf(d["actions"]),
				})
			})),

		// RFC 8707 -- resource indicators, allow-listed by target.
		provider.WithResourceIndicators(toolResources),

		// RFC 8693 -- the exchange.
		//
		// CLIENT AUTHENTICATION IS REQUIRED. Without this option go-oidc
		// synthesizes a mock client holding every registered scope when the
		// caller is merely unidentified (internal/token/exchange.go), so an
		// unauthenticated POST /token returned 200 and a full delegated token
		// for any known user as any known agent. Reproduced by two independent
		// reviewers. A WRONG secret always 401'd; the hole was the omitted-
		// credentials path, which no test exercised because every test sent both.
		provider.WithTokenExchangeGrant(
			func(ctx context.Context, req goidc.TokenExchangeRequest) (goidc.TokenExchangeResult, error) {
				if req.ActorTokenType != goidc.TokenTypeIdentifierJWT {
					return goidc.TokenExchangeResult{}, goidc.NewError(
						goidc.ErrorCodeInvalidRequest,
						"actor_token_type must be urn:ietf:params:oauth:token-type:jwt")
				}
				sub, err := subjectOfAssertion(req.SubjectToken)
				if err != nil {
					return goidc.TokenExchangeResult{}, goidc.WrapError(
						goidc.ErrorCodeInvalidRequest, "subject_token is not a readable JWT", err)
				}
				// The prior chain comes from the SUBJECT token -- it is the
				// output of the previous exchange and is where `act` accumulates.
				// This used to read it from the ACTOR token, which for Andyur is
				// a JWT-SVID and carries no `act` at all, so every hop before the
				// last was dropped. The test passed only because the fixture
				// hand-built an actor token with an `act` claim, a shape no real
				// SVID has.
				actor, err := actorOf(req.ActorToken, priorActor(req.SubjectToken), actorProof)
				if err != nil {
					return goidc.TokenExchangeResult{}, err
				}

				// THE DECISION. This runs on EVERY exchange, and it is the only
				// place that can refuse to ISSUE. Andyur narrowing before it asks
				// is necessary and not sufficient -- a compromised Andyur simply
				// asks for more, and only the issuer can decline.
				in := policy.Input{
					Subject:  sub,
					Actor:    actor.Subject,
					Agent:    policy.AgentOf(actor.Subject),
					Audience: req.Audience,
					Resource: []string(req.Resource),
					// ONE decision, over everything the client asked for.
					// RequestedScopes and RequestedAuthDetails come from the
					// local patch in patches/ -- upstream drops them before the
					// handler runs, which left a subject-aware policy over scope
					// and RAR with nowhere to live. See patches/UPSTREAM-ISSUE.md.
					Scope:   req.RequestedScopes,
					Details: detailsOf(req.RequestedAuthDetails),
				}
				d := engine.Evaluate(in)
				if !d.Allow {
					log.Printf("exchange DENIED: sub=%s agent=%s: %s",
						sub, in.Agent, d.Reason)
					// access_denied, not invalid_request: the request was
					// well-formed and the POLICY refused it, and a caller that
					// cannot tell those apart retries forever.
					return goidc.TokenExchangeResult{}, goidc.NewError(
						goidc.ErrorCodeAccessDenied, d.Reason)
				}
				log.Printf("exchange ALLOWED: sub=%s agent=%s resource=%v",
					sub, in.Agent, req.Resource)
				return goidc.TokenExchangeResult{Subject: sub, Actor: actor}, nil
			},
			provider.WithTokenExchangeClientAuthnRequired(),
		),
	)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", op.Handler())
	// ReadHeaderTimeout alone bounds headers only. A peer that sends complete
	// headers and then dribbles a body held a goroutine and an fd indefinitely,
	// and IdleTimeout falling back to ReadTimeout (zero) meant keep-alive
	// connections were never reaped.
	srv := &http.Server{
		Addr:              addr,
		Handler:           http.MaxBytesHandler(mux, maxRequestBytes),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("andyur reference AS on %s (issuer %s, %s)", addr, issuer, sigAlg)
	var serveErr error
	certFile, keyFile := os.Getenv("ANDYUR_REFAS_TLS_CERT"), os.Getenv("ANDYUR_REFAS_TLS_KEY")
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			log.Fatal("ANDYUR_REFAS_TLS_CERT and ANDYUR_REFAS_TLS_KEY must be set together")
		}
		serveErr = srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		serveErr = srv.ListenAndServe()
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		log.Fatal(serveErr)
	}
}

func dpopOptions() []provider.DPoPOption {
	if os.Getenv("ANDYUR_REFAS_DPOP_REQUIRED") == "1" {
		return []provider.DPoPOption{provider.WithDPoPRequired()}
	}
	return nil
}

// actorOf turns the presented actor token into the `act` chain.
//
// Andyur presents the RUN's JWT-SVID here, so `act.sub` is the run's SPIFFE id
// rather than the agent's name. That distinction is the whole of identity
// finding I2: two concurrent runs of one agent must not be the same principal
// at a tool.
//
// An actor token is REQUIRED. Without it the issued token would be
// indistinguishable from the user acting directly, which is impersonation --
// the thing this design exists to avoid. Refusing is the only safe default.
func actorOf(actorToken string, prior *goidc.Actor, verifier *actorVerifier) (*goidc.Actor, error) {
	if strings.TrimSpace(actorToken) == "" {
		// A CLIENT error, so it must not surface as a 500. The first run of
		// verify.sh caught exactly that: a bare errors.New here became an
		// internal server error, which tells a caller nothing and reads like the
		// AS is broken rather than the request being wrong.
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"actor_token is required: without it the issued token asserts the "+
				"user acted directly, and no resource server could tell "+
				"delegation from impersonation")
	}
	var sub string
	var err error
	if verifier == nil {
		sub, err = subjectOfAssertion(actorToken)
	} else {
		sub, err = verifier.verify(actorToken, time.Now())
	}
	if err != nil {
		log.Printf("actor token refused: %v", err)
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"actor_token validation failed")
	}
	// RFC 8693 sec 4.1: nested `act` is "a history trail that connects the
	// initial request and subject through the various delegation steps". The
	// new actor goes on the outside; everything the subject token already
	// carried nests beneath it.
	return &goidc.Actor{Subject: sub, Actor: prior}, nil
}

type actorVerifier struct {
	bundle      *spiffebundle.Bundle
	audience    string
	expectedID  spiffeid.ID
	maxLifetime time.Duration
}

func loadActorVerifier() (*actorVerifier, error) {
	bundlePath := strings.TrimSpace(os.Getenv("ANDYUR_REFAS_ACTOR_SPIFFE_BUNDLE"))
	audience := strings.TrimSpace(os.Getenv("ANDYUR_REFAS_ACTOR_AUDIENCE"))
	expected := strings.TrimSpace(os.Getenv("ANDYUR_REFAS_ACTOR_EXPECTED_ID"))
	configured := bundlePath != "" || audience != "" || expected != ""
	if !configured {
		return nil, nil
	}
	if bundlePath == "" || audience == "" || expected == "" {
		return nil, errors.New("bundle, audience, and sealed expected actor ID must be configured together")
	}
	id, err := spiffeid.FromString(expected)
	if err != nil {
		return nil, fmt.Errorf("expected actor ID: %w", err)
	}
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("read SPIFFE bundle: %w", err)
	}
	bundle, err := spiffebundle.Parse(id.TrustDomain(), raw)
	if err != nil {
		return nil, fmt.Errorf("parse SPIFFE bundle: %w", err)
	}
	maxSeconds := int64(300)
	if value := strings.TrimSpace(os.Getenv("ANDYUR_REFAS_ACTOR_MAX_LIFETIME_SECONDS")); value != "" {
		maxSeconds, err = strconv.ParseInt(value, 10, 32)
		if err != nil || maxSeconds < 1 {
			return nil, errors.New("actor maximum lifetime must be a positive integer")
		}
	}
	return &actorVerifier{
		bundle: bundle, audience: audience, expectedID: id,
		maxLifetime: time.Duration(maxSeconds) * time.Second,
	}, nil
}

func (v *actorVerifier) verify(token string, now time.Time) (string, error) {
	svid, err := jwtsvid.ParseAndValidate(token, v.bundle, []string{v.audience})
	if err != nil {
		return "", fmt.Errorf("JWT-SVID signature/audience/lifetime validation failed: %w", err)
	}
	if svid.ID != v.expectedID {
		return "", fmt.Errorf("verified actor %q does not equal sealed expected actor %q",
			svid.ID, v.expectedID)
	}
	issuedAt, err := numericDate(svid.Claims["iat"])
	if err != nil {
		return "", fmt.Errorf("verified actor iat: %w", err)
	}
	if issuedAt.After(now.Add(5 * time.Second)) {
		return "", errors.New("verified actor iat is in the future")
	}
	lifetime := svid.Expiry.Sub(issuedAt)
	if lifetime <= 0 || lifetime > v.maxLifetime {
		return "", fmt.Errorf("verified actor original lifetime %s is outside (0,%s]",
			lifetime, v.maxLifetime)
	}
	return v.expectedID.String(), nil
}

func numericDate(value any) (time.Time, error) {
	seconds, ok := value.(float64)
	if !ok || seconds != float64(int64(seconds)) {
		return time.Time{}, errors.New("claim must be an integer NumericDate")
	}
	return time.Unix(int64(seconds), 0), nil
}

func priorActor(token string) *goidc.Actor {
	c, err := unverifiedClaims(token)
	if err != nil {
		return nil
	}
	raw, ok := c["act"]
	if !ok {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var a goidc.Actor
	if err := json.Unmarshal(b, &a); err != nil || a.Subject == "" {
		return nil
	}
	return &a
}

// subjectOfAssertion reads `sub` from a presented JWT.
//
// IT DOES NOT VERIFY THE SIGNATURE, and that is a fixture limitation worth
// being loud about: a real AS validates the assertion against the asserting
// client's registered key (RFC 7523 sec 3) and the subject token against its
// issuer. This server exists to prove what a token can CARRY, and Andyur's
// behaviour is what the tests are about. Do not copy this function.
func subjectOfAssertion(token string) (string, error) {
	c, err := unverifiedClaims(token)
	if err != nil {
		return "", err
	}
	sub, _ := c["sub"].(string)
	if sub == "" {
		return "", errors.New("presented token carries no sub")
	}
	return sub, nil
}

func unverifiedClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("undecodable JWT payload")
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("unparseable JWT payload")
	}
	return c, nil
}

// The ports `andyur auth login` will try, in order.
func loopbackRedirects() []string {
	var out []string
	for _, p := range []string{"8765", "8766", "8767", "8768", "8769"} {
		out = append(out, "http://127.0.0.1:"+p+"/callback")
	}
	return out
}

func scopeIDs() string {
	all := allScopes()
	ids := make([]string, 0, len(all))
	for _, s := range all {
		ids = append(ids, s.ID)
	}
	return strings.Join(ids, " ")
}

// detailsOf converts the AS's RAR representation into the policy's.
func detailsOf(raw []goidc.AuthDetail) []policy.Detail {
	out := make([]policy.Detail, 0, len(raw))
	for _, d := range raw {
		out = append(out, policy.Detail{
			Type:       string(d.Type()),
			Identifier: strOf(d["identifier"]),
			Actions:    strsOf(d["actions"]),
			Locations:  strsOf(d["locations"]),
		})
	}
	return out
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

func strsOf(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Big enough for a token exchange carrying a subject token, an actor token and
// authorization details; small enough that PostFormValue's 10 MB default is not
// the bound. A login form is a few hundred bytes.
const maxRequestBytes = 256 << 10

// consumeJTI makes a DPoP proof single-use. Bounded, because the key is
// attacker-chosen: at the cap the oldest window is dropped, which can only
// re-permit a proof whose time window go-oidc will independently reject.
var (
	seenJTIMu sync.Mutex
	seenJTI   = map[string]time.Time{}
)

func consumeJTI(_ context.Context, jti string) error {
	seenJTIMu.Lock()
	defer seenJTIMu.Unlock()
	now := time.Now()
	if at, ok := seenJTI[jti]; ok && now.Sub(at) < 5*time.Minute {
		return errors.New("jti has already been used")
	}
	if len(seenJTI) > 8192 {
		for k, at := range seenJTI {
			if now.Sub(at) > 5*time.Minute {
				delete(seenJTI, k)
			}
		}
		if len(seenJTI) > 8192 {
			seenJTI = map[string]time.Time{}
		}
	}
	seenJTI[jti] = now
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
