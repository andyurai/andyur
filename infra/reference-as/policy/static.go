package policy

// StaticEngine is the reference decision engine: the four-term intersection,
// evaluated by the ISSUER rather than by the party asking.
//
//	entitlement  what the USER may do, and which resources they may touch
//	ceiling      what the AGENT may EVER do, and which audiences it may hold
//	requested    what the client asked for
//	pin          the ONE resource this run is about
//
// Every term is a conjunct and any one of them can empty the grant. An empty
// grant is a DENIAL, never an unrestricted token -- which is the defect
// `docs/reviews/2026-08-06-open-findings.md` #1 records, where two independent
// "unrestricted" sentinels composed into "permit every action".
//
// Swap this struct for a client of your PDP. The call site does not change.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// User is what the enterprise's directory would hold.
type User struct {
	Entitlements []string `json:"entitlements"`
	// Resources the user may touch at all. The pin must be one of these; an
	// agent cannot be pointed at a resource its user has no claim to.
	Resources []string `json:"resources"`
}

// Ceiling is what an agent may EVER hold, independent of any user.
type Ceiling struct {
	Actions   []string `json:"actions"`
	Audiences []string `json:"audiences"`
}

type Data struct {
	Users    map[string]User    `json:"users"`
	Ceilings map[string]Ceiling `json:"ceilings"`
}

// StaticEngine holds the USER directory itself -- that is the enterprise's fact,
// and Andyur has no business holding it -- and asks a CeilingSource for agent
// ceilings, which are registry data owned by Andyur.
type StaticEngine struct {
	data     Data
	ceilings CeilingSource
}

// NewStatic uses the configured ceilings from ceilings.json.
func NewStatic(d Data) *StaticEngine {
	return &StaticEngine{data: d, ceilings: StaticCeilings(d.Ceilings)}
}

// WithCeilingSource points the engine at Andyur's agent registry instead, so
// there is ONE definition of what an agent may ever hold rather than two that
// drift.
func (e *StaticEngine) WithCeilingSource(src CeilingSource) *StaticEngine {
	e.ceilings = src
	return e
}

// Load reads users.json and ceilings.json from dir.
func Load(dir string) (Data, error) {
	var d Data
	if err := readJSON(filepath.Join(dir, "users.json"), &d.Users); err != nil {
		return d, err
	}
	if err := readJSON(filepath.Join(dir, "ceilings.json"), &d.Ceilings); err != nil {
		return d, err
	}
	return d, nil
}

func readJSON(path string, into any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("policy data: %w", err)
	}
	return json.Unmarshal(b, into)
}

func (e *StaticEngine) Evaluate(in Input) Decision {
	// TERM 1 -- the user. An unknown subject is DENIED, not defaulted. A policy
	// engine that treats "I have never heard of this user" as "no restrictions"
	// is worse than no policy engine.
	user, known := e.data.Users[in.Subject]
	if !known {
		return deny("unknown subject %q: this authorization server has no "+
			"entitlements for that user", in.Subject)
	}

	// TERM 2 -- the agent's ceiling, from whichever source is configured.
	// A source that ERRORS fails closed: not knowing the bound is not permission
	// to proceed without one.
	ceiling, known, cerr := e.ceilings.Ceiling(in.Agent)
	if cerr != nil {
		return deny("could not establish agent %q's ceiling, so nothing is "+
			"granted: %v", in.Agent, cerr)
	}
	if !known {
		return deny("unknown agent %q (actor %q): no ceiling is configured, and "+
			"an agent with no ceiling is not an agent with no limit",
			in.Agent, in.Actor)
	}

	// A request naming NO TARGET AT ALL must be refused, not granted.
	//
	// Terms 3 and 5 both iterate over the requested targets, so with neither
	// `resource` nor `audience` the loops ran zero times and the ceiling and the
	// pin were never consulted: `bob + sre` with no resource returned 200, and so
	// did `alice + reader` whose ceiling is telemetry-only. An empty loop is not
	// a satisfied conjunct.
	if len(in.Audience) == 0 && len(in.Resource) == 0 {
		return deny("no `resource` and no `audience`: this server will not issue " +
			"a token that names no target, because the ceiling and the pin are " +
			"both statements ABOUT a target")
	}

	// TERM 3 -- the audience. Above the ceiling the whole authority is empty
	// rather than redirected: rewriting the target would hand back a token for a
	// service nobody asked about.
	for _, target := range append(append([]string{}, in.Audience...), in.Resource...) {
		if !permitted(ceiling.Audiences, target) {
			return deny("agent %q may not hold a token for %q; its ceiling "+
				"permits %v", in.Agent, target, ceiling.Audiences)
		}
	}

	// TERM 4 -- the actions.
	//
	// `allowed` is what this user MAY do through this agent at all, independent
	// of the request. `granted` is that intersected with what was actually asked
	// for. They differ when no scope is requested: granted is then empty, which
	// is correct (ask for nothing, receive nothing) but must NOT be read as "this
	// user may do nothing" when bounding a pin below.
	allowed := intersect(user.Entitlements, ceiling.Actions)
	// OIDC PROTOCOL scopes are not resource actions and this engine has no
	// opinion on them. `openid` asks for an ID token, not for access to
	// anything, so judging it against an entitlement list rejects a request that
	// asked for nothing privileged -- and the denial reads as a policy failure
	// rather than a vocabulary mismatch, which is a bad hour to spend.
	asked, protocol := splitProtocolScopes(in.Scope)
	kept := intersect(asked, allowed)
	granted := append(append([]string{}, kept...), protocol...)

	// THE AS CANNOT NARROW, SO IT MUST REFUSE.
	//
	// goidc.TokenExchangeResult has only Subject, Actor and Store -- there is no
	// field for a narrowed scope, and the grant is built from what the CLIENT
	// asked for. So a Decision carrying a smaller Scope was computed and thrown
	// away: a request mixing one permitted and one unpermitted action was ALLOWED
	// and both were issued. Verified by execution.
	//
	// Denying instead is the only honest option available here. It also gives the
	// caller something actionable, which silently issuing more never did.
	if len(asked) != len(kept) {
		return deny("scope %v exceeds what user %q may do through agent %q; ask "+
			"for %v instead. This server cannot narrow a grant, so it refuses "+
			"one it would have to widen", asked, in.Subject, in.Agent, kept)
	}
	if len(asked) > 0 && len(kept) == 0 {
		return deny("nothing remains of scope %v after the user's entitlements "+
			"%v and agent %q's ceiling %v", asked, user.Entitlements,
			in.Agent, ceiling.Actions)
	}

	// TERM 5 -- the pin. THE CONTROL THE CLAIM ITSELF CANNOT PROVIDE.
	//
	// The pin is read from the RFC 8707 `resource` URL, not from the RFC 9396
	// detail. That is not a preference: go-oidc's exchange callback receives
	// SubjectToken, ActorToken, Audience and Resource, and NOT the requested
	// scope or authorization_details. The resource is the one the decision can
	// see, and in this design it already names the pinned thing
	// (https://telemetry.internal/teams/checkout -> "checkout").
	//
	// The RAR detail is checked too, where the caller supplies it, because the
	// claim is not self-validating: the AS carries whatever it is told, so
	// without this `identifier: "*"` travels intact and a resource server that
	// trusts the claim is authorising on the caller's own assertion.
	// BOTH axes. This used to iterate in.Resource only, so the same value that
	// was refused as `resource` was permitted as `audience` -- alice got a 200
	// for audience=.../teams/payments. Latent today because this AS reflects only
	// `resource` into `aud`, and a latent asymmetry is still an asymmetry.
	for _, res := range append(append([]string{}, in.Resource...), in.Audience...) {
		pin := PinOf(res)
		if pin == "" {
			continue // a target with no resource segment is not pinned
		}
		if !slices.Contains(user.Resources, pin) {
			return deny("user %q has no claim to resource %q (from %s); the run "+
				"may not be pointed at something its user cannot reach",
				in.Subject, pin, res)
		}
	}

	// The RFC 9396 half, reachable again now that the handler receives the
	// requested details. Shape is checked by ValidateDetail before this runs;
	// what is added here is the part that NEEDS the subject and the ceiling.
	var details []Detail
	for _, d := range in.Details {
		if err := ValidateDetail(d); err != nil {
			return deny("%v", err)
		}
		if !slices.Contains(user.Resources, d.Identifier) {
			return deny("user %q has no claim to resource %q; a pin may not name "+
				"a resource the user cannot reach", in.Subject, d.Identifier)
		}
		// Bounded by what the user and the ceiling ALLOW, not by this request's
		// scope: a pin naming an action is asking about capability, and a request
		// that named no scope has not thereby forfeited every action.
		da := d.Actions
		if len(da) > 0 {
			da = intersect(da, allowed)
			if len(da) == 0 {
				return deny("the pin on %q asks for actions %v, none of which "+
					"this user may perform through agent %q (allowed: %v)",
					d.Identifier, d.Actions, in.Agent, allowed)
			}
		}
		details = append(details, Detail{Type: d.Type, Identifier: d.Identifier,
			Actions: da, Locations: d.Locations})
	}

	return Decision{Allow: true, Scope: granted, Details: details}
}

// The OIDC and OAuth scopes that ask for protocol behaviour rather than for
// access to a resource. Passed through untouched.
var protocolScopes = map[string]bool{
	"openid": true, "profile": true, "email": true, "address": true,
	"phone": true, "offline_access": true,
}

func splitProtocolScopes(scopes []string) (asked, protocol []string) {
	for _, s := range scopes {
		if protocolScopes[s] {
			protocol = append(protocol, s)
		} else {
			asked = append(asked, s)
		}
	}
	return asked, protocol
}

func deny(format string, a ...any) Decision {
	return Decision{Allow: false, Reason: fmt.Sprintf(format, a...)}
}

// permitted is exact matching with ONE wildcard form: a trailing "*" on a
// configured entry. Substring matching would make "https://telemetry.internal"
// permit "https://telemetry.internal.evil.com".
func permitted(allowed []string, want string) bool {
	if want == "" {
		// An empty target matched any pattern ending in `*`. Nothing legitimate
		// asks for the empty string, and "matches everything" is the wrong answer
		// for a bounding function.
		return false
	}
	for _, a := range allowed {
		if a == "*" || a == want {
			return true
		}
		if !strings.HasSuffix(a, "*") {
			continue
		}
		prefix := strings.TrimSuffix(a, "*")
		if !strings.HasPrefix(want, prefix) {
			continue
		}
		// The remainder must not climb out of the prefix.
		// `https://telemetry.internal/teams/*` matched
		// `https://telemetry.internal/teams/../../admin`, which is a different
		// resource entirely once anything normalises the path.
		rest := want[len(prefix):]
		if strings.Contains(rest, "..") || strings.Contains(rest, "//") {
			continue
		}
		return true
	}
	return false
}

func intersect(requested, bound []string) []string {
	// A nil bound means "this term restricts nothing" ONLY where the caller has
	// established that. Here an empty bound restricts everything, deliberately:
	// see the module comment on unrestricted sentinels.
	var out []string
	for _, r := range requested {
		if permitted(bound, r) {
			out = append(out, r)
		}
	}
	return out
}

// ValidateDetail is the RFC 9396 half, called from go-oidc's RARValidateDetail
// hook because the exchange callback never sees authorization_details.
//
// It can only judge the detail's SHAPE: the hook receives the detail and nothing
// else, so "may this user reach this resource" is not answerable here and is
// enforced from the resource indicator in Evaluate instead. What it can stop is
// the shape that makes the claim meaningless -- a wildcard, or a pin with no
// identifier -- and that matters because the AS otherwise carries whatever it is
// told, and a resource server trusting the claim would be authorising on the
// caller's own assertion.
func ValidateDetail(d Detail) error {
	if d.Type != "andyur_pin" {
		return fmt.Errorf("authorization detail type %q is not one this server issues", d.Type)
	}
	if d.Identifier == "" {
		return fmt.Errorf("an andyur_pin with no identifier constrains nothing; " +
			"an unpinned detail is not a detail pinned to everything")
	}
	if d.Identifier == "*" || strings.Contains(d.Identifier, "*") {
		return fmt.Errorf("an andyur_pin identifier may not be a wildcard (%q): "+
			"a pin that matches everything is the absence of a pin", d.Identifier)
	}
	for _, a := range d.Actions {
		if a == "*" || strings.Contains(a, "*") {
			return fmt.Errorf("an andyur_pin action may not be a wildcard (%q)", a)
		}
	}
	return nil
}

// PinOf reads the pinned resource out of an RFC 8707 resource indicator.
//
//	https://telemetry.internal/teams/checkout -> "checkout"
//	https://tickets.internal/incidents        -> "incidents"
//
// The LAST path segment, because that is what the deployment's resource URLs
// name. An adopter whose URLs are shaped differently changes this one function.
func PinOf(resource string) string {
	trimmed := strings.TrimRight(resource, "/")
	i := strings.LastIndex(trimmed, "/")
	if i < 0 || i+1 >= len(trimmed) {
		return ""
	}
	seg := trimmed[i+1:]
	// A scheme-only or host-only URL has no resource segment to speak of.
	if strings.Contains(seg, ":") || strings.HasSuffix(trimmed[:i], ":/") {
		return ""
	}
	return seg
}

// AgentOf reduces a SPIFFE run id to the agent it belongs to.
//
//	spiffe://td/agent/<name>/run/<run id>  ->  <name>
func AgentOf(spiffeID string) string {
	const marker = "/agent/"
	i := strings.Index(spiffeID, marker)
	if i < 0 {
		return ""
	}
	rest := spiffeID[i+len(marker):]
	if j := strings.Index(rest, "/"); j >= 0 {
		return rest[:j]
	}
	return rest
}
