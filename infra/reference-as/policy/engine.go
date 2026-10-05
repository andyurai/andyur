// Package policy is the decision point of the reference authorization server.
//
// THE CONTRACT THIS EXISTS TO PROVE: the authorization server is the only place
// that can say DENY on a ceiling violation. Not Andyur, and not agentgateway.
//
// Andyur narrows before it asks, and that is necessary but not sufficient: a
// compromised or buggy Andyur can simply ask for more. Only the issuer can
// refuse to issue. If the AS says no, no credential exists at all.
//
// This matters because of something measured, not assumed: an authorization
// server carries whatever `authorization_details` a client asks for. It
// allow-lists the RAR *type* and never its *content*, since a token exchange has
// no prior granted set to compare against. Ask for `identifier: "*"` and you get
// it (`infra/reference-as/verify.sh` asserts exactly that). The RAR claim is a
// CARRIER. This package is the CONTROL.
//
// FOR AN ADOPTER: replace `StaticEngine` with a client for your PDP. The call
// site in main.go -- `provider.WithTokenExchangeGrant(... policy.Evaluate ...)`
// -- does not change. That is the seam, and it is the whole point of the
// interface being this small.
//
// A CAVEAT THAT MUST NOT BE LOST: not every authorization server has a hook like
// this. Keycloak has none. Against an AS that cannot run policy at the exchange,
// this control is simply absent and enforcement falls back to the gateway and
// the PDP at tool-invoke time (docs/decisions.md O1). The design must therefore
// treat AS-side denial as the strongest available option and never as a
// requirement.
package policy

// Input is everything the decision may consider. It is deliberately the facts
// PRESENTED at the exchange plus nothing else: an engine that reached for
// ambient state would be deciding on something the audit record cannot show.
type Input struct {
	// Subject is the user the token will act for, from the subject token.
	Subject string
	// Actor is the workload asking, from the actor token. In Andyur this is the
	// RUN's SPIFFE id, not the agent's name, so two concurrent runs of one agent
	// are distinguishable here.
	Actor string
	// Agent is Actor reduced to the agent it belongs to, for ceiling lookup.
	Agent string
	// Audience and Resource name the target service.
	Audience []string
	Resource []string
	// Scope is what the client asked to be able to DO.
	Scope []string
	// Details is the RFC 9396 authorization_details the client asked to carry,
	// which for Andyur is the pin.
	Details []Detail
}

// Detail is one RFC 9396 authorization detail, reduced to the fields this
// reference engine reasons about.
type Detail struct {
	Type       string   `json:"type"`
	Identifier string   `json:"identifier,omitempty"`
	Actions    []string `json:"actions,omitempty"`
	Locations  []string `json:"locations,omitempty"`
}

// Decision is the answer. A denial always carries a Reason, because an error
// naming the wrong cause costs more than one naming none -- and this reason is
// what an operator sees when a tool call fails.
type Decision struct {
	Allow  bool
	Reason string
	// Scope is what was actually granted, which may be NARROWER than requested.
	// An engine must never return more than it was asked for.
	Scope []string
	// Details is the granted authorization_details, likewise never widened.
	Details []Detail
}

// Engine decides. One method, so an adopter's PDP client is a small adapter
// rather than a rewrite.
type Engine interface {
	Evaluate(Input) Decision
}
