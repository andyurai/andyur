# Upstream issue: token exchange handler cannot see the requested scope or authorization_details

To file at https://github.com/luikyv/go-oidc/issues — text below, ready to paste.

---

**Title:** `TokenExchangeRequest` omits the requested scope and `authorization_details`, so a subject-aware policy has nowhere to run

**Version:** v0.25.0

### What I am trying to do

Run a policy decision on every RFC 8693 token exchange, where the decision depends
on **the subject** — "may this user, acting through this workload, receive this
scope for this resource?" This is the shape an authorization server needs in order
to be the place that can refuse to issue, rather than trusting the client to have
asked for the right thing.

### The problem

`goidc.TokenExchangeRequest` carries `RequestedTokenType`, `SubjectToken`,
`SubjectTokenType`, `ActorToken`, `ActorTokenType`, `Audience` and `Resource`. It
does **not** carry the requested `scope` or `authorization_details`.

The handler set by `WithTokenExchangeGrant` is the only place the subject becomes
known — it is what resolves the subject token and returns `Subject`. But scope,
resources and authorization details are all validated *before* it runs
(`internal/token/exchange.go`, v0.25.0):

```
 47   validateScopes(ctx, req, c, nil)
 51   validateResources(ctx, req, nil)
 55   validateAuthDetails(ctx, req, c, nil)
 92   ctx.TokenExchangeHandle(...)          <- the subject is learned HERE
105   NewGrant(ctx, c, GrantOptions{ ... Scopes: req.scopes, AuthDetails: req.authDetails ... })
```

So:

- `WithRARDetailValidator` runs at line 55 and receives the detail and nothing
  else, so it can judge the detail's shape but not who is asking for it.
- There is no scope-validation callback at all — only `WithScopes`, a static
  allow-list, and `WithOpenIDScopeRequired`.
- The handler at line 92 knows the subject but cannot see either value.

The result is that a subject-aware decision over scope or RAR cannot be expressed
anywhere in the current API.

### Why this matters for RAR specifically

On the exchange path there is no prior granted set to narrow against, so
`validateAuthDetails` is called with `opts == nil` and only the *type* allow-list
applies. The **content** is carried through unchecked — a client can request
`{"type": "<registered>", "identifier": "*"}` and the issued token carries it
intact. That is correct behaviour for a carrier, but it means the only way to
bound the content is a policy hook, and the hook that exists cannot see who is
asking.

### Suggested change

Both values are already parsed and are passed to `NewGrant` twenty lines later,
so this is a pass-through rather than new machinery:

```go
type TokenExchangeRequest struct {
    // ... existing fields ...
    RequestedScopes      []string
    RequestedAuthDetails []AuthDetail
}
```

populated at the call site:

```go
result, err := ctx.TokenExchangeHandle(goidc.TokenExchangeRequest{
    // ... existing fields ...
    RequestedScopes:      strings.Fields(req.scopes),
    RequestedAuthDetails: req.authDetails,
})
```

This is additive and does not change behaviour for existing handlers.

A patch against v0.25.0 is attached in this directory
(`0001-token-exchange-request-carries-scope-and-authdetails.patch`); it builds
clean with `go build ./...`.

### Alternative considered

Passing the values through the `context.Context` from an earlier validator. That
does not work from outside the module, because `oidc.Context` is internal — and it
would be a worse API besides, since it makes an ordering dependency invisible at
the call site.
