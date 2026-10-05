# Authority runbook: drive the token mint by hand

> **SUPERSEDED IN PART — read `docs/authority-architecture.md` first.**
>
> This is a runbook for driving the token mint, and the mint is the component the
> architecture correction retires. Andyur issues audience-bound OAuth access
> tokens today; it is supposed to stop, and hand that job to the enterprise's own
> authorization server.
>
> It is kept because it is TRUE OF THE CODE TODAY, and someone operating or
> debugging the running system needs it. It is not a description of where we are
> going. Do not extend the behaviour it documents.


Andyur's token mint decides, once, how much authority a request may ever carry:

```
authority = entitlement AND pin AND ceiling AND audience
```

There is deliberately no check anywhere downstream that asks "is this run allowed
to touch account 447". The answer is settled at the mint, and the token that comes
out cannot express anything wider. This runbook makes that visible. You type every
request and read the real response.

Each section shows a legitimate call next to the escalation attempt it refuses.
The pairing matters. A refusal on its own proves nothing, because a broken server
also refuses everything.

## Start it

```bash
./run.sh authority-demo up
source /tmp/andyur-authority-demo/tokens.env
```

That runs its own server on port 8655 against a scratch database, so it cannot
disturb anything you have running. Same code, same schema, same endpoints: the
isolation is where the data lives, not what the product does.

**To run it against your actual Andyur instead**, which is the version that
answers "does the product work":

```bash
ANDYUR_AGENT_AUTH=on ./run.sh up
./run.sh authority-demo up --real
source data/tokens.env
```

Every agent it creates carries a prefix, `demo-` by default, and `./run.sh
authority-demo down --real` removes exactly those six names through
`DELETE /agents/<name>` and nothing else. Teardown never scans for "agents
starting with the prefix", because that would take an agent of yours that merely
sorts under it, and deletion has no undo.

Pass `--prefix <p>` to choose your own. That lets a second copy run beside the
first, which is useful if someone else is using the same Andyur or you want to
compare two ceiling configurations at once:

```bash
./run.sh authority-demo up --real --prefix alpha-
./run.sh authority-demo up --real --prefix beta-
./run.sh authority-demo down --real --prefix alpha-   # beta- is untouched
```

The prefix is recorded in the tokens file, so `down` cleans up the right set
without being told twice. Agent-auth must be on: with it off, dev treats every caller as the operator
and run tokens are not parsed at all, so there is no caller identity for the
ceiling to apply to.

Either way, the setup creates six agents whose only meaningful difference is the
ceiling each carries, gives four of them a live pinned run, and exports the run
tokens.

| agent | ceiling | its run is pinned to |
|---|---|---|
| `demo-classifier` | `actions: [files:read]` | account 447 |
| `demo-specialist` | unset, so unrestricted | account 447 |
| `demo-roamer` | unset | account **999** |
| `demo-bystander` | unset | account 447 |
| `demo-teller` | `audiences: [tool:bank]` | no run |
| `demo-muzzled` | `actions: []`, deny all | no run |
| `demo-ghost` | does not exist | |

Every run acts for `alice` and is entitled to `files:read`, `files:write` and
`payments:transfer`. So anything that comes back narrower than that was narrowed
by a **ceiling** or by the **pin**, never by the entitlement. That is what makes
each result attributable to one term.

Stop it with `./run.sh authority-demo down` (add `--real` if you started that way).
To clear a dev box entirely, `./run.sh reset`.

---

## 1. The ceiling, and the party it actually constrains

`demo-classifier` is read-only. `demo-specialist` is not. Both facts live in the registry,
not in the request.

**Legitimate.** `demo-classifier` asks for read, which it may have:

```bash
curl -s -X POST $B/oauth/token -H "X-Andyur-Run-Token: $TOK_CLASSIFIER" \
  -H 'content-type: application/json' \
  -d '{"audience":"tool:fs","actor":"demo-specialist","scope":["files:read"]}'
```

```json
{"access_token":"eyJ...","issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
 "token_type":"Bearer","expires_in":300}
```

No `scope` field in the response, because nothing was narrowed.

**The escalation.** `demo-classifier` now asks for write as well. It names `demo-specialist`,
which *is* write-capable, as the delegatee:

```bash
curl -s -X POST $B/oauth/token -H "X-Andyur-Run-Token: $TOK_CLASSIFIER" \
  -H 'content-type: application/json' \
  -d '{"audience":"tool:fs","actor":"demo-specialist","scope":["files:read","files:write"]}'
```

```json
{"access_token":"eyJ...","token_type":"Bearer","expires_in":300,
 "scope":"files:read"}
```

Write is gone, and `scope` now appears in the response *because* the grant came
back smaller than the request (RFC 6749 §3.3). Without that field the agent would
call the tool, get a 403 it cannot explain, and retry forever.

**Why this is the interesting one.** The obvious reading is that the ceiling
should be the delegatee's, since the delegatee is who will spend the token. That
was the first implementation, and it was wrong: the minted token is returned to
the **caller** in the response body, so "it was minted for someone else" is not a
control over who holds it. A read-only classifier could name a write-capable
specialist and walk away holding write. Both ceilings now apply. For a credential,
ask who ends up **holding** it, not whose name is on it.

---

## 2. The audience is a conjunct, and a refusal is not a redirect

`demo-teller` may only ever hold a token for `tool:bank`.

```bash
curl -s -X POST $B/oauth/token -H "X-Andyur-Run-Token: $TOK_CLASSIFIER" \
  -H 'content-type: application/json' \
  -d '{"audience":"tool:payments","actor":"demo-teller"}'
```

```json
{"detail":{"error":"invalid_target",
 "error_description":"'demo-teller' may not be granted the audience 'tool:payments': it is above this agent's registry ceiling"}}
```

`invalid_target` is RFC 8693 §2.2.2's dedicated code for "the server will not
issue for that target". It is a 400 rather than a 403 on purpose: the code is
machine-greppable, which separates this from every other 400 on the endpoint
better than a 403 that collapses into every other 403 on the service.

Note what does *not* happen. The audience is never rewritten to a permitted one.
A conjunction with a false term is false, not "the same authority pointed
somewhere else" — that would hand back a token for a target nobody asked about.

---

## 3. The pin travels inside the token

Decode the grant the setup minted:

```bash
./run.sh authority-demo decode $GRANT_SPECIALIST
```

```json
{
  "sub": "alice",
  "act": {"sub": "demo-specialist"},
  "aud": "tool:bank",
  "scope": ["files:read"],
  "authorization_details": [
    {"type": "urn:andyur:authority",
     "resources": {"account": "447"},
     "actions": ["files:read"]}
  ]
}
```

Four things are visible at once. `sub` is the human, and it travelled from the run
rather than from the request. `act.sub` is the delegatee (RFC 8693 §4.1). `aud` is
the single target. And `authorization_details` (RFC 9396) carries the resource
bound, so a resource server can ask "was this minted for the account I am being
asked to touch?" without calling back to Andyur.

`scope` is `files:read` even though alice may also write, because this grant was
minted from `demo-classifier`'s run and `demo-classifier` is read-only. That is section 1
showing up in the token itself.

**The escalation.** Try to state a different pin in the request:

```bash
curl -s -X POST $B/oauth/token -H "X-Andyur-Run-Token: $TOK_CLASSIFIER" \
  -H 'content-type: application/json' \
  -d '{"audience":"tool:fs","actor":"demo-specialist","pin":{"account":"999"}}'
```

```json
{"detail":[{"type":"extra_forbidden","loc":["body","pin"],
 "msg":"Extra inputs are not permitted","input":{"account":"999"}}]}
```

Rejected, not ignored. The body is composed by the model, and the pin is sealed on
the run by an authenticated caller, so there must be no field here through which
the model can restate what its own authority is about. Silently dropping the key
would tell a confused client nothing and would quietly start honouring the field
the day someone adds one with that name.

---

## 4. A chain hop cannot launder the pin

This is the subtlest one. `GRANT_ROAMER` was minted from the 447 run, for `demo-roamer`.
But `demo-roamer`'s own run is pinned to **999**.

**The escalation.** `demo-roamer` presents its 447 grant from its 999 run:

```bash
curl -s -X POST $B/oauth/token -H "X-Andyur-Run-Token: $TOK_ROAMER" \
  -H 'content-type: application/json' \
  -d "{\"audience\":\"tool:bank\",\"actor\":\"roamer\",\"subject_token\":\"$GRANT_ROAMER\"}"
```

```json
{"detail":{"error":"invalid_request",
 "error_description":"the subject token is pinned to [('account', '447')] but the calling run is pinned to [('account', '999')]: a grant cannot be re-pinned to a resource nobody delegated it for"}}
```

Before this was fixed, that call succeeded and returned 447's actions stamped onto
account 999 — a pairing no authenticated party had ever asserted. Presented from an
*unpinned* run it was different but no better: the resource bound vanished
entirely, so a resource server that was going to check the pin received a token
that made no resource claim at all. The pin is now inherited across the hop, and a
conflicting one is refused.

**Legitimate.** `demo-specialist`, pinned to 447, extends the grant that was minted for
it:

```bash
curl -s -X POST $B/oauth/token -H "X-Andyur-Run-Token: $TOK_SPECIALIST" \
  -H 'content-type: application/json' \
  -d "{\"audience\":\"tool:bank\",\"actor\":\"specialist\",\"subject_token\":\"$GRANT_SPECIALIST\"}"
```

A token comes back. Delegation chains still work; only the laundering is closed.

---

## 5. Only the agent a grant was minted for may extend it

`demo-bystander` presents a grant minted for `demo-specialist`:

```bash
curl -s -X POST $B/oauth/token -H "X-Andyur-Run-Token: $TOK_BYSTANDER" \
  -H 'content-type: application/json' \
  -d "{\"audience\":\"tool:bank\",\"actor\":\"specialist\",\"subject_token\":\"$GRANT_SPECIALIST\"}"
```

```json
{"detail":{"error":"invalid_request",
 "error_description":"subject token was minted for 'demo-specialist', not for the calling agent 'demo-bystander': it cannot be extended by a party it was not delegated to"}}
```

The subject token used to be matched on its `sub` alone. Since every run for alice
shares that `sub`, **any** same-user grant was a re-mint key: an agent holding a
narrow token could present a wider one it had merely observed and continue that
chain instead of its own. RFC 8693 puts the delegatee in `act.sub`, and the
delegatee is the party entitled to spend a grant and therefore to extend it.

---

## 6. Two absences that must not be confused

An actor with no registry row:

```bash
curl -s -X POST $B/oauth/token -H "X-Andyur-Run-Token: $TOK_CLASSIFIER" \
  -H 'content-type: application/json' -d '{"audience":"tool:fs","actor":"demo-ghost"}'
```

```json
{"detail":{"error":"invalid_target",
 "error_description":"no registry entry for agent 'demo-ghost': a ceiling cannot be read, so no authority can be derived for it"}}
```

An actor whose ceiling is a deliberate deny-all:

```bash
curl -s -X POST $B/oauth/token -H "X-Andyur-Run-Token: $TOK_CLASSIFIER" \
  -H 'content-type: application/json' -d '{"audience":"tool:fs","actor":"demo-muzzled"}'
```

```json
{"detail":{"error":"invalid_scope",
 "error_description":"no authority remains for 'demo-muzzled' after the entitlement, pin, ceiling and audience are intersected: refusing to mint a token that would permit nothing"}}
```

Both refuse, with different codes, and neither issues a token. The alternative —
minting a valid token whose scope is `[]` — is the worse outcome even though it
looks safe. Such a credential validates everywhere and permits nothing, so every
call made with it fails somewhere else for reasons that never mention the ceiling,
and whoever is on call debugs it as an outage.

A third absence is different again: an agent with **no ceiling set** is
unrestricted, not denied. Upgrading a live database adds those columns as NULL, so
reading NULL as "deny" would brick every agent that existed before the ceiling did.

---

## 7. Watch the decisions in the log

The mint is an authorization point, so it says what it did. In another terminal:

```bash
tail -f /tmp/andyur-authority-demo/server.log | grep "mint "
```

Re-run section 1's escalation and you get a line naming the caller, the actor, the
audience, the pin, what was asked for and what was granted. Re-run section 2 and
you get the refusal. Silent narrowing is the case that most needs this: it returns
200 with a shorter scope, which is invisible to an operator otherwise, and "why
can my agent no longer write" is a support question whose answer has to be in the
logs.

---

## What this demo does not show

**How the user gets sealed onto the run.** The setup writes `acting_user='alice'`
into the run row directly. In production that `sub` comes from the user's OIDC
login. For that path against a real Keycloak, run `./run.sh user-idp`.

**Agent-auth is on, and identity is not optional.** The demo sets
`ANDYUR_AGENT_AUTH=on` so a run token scopes its caller to one agent. Caller
identity always comes from SPIRE: every operator call carries a JWT-SVID
fetched through the local Workload API (`./run.sh spire-setup`, `spire-server`,
`spire-agent`), and there is no flag that substitutes for it. `ANDYUR_TRUST_LOCAL`
used to be that flag; it is deleted, because a caller who cannot be identified
is not an operator in any configuration. Per-run SVIDs on containers are
exercised by `./run.sh spire-redteam`.

**The resource server side.** Nothing here presents a minted token to a tool and
watches it be checked. The token is a ceiling, never proof that a request must be
allowed: a resource server still applies its own policy and current state. That
is the next thing to build a demo for.
