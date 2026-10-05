# Extensions

An extension is a separately installed Python distribution that plugs into
Andyur at one of a fixed set of seams. This document is the contract for writing
one. The code is [`andyur/extensions.py`](../andyur/extensions.py); where the two
disagree, the code is right and this is a bug.

## What enabling one means

An enabled extension is Python running in the control plane's process. It can
import anything the server can. The `Registrar` described below limits what an
extension is *offered*, so that a reviewer can see every place one plugs in; it
is not a sandbox. Naming an extension in `ANDYUR_EXTENSIONS` is trusting it as
much as the platform itself.

## Enabling one

Installing an extension does nothing. The operator enables it by name:

```bash
pip install acme-andyur-policy
export ANDYUR_EXTENSIONS=acme-policy        # comma-separated for several
```

Only named extensions are imported. The complete set of code a deployment runs
is therefore the package plus that one variable, and an extension nobody enabled
is never loaded.

Extensions are loaded by the control-plane server and by nothing else. The
worker daemon, the runner and the workflow execution worker do not read
`ANDYUR_EXTENSIONS`. Every server replica loads its own copy from its own
environment, so the variable, and the package it names, must be the same on all
of them: a replica started without it serves with no policy, and the only place
that shows is its startup log, where each enabled extension is named with its
distribution and version.

The server refuses to start, rather than serving without it, when a named
extension:

- is not installed, or is declared by more than one installed distribution;
- fails to import, or raises while registering;
- claims a name a built-in or another extension already holds;
- installs an authorization policy while `ANDYUR_USER_AUTH` is off (the policy
  would never be consulted);
- installs an authorization policy whose `refuse` is an `async def`;
- is configured with a policy bound that is not a positive number.

## Declaring one

```toml
# pyproject.toml of the extension
[project.entry-points."andyur.extensions"]
acme-policy = "acme_andyur.policy:register"
```

The entry point is a callable that receives a `Registrar`. It is not given the
application, the database or the configuration; what it may do is exactly what
`Registrar` offers.

```python
def register(registrar):
    registrar.authorization_policy(AcmePolicy())
```

## The seams

### `registrar.workflow_provider(name, builder)`

Offers a workflow provider, selectable with `ANDYUR_WORKFLOW_PROVIDER=<name>`
like a built-in one. `builder` is called with no arguments and returns an object
implementing `andyur.orchestration.WorkflowProvider`.

Names are compared in lower case. Built-in names (`local`, `temporal`) cannot be
taken, and the provider's own `name` must be exactly the lower-case name it was
registered under: runs are bound to a provider,
and later claimed by it, under the name it reports. So a run bound to a built-in
provider means the same engine whatever else is installed.

Disabling a provider extension does not move its runs. A run bound to a provider
that is no longer loaded is not claimed by any other, so drain those runs before
removing the extension. If `ANDYUR_WORKFLOW_PROVIDER` still names the removed
provider, the server refuses to start and says which providers it knows.

### `registrar.authorization_policy(policy)`

Installs the one policy that may further narrow what an authenticated user can
do. At most one may be enabled.

```python
from andyur.extensions import UserRequest

class AcmePolicy:
    def refuse(self, request: UserRequest) -> str | None:
        if request.action.startswith("POST ") and "auditors" in request.claims.get("groups", []):
            return "auditors are read-only"
        return None
```

`request.action` is the route as declared, `"<METHOD> <path template>"`, for
example `"POST /agents/{name}/trigger"`; `request.params` holds its path
parameters. `request.claims` are the user token's claims, already validated, as
a read-only copy. Return `None` to allow or a string to refuse. Anything else,
including `False`, is treated as the policy failing, and refuses.

**What it governs.** Every request that presents a user token
(`X-Andyur-User-Token`) under user-auth, on every API route, including routes
that do not otherwise look at the user. The generated documentation routes
(`/docs`, `/docs/oauth2-redirect`, `/redoc`, `/openapi.json`) are not API routes
and are not governed;
they describe the API and carry nothing about users or agents. A request with
no user token is the host operator's SVID and is not governed, so that halting
a workflow cannot depend on a browser session or on the policy answering.

**Who it is asked about.** The calling workload is authenticated first, by its
SVID, and then the user, by the token. With a policy enabled, a user token is
accepted only from the operator workload, which is what the CLI and the console
are: a caller with no valid SVID gets the platform's 401, any other workload
presenting a user token gets a 403, and neither reaches the identity provider
or the policy. In particular an agent run, which holds a runner SVID and may
hold its user's token, cannot ask the policy anything. A user token that does
not validate is a 401 on every API route.

**When it is asked.** Once per request, before the route runs. Ownership and
the admin role are checked afterwards, so a policy may be asked about a request
the platform then refuses. It is never
asked to allow one: returning `None` allows nothing the platform would refuse.

**What the caller sees.**

| The policy | The caller gets |
|---|---|
| returns `None` | whatever the platform answers |
| returns a string | `403`, carrying the string on one line, redacted and cut to 256 characters |
| raises, or returns anything else | `403`, with no detail from the policy |
| does not answer within the deadline | `503` with `Retry-After` |
| has every allowed call still outstanding | `503` with `Retry-After`, at once |

Because the policy answers before the route looks anything up, a refusal is the
same whether or not the thing named exists. Keep it that way in the policy
itself: `request` carries the route and its parameters, not existence, and a
refusal that depended on existence would reveal what the platform's 404s
deliberately do not.

**It is bounded.** `refuse` is called on a thread of its own, never on a request
thread, with a deadline. A policy that hangs holds its own slot until it
returns; once every slot is held, further user requests are answered `503`
immediately. The operator's path and the liveness check are unaffected, and a
hung call does not stop the server from shutting down.

The cap is on calls, not on callers. One user sending requests faster than the
policy answers can hold every slot, and other users are then answered `503`
until it catches up. If the policy is slow enough for that to matter, put a
per-caller rate limit in front of the server.

| Variable | Default | Meaning |
|---|---|---|
| `ANDYUR_EXTENSION_POLICY_TIMEOUT` | `2.0` | seconds a consultation may take |
| `ANDYUR_EXTENSION_POLICY_CONCURRENCY` | `8` | consultations outstanding at once |

`refuse` may block, for example to call a decision service, but it runs on a
thread: it must be an ordinary function, and it should carry its own timeout
shorter than the deadline so that its slot comes back. It runs inside the
consultation's span, so a traced call it makes is a child of that span.

**What it leaves behind.** Each consultation is a span named `authz.policy`
under the request's span, with `andyur.authz.policy` (the extension's name),
`andyur.authz.action`, `andyur.user` and `andyur.authz.decision`, which is one
of `allow`, `refuse`, `error`, `timeout`, `saturated`. A refusal adds an
`andyur.authz.refused` event carrying the reason; `error`, `timeout` and
`saturated` mark the span as an error, and `error` adds an `exception` event
with the exception's type and its message, redacted and cut like a reason. The
traceback is not recorded, because what a policy raises is as untrusted as what
it returns. The
counter `andyur.extension_policy.decisions` and the histogram
`andyur.extension_policy.duration` count and time them. See
[observability.md](observability.md) for what to do when each appears.
