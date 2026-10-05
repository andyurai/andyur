"""Central configuration.

Everything resolves from environment variables. Most have local defaults, so
individual subsystems can be left alone and pointed elsewhere in deployment.

The exception, and it is deliberate: ANDYUR_PROFILE defaults to `prod`, and a
production deployment REFUSES TO START until its containment is configured (see
assert_profile below). So this does not run out of the box -- `ANDYUR_PROFILE=dev`
does, and the refusal names every missing control. An earlier version of this
docstring promised out-of-the-box, which stopped being true the day the default
flipped, and .env.example repeated it.

A .env in the project directory (or one directory above it) is loaded if present.
"""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

from . import layout

PROJECT_ROOT = layout.PACKAGE_PARENT

def _load_env() -> None:
    """Layer the .env files UNDER the real environment, never over it.

    The project .env beats a parent .env, and an EXPORTED variable beats both.
    `load_dotenv(override=True)` inverted that last rule, which is the one that
    matters operationally: a gate that runs `export ANDYUR_OTEL=on` was
    silently overridden by whatever the checked-out .env said, so it exercised
    a dark process and then failed reporting that the collector was down.
    """
    if not layout.SOURCE_CHECKOUT:
        # Beside an installed copy is a library directory. A .env there was
        # not written for this program, and reading it would let a file in
        # site-packages choose which server the command talks to.
        return
    exported = dict(os.environ)
    load_dotenv(PROJECT_ROOT.parent / ".env")
    load_dotenv(PROJECT_ROOT / ".env", override=True)
    os.environ.update(exported)


_load_env()

DATA_DIR = layout.data_dir()
# The agent "mind" (files). In multi-node deployments this points at a shared
# mount (NFS/EFS) so any runner on any node can load and save an agent's files;
# it is independent of where the state database lives.
WORKSPACE_DIR = Path(os.environ.get("ANDYUR_WORKSPACE_DIR", DATA_DIR / "workspace"))
DB_PATH = DATA_DIR / "andyur.db"
# State store. Empty -> local SQLite (single node). A postgres:// URL -> shared
# Postgres, which is what lets multiple stateless server replicas run.
DB_URL = os.environ.get("ANDYUR_DB_URL", "")

# Where the agent mind (files) is stored: 'local' filesystem (default, under
# WORKSPACE_DIR) or 's3' object storage (S3 / MinIO / R2 / GCS). Object storage
# lets every node share the mind with no shared filesystem, and the server is
# the only component that touches it (runners reach the mind over HTTP).
STORAGE = os.environ.get("ANDYUR_STORAGE", "local").lower()
S3_ENDPOINT = os.environ.get("ANDYUR_S3_ENDPOINT", "http://localhost:9000")
S3_BUCKET = os.environ.get("ANDYUR_S3_BUCKET", "andyur")
S3_ACCESS_KEY = os.environ.get("ANDYUR_S3_ACCESS_KEY", "minioadmin")
S3_SECRET_KEY = os.environ.get("ANDYUR_S3_SECRET_KEY", "minioadmin")
S3_REGION = os.environ.get("ANDYUR_S3_REGION", "us-east-1")

# Associative memory graph (Phase 6). 'off' (default) disables it entirely;
# 'neo4j' stores a per-agent memory graph in Neo4j. Like the mind, only the
# server touches it; runners and the CLI reach it over HTTP.
GRAPH = os.environ.get("ANDYUR_GRAPH", "off").lower()
NEO4J_URL = os.environ.get("ANDYUR_NEO4J_URL", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("ANDYUR_NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("ANDYUR_NEO4J_PASSWORD", "andyurgraph")
# Local embedding model (Ollama) used by the runner to embed graph entities.
# Decoupled from the generation backend: even a cloud run embeds locally and
# free. Capture degrades gracefully (no vector) if it is unreachable.
EMBED_MODEL = os.environ.get("ANDYUR_EMBED_MODEL", "nomic-embed-text")
# Consolidation A (mechanical, no LLM): the server periodically merges near-
# identical graph entities by cosine over their embeddings and prunes orphans.
# Off by default; when on it runs in the server heartbeat loop.
GRAPH_CONSOLIDATE = os.environ.get(
    "ANDYUR_GRAPH_CONSOLIDATE", "off").lower() in ("1", "on", "true")
GRAPH_CONSOLIDATE_INTERVAL = int(
    os.environ.get("ANDYUR_GRAPH_CONSOLIDATE_INTERVAL", "300"))
GRAPH_MERGE_THRESHOLD = float(os.environ.get("ANDYUR_GRAPH_MERGE_THRESHOLD", "0.92"))

# --- Deployment profile ----------------------------------------------------
#
# Andyur's containment (sandbox, model-call broker, workload identity, egress
# lockdown) used to be individually opt-in, each defaulting to off. That makes
# the DEFAULT deployment the unsafe one, and defaults are what a platform is
# actually judged on: nobody reads a hardening guide before the first run, and
# an opt-in control is one nobody turned on.
#
# So the posture is now explicit and prod is the default. An unconfigured
# deployment refuses to start and says exactly what is missing, rather than
# starting in a shape its operator would not have chosen. Running without the
# controls is still entirely possible -- it is one variable, and it has to be a
# decision:
#
#   ANDYUR_PROFILE=prod   (default) every containment control is required
#   ANDYUR_PROFILE=dev    single trusted machine; nothing is required
#
# There is deliberately no middle profile. A half-contained platform invites
# reasoning about which half you are in, and that reasoning is where mistakes
# live.
PROFILE = os.environ.get("ANDYUR_PROFILE", "prod").strip().lower()
# An unrecognised value must NOT mean "not prod". `PROFILE == "prod"` alone
# fails open on the single most likely thing an operator types -- "production" --
# and on a trailing space, silently disabling every containment control with no
# log line to say so. A wrong explicit value is worse than an absent one,
# because the operator believes they configured it.
_PROFILES = {"prod", "dev"}
if PROFILE not in _PROFILES:
    raise RuntimeError(
        f"ANDYUR_PROFILE='{os.environ.get('ANDYUR_PROFILE')}' is not a profile. "
        f"Use one of: {', '.join(sorted(_PROFILES))}. Refusing to guess, because "
        "guessing wrong here silently turns off every containment control."
    )
PROD = PROFILE == "prod"

# One installation shape covers both the persistent control plane and ephemeral
# agent runs. Mixed shapes are deliberately not a product contract yet.
DEPLOYMENT = os.environ.get("ANDYUR_DEPLOYMENT", "native").strip().lower()
if DEPLOYMENT not in {"native", "docker", "kubernetes"}:
    raise RuntimeError(
        f"ANDYUR_DEPLOYMENT='{os.environ.get('ANDYUR_DEPLOYMENT')}' is not a "
        "deployment. Use one of: native, docker, kubernetes. Refusing to infer "
        "or fall back because that could execute work in a weaker runtime."
    )


def _on(var: str) -> bool:
    return os.environ.get(var, "off").lower() in ("1", "on", "true")


# Read here (rather than imported from identity/daemon) so the profile check has
# no import cycle and one place answers "is this control actually on".
SANDBOX = _on("ANDYUR_SANDBOX")

# Egress lockdown: the Docker network run containers are attached to. In the
# production profile this MUST be an `internal` network -- one Docker gives no
# route off the host -- so the agent can reach the services placed on it (the
# control plane, the broker, its own tool servers) and nothing else.
#
# Why this control and not a filter: an agent runs arbitrary code with a shell
# and a fetch tool. Anything it can read, it can send, so confining what it may
# READ is only half a boundary; the other half is having nowhere to send it. A
# prompt cannot talk its way past a missing route.
EGRESS_NETWORK = os.environ.get("ANDYUR_SANDBOX_NETWORK", "")



# Level for the `andyur` package's own logs. INFO by default because the mint's
# issuance record lives there, and an audit record that does not emit is not one.
LOG_LEVEL = os.environ.get("ANDYUR_LOG_LEVEL", "INFO").upper()

class InsecureProfile(RuntimeError):
    """Raised at startup when the production profile is not actually met."""


def temporal_dispatch_problem() -> str | None:
    """Why this production process may not run Temporal as configured, or None.

    Every process that reads the dispatch mode must agree on it -- the server
    admits triggered runs, the control plane's workflow worker admits scheduled
    ones -- so each refuses the same way (see `assert_profile`)."""
    if not PROD:
        return None
    provider = (os.environ.get("ANDYUR_WORKFLOW_PROVIDER") or "").strip().lower()
    dispatch = (os.environ.get("ANDYUR_TEMPORAL_DISPATCH") or "").strip().lower()
    if provider == "temporal" and dispatch != "engine":
        return ("ANDYUR_TEMPORAL_DISPATCH=engine  a production Temporal deployment "
                "dispatches runs through the engine; unset, every run silently goes "
                "through the native assignment loop instead")
    return None


def assert_profile(*, signs_run_tokens: bool = True) -> None:
    """Refuse to start a production deployment that is not contained.

    `signs_run_tokens=False` is for a process that neither signs nor verifies
    run tokens -- the engine's execution worker, which receives each run's
    credentials from the server per run. It is not asked for the signing key,
    so it does not have to carry one; every other production check applies.

    Called by the server and the daemon at startup. Import-time would be worse:
    a test suite or a tool that merely imports Andyur would then be unable to
    run without a full production environment.
    """
    if not PROD:
        return
    missing = []
    kubernetes = DEPLOYMENT == "kubernetes"
    docker = DEPLOYMENT == "docker"
    if DEPLOYMENT == "native":
        missing.append(
            "ANDYUR_DEPLOYMENT=docker|kubernetes  native runs execute directly "
            "on this host with a shell and your filesystem")
    if docker and not SANDBOX:
        missing.append(
            "ANDYUR_SANDBOX=on          required by the Docker deployment until "
            "the legacy sandbox flag is retired; without it an agent shell runs "
            "against the control-plane host")
    # ANDYUR_IDENTITY was checked here. It is not a setting any more, so there is
    # no production-only version of it to require: an Andyur that cannot reach the
    # Workload API does not start, in any profile.
    if not AGENT_AUTH:
        missing.append(
            "ANDYUR_AGENT_AUTH=on       runs are not confined to their own agent "
            "otherwise: any run can rewrite any agent")
    # ANDYUR_TRUST_LOCAL was refused here. The branch that trusted a local caller
    # was deleted along with ANDYUR_IDENTITY (a caller who cannot be identified is
    # not an operator in any configuration), so there is no longer a setting to
    # refuse: the flag is gone, not merely off.
    if not EGRESS_NETWORK and docker:
        missing.append(
            "ANDYUR_SANDBOX_NETWORK=... name an INTERNAL Docker network for runs; "
            "without it an agent has the open internet to exfiltrate to")
    if _needs_broker():
        missing.append(
            "ANDYUR_BROKER_URL=...      the provider API key is inherited by the "
            "agent subprocess otherwise, and one injection exfiltrates it")
    if not _delegation_configured():
        missing.append(
            "ANDYUR_DELEGATIONS=...     who may hand work to whom. Delegation is "
            "how one agent's text reaches another agent's prompt, so an unset "
            "policy lets a single compromised agent wake every other one; use "
            "\"*\" to keep that open deliberately")
    if SECCOMP_MODE != "require" and docker:
        missing.append(
            "ANDYUR_SECCOMP=require     run containers keep the host runtime's "
            "default filter otherwise, which on some hosts is none at all; and "
            "the default never denies ptrace, so in pod mode the agent can "
            "inspect the driver it shares a uid with")
    elif docker and not SANDBOX:
        # require with nothing to apply it to. Naming this is the difference
        # between a control and a belief about a control.
        missing.append(
            "ANDYUR_SANDBOX=on          ANDYUR_SECCOMP=require has no effect "
            "without a container to apply the filter to")
    missing.extend(_secret_problems(signs_run_tokens=signs_run_tokens))
    # NO SILENT ARCHITECTURE A (ADR-014 D11, B+ adversarial review). An unset
    # ANDYUR_TEMPORAL_DISPATCH means `native`, and the native worker daemon is
    # still deployed beside the engine -- so a production manifest that lost
    # the line silently ran every Temporal-backed run through the native
    # assignment loop. Production Temporal dispatches through the engine, said
    # explicitly. The package default (Local) is untouched: this names only
    # what a production deployment that CHOSE Temporal must also say.
    problem = temporal_dispatch_problem()
    if problem:
        missing.append(problem)
    # The external AS is required when it would be USED, not at boot -- the
    # broker rule. Production never mints tool authority locally either way:
    # /oauth/token refuses the local signer unconditionally in prod, and the
    # runner's run-start probe withholds delegated tools with that same named
    # refusal, so a prod deployment without an AS runs and its delegated tools
    # refuse -- fail closed at the mint, where the authority actually is. A
    # boot-time version of this check required an AS of deployments that never
    # exercise delegated tool authority, which is how the shipped compose spent
    # two days unbootable (gap 15b). A HALF-configured AS still refuses boot:
    # as_problems() below rejects stray ANDYUR_AS_* set without the endpoint.
    if not USER_AUTH:
        missing.append(
            "ANDYUR_USER_AUTH=on        production runs must inherit an "
            "enterprise-authenticated subject, not an asserted or absent user")
    if not REQUIRE_RUN_SVID:
        missing.append(
            "ANDYUR_REQUIRE_RUN_SVID=on every run-token call must also prove "
            "the matching per-run SPIFFE workload identity")
    # A half-configured external AS fails at the first tool call, inside a run,
    # rather than at boot -- and until then Andyur keeps signing its own access
    # tokens while the configuration says it should not.
    missing.extend(as_problems())
    if not missing:
        return
    raise InsecureProfile(
        "ANDYUR_PROFILE=prod requires:\n  "
        + "\n  ".join(missing)
        + "\n\nSet ANDYUR_PROFILE=dev to run without these on a trusted machine."
    )


def assert_user_auth() -> None:
    """When user-auth is on -- in ANY profile -- refuse to start without a
    verifiable issuer AND audience.

    Admin (and the whole owner axis) is derived from claims in the user's token,
    and `oidc.validate_user_claims` only checks `aud`/`iss` when they are
    configured (`verify_aud=bool(OIDC_AUDIENCE)`). With them blank, a token the
    IdP minted for a DIFFERENT audience -- another client in the same realm --
    validates here and carries the same `realm_access.roles`, so an unrelated
    token becomes admin. Requiring both closes that: a token must name THIS
    deployment to be trusted for authority. Not folded into assert_profile
    because the hole exists in dev too, and dev is where user-auth is first
    switched on."""
    if not USER_AUTH:
        return
    missing = [name for name, val in
               (("ANDYUR_OIDC_ISSUER", OIDC_ISSUER),
                ("ANDYUR_OIDC_AUDIENCE", OIDC_AUDIENCE)) if not val]
    if missing:
        raise InsecureProfile(
            "ANDYUR_USER_AUTH=on requires " + " and ".join(missing)
            + ": admin and ownership are read from the user's token, so it must "
            "be validated against a known issuer and audience or a token minted "
            "for another audience would be trusted for authority.")


def _delegation_configured() -> bool:
    """Imported lazily: config must not depend on the server package, which
    imports config."""
    from .server import delegation
    return delegation.configured()




def _secret_problems(*, signs_run_tokens: bool = True) -> list:
    """Secrets that must be REAL in production, not defaults or per-process
    randomness.

    Every item here shares a failure mode: the platform starts, appears to work,
    and is either quietly insecure or quietly broken in a way that only shows up
    under load, across replicas, or during an incident. Refusing at boot is the
    cheapest place to find any of them.
    """
    problems = []
    if signs_run_tokens and not RUN_TOKEN_SECRET_SET:
        # The random per-process fallback is fine for a single process talking to
        # itself. It breaks the moment anything ELSE verifies a token: a second
        # replica, or the broker, which is a separate process that must verify
        # credentials this server signed. Symptom without this check: every model
        # call 401s, and nothing says why.
        problems.append(
            "ANDYUR_RUN_TOKEN_SECRET=.. shared by the server replicas AND the "
            "broker, which verify the tokens this server signs; the random "
            "per-process default makes them all reject each other")
    if STORAGE == "s3" and (S3_ACCESS_KEY == "minioadmin" or S3_SECRET_KEY == "minioadmin"):
        problems.append(
            "ANDYUR_S3_ACCESS_KEY/SECRET_KEY  still the well-known development "
            "default, which is a published credential for the store holding "
            "every agent's mind")
    if GRAPH == "neo4j" and NEO4J_PASSWORD == "andyurgraph":
        problems.append(
            "ANDYUR_NEO4J_PASSWORD=..   still the default in this repository, on "
            "the store holding every agent's memory graph")
    if DB_URL and not EXCHANGE_KEY_PATH:
        # Multi-node: an ephemeral keypair per process means a downstream token
        # signed by one replica fails against the JWKS another replica publishes,
        # so delegation works or fails depending on which replica answered.
        problems.append(
            "ANDYUR_EXCHANGE_KEY=...    a PEM shared by the replicas; without it "
            "each generates its own, and a delegated token validates only against "
            "the replica that happened to mint it")
    return problems


def _needs_broker() -> bool:
    """Require a broker whenever a provider key would otherwise reach the agent.

    The condition is deliberately "is there a key present", NOT "is the backend
    api mode". Those are different questions, and getting them confused is how
    the key leaks: the daemon forwards ANTHROPIC_API_KEY into every run container
    whenever no broker is configured (daemon._sandbox_argv), regardless of
    ANDYUR_LLM. So with ANDYUR_LLM=ollama and a stale key still exported from a
    .env, production would boot cleanly and hand that key to every agent.

    Asking about the key itself makes the check match what actually happens. A
    deployment with no key present needs no broker, which keeps the local-model
    path free of ceremony -- ceremony is what teaches people to disable checks.
    """
    return bool(os.environ.get("ANTHROPIC_API_KEY")) and not BROKER_URL


# Agent-scoped API authorization (R1). When on, run-scoped endpoints (an agent's
# files, memory graph, task/message creation, run lifecycle) require a per-run
# token that names WHICH agent is acting, so a compromised run is confined to its
# own namespace and cannot forge provenance. Off by default (role-only auth, the
# dev default). The operator is proven by its SVID; identity is unconditional, so
# there is no configuration in which a no-token call is treated as the operator.
AGENT_AUTH = _on("ANDYUR_AGENT_AUTH")
# HMAC secret the server signs run tokens with. MUST be set and shared across
# replicas in a multi-node deployment; a random per-process default is fine for
# single-node. Only the server needs it (the daemon/runner carry the opaque token).
RUN_TOKEN_SECRET = os.environ.get("ANDYUR_RUN_TOKEN_SECRET") or os.urandom(32).hex()
# The run token must outlive the run, or a healthy long run's calls would 401
# mid-flight. This clamp keeps that true for the DEFAULT lifetime only: it can
# only ever compare against the platform-wide setting, so it says nothing about
# an agent that was granted its own lifetime in the registry.
#
# That case is handled where the token is actually minted. `_run_token_ttl`
# passes an explicit TTL derived from the lifetime sealed onto the run, so a
# granted agent's credential covers its grant regardless of this value. This
# stays as the answer for a run that declared nothing, which is also the only
# thing it was ever able to answer correctly.
_RUN_TTL = int(os.environ.get("ANDYUR_RUN_TTL_SECONDS", "900"))
RUN_TOKEN_TTL = max(int(os.environ.get("ANDYUR_RUN_TOKEN_TTL", "1800")), _RUN_TTL + 300)
# Whether the run-token secret was explicitly provided (vs a per-process random
# default). Used to refuse an insecure multi-node boot.
RUN_TOKEN_SECRET_SET = bool(os.environ.get("ANDYUR_RUN_TOKEN_SECRET"))
# ANDYUR_TRUST_LOCAL was defined here: a dev escape hatch that treated a
# token-less local caller as the operator. Deleted with ANDYUR_IDENTITY -- a
# caller who cannot be identified is not an operator in any configuration, so
# there is no configuration in which the flag could do anything.
# Bind the R1 run token to the caller's container-attested SVID (Slice 4). When
# identity is on and a run-scoped call presents a per-run SVID, the server always
# requires it to match the token's agent/run (a stolen token replayed from another
# container fails). This flag makes a matching per-run SVID MANDATORY on every
# token-scoped call (full enforcement), rather than only checked when present.
REQUIRE_RUN_SVID = os.environ.get("ANDYUR_REQUIRE_RUN_SVID", "off").lower() in (
    "1", "on", "true",
)
# User delegation (U1): each agent instance is OWNED by a user authenticated via an
# OIDC IdP; runs inherit the owner as their `sub`, carried in the run grant. Opt-in;
# off => no user axis (agents are ownerless, as before).
USER_AUTH = os.environ.get("ANDYUR_USER_AUTH", "off").lower() in ("1", "on", "true")
OIDC_ISSUER = os.environ.get("ANDYUR_OIDC_ISSUER", "")
OIDC_JWKS_URL = os.environ.get("ANDYUR_OIDC_JWKS", "")   # else derived from the issuer
OIDC_AUDIENCE = os.environ.get("ANDYUR_OIDC_AUDIENCE", "")
# Scoped least privilege (U2). Space-separated scopes a user is entitled to; "*" = all.
# A run is granted the INTERSECTION of this and the scope its task declares
# (TriggerBody.scope), sealed in the run grant and enforced per endpoint. So even
# acting as the entitled user, a run cannot exceed the scope its task asked for.
USER_ENTITLEMENTS = os.environ.get("ANDYUR_USER_ENTITLEMENTS", "*")
# Admin axis. A user whose validated IdP token carries ADMIN_ROLE in the claim
# named by ROLES_CLAIM (a dot path; default matches Keycloak's realm-role shape,
# any IdP works by pointing this at its own roles/groups claim) may see and
# manage EVERY owner's agents and the ops surfaces (workers, workflow halt).
# Admin is never impersonation: triggering an agent stays owner-only, because a
# run's subject token must belong to the user it acts for.
# Unset ADMIN_ROLE => nobody is admin (fail closed), which is also why the role
# lives in the IdP and not here: Andyur decides what admin MAY do, the IdP
# decides WHO holds it.
ADMIN_ROLE = os.environ.get("ANDYUR_ADMIN_ROLE", "")
ROLES_CLAIM = os.environ.get("ANDYUR_ROLES_CLAIM", "realm_access.roles")
# WHICH CLAIM IS THE USER. `sub` by default, and the default is the safe one:
# OIDC guarantees `sub` is stable for the life of the account and never reused,
# which is exactly what an OWNERSHIP key needs. The cost is legibility -- a
# Keycloak `sub` is a UUID, so `acting_user` in the audit trail, and the subject
# every downstream resource server resolves, reads as
# `f78382c2-0614-4b2d-b4f8-24b7eef284d9` rather than `sarah.miller`.
#
# Point this at `preferred_username` (or `email`, or any single top-level claim)
# to get a legible audit trail, KNOWING WHAT YOU ARE TRADING: those claims are
# not guaranteed unique or stable. An IdP that lets a username be released and
# re-registered would hand the new holder every agent, run and memory owned by
# the old one, because ownership is compared as a string. Only set this against
# an IdP where the claim is immutable and never recycled.
#
# Changing it on a deployment that already has data ORPHANS that data: existing
# rows hold the old identifier and will not match the new one. Migrate or start
# clean; the platform cannot tell the two identifier spaces apart.
OIDC_SUBJECT_CLAIM = os.environ.get("ANDYUR_OIDC_SUBJECT_CLAIM", "sub").strip() or "sub"
# The OAuth client the CONSOLE logs in as. Deliberately its OWN client, distinct
# from the CLI's `andyur-cli`: the console client is Auth Code + PKCE only (no
# resource-owner password grant) and is scoped to the `andyur` audience alone, so
# a console session token cannot be replayed at another audience. An adopter
# points this at whatever client id they register for the console in their IdP.
CONSOLE_CLIENT_ID = os.environ.get("ANDYUR_CONSOLE_CLIENT_ID", "andyur-console")
# Where the console links a run's trace. A URL template with `{trace_id}`
# (Jaeger: http://localhost:16686/trace/{trace_id}); empty = no link. The
# console never queries a tracing backend, it only links out, so any backend
# with a per-trace URL works and none is required.
TRACE_UI_URL = os.environ.get("ANDYUR_TRACE_UI_URL", "")

# Authorization decision point (PDP). "builtin" decides in-process, using the rules
# in server/pdp.py -- the default, so Andyur still runs standalone. "authzen"
# delegates the same decisions to an external policy engine (OPA behind an AuthZEN
# shim) over the OpenID AuthZEN Authorization API, so authorization changes without
# a redeploy and the engine is swappable.
# May an authenticated API client ASSERT which user a run acts for, when there is
# no IdP to authenticate that user? Default NO.
#
# The design names three tiers of who may say who a run acts for: an IdP claim is
# strongest, an authenticated application asserting it is acceptable AND GETS
# LOGGED, and the agent must be structurally unable to. This flag is the middle
# tier, and it is off by default because turning it on makes Andyur sign an
# RS256 token whose `sub` nobody authenticated -- a resource server validating
# against Andyur's JWKS cannot tell that apart from a real login unless it looks
# at the provenance claim the mint adds (`andyur_sub_src`). That is a real
# capability with a real cost, so an operator turns it on deliberately.
#
# Irrelevant when ANDYUR_USER_AUTH is on: the IdP wins and an asserted user is
# refused outright rather than merged.
ASSERTED_USER = os.environ.get("ANDYUR_ASSERTED_USER", "off").lower() in (
    "1", "on", "true")

PDP = os.environ.get("ANDYUR_PDP", "builtin").lower()
PDP_URL = os.environ.get("ANDYUR_PDP_URL", "http://127.0.0.1:8181")

# Downstream delegation (U4, RFC 8693 token exchange). When a run delegates to another
# agent or an external tool, the server mints a downstream grant that carries the SAME
# user (`sub`), appends the delegatee to a nested `act` chain, and narrows the scope to
# a subset of the parent's (never wider). For external targets the exchange issues an
# asymmetric (RS256) JWT they validate against Andyur's JWKS without calling back;
# server-internal calls keep the HMAC run token. A shared PEM key across replicas; if
# unset, an ephemeral keypair is generated at startup (fine for a single node / dev).
EXCHANGE_KEY_PATH = os.environ.get("ANDYUR_EXCHANGE_KEY", "")   # RSA private-key PEM
EXCHANGE_ISSUER = os.environ.get("ANDYUR_EXCHANGE_ISSUER", "andyur")

# The ADOPTER'S authorization server (decisions.md #1: the AS is theirs, always).
# When the token endpoint is set, Andyur ASKS it to mint instead of signing an
# access token itself. Off by default, because the getting-started path must not
# require an authorization server the reader does not have.
#
# These four are a SET. A half-configured AS is worse than none: it fails at the
# first tool call, in a run, rather than at boot -- so `assert_profile` refuses a
# partial set rather than discovering it later.
AS_TOKEN_ENDPOINT = os.environ.get("ANDYUR_AS_TOKEN_ENDPOINT", "")
AS_ISSUER = os.environ.get("ANDYUR_AS_ISSUER", "")
AS_CLIENT_ID = os.environ.get("ANDYUR_AS_CLIENT_ID", "")
AS_CLIENT_SECRET = os.environ.get("ANDYUR_AS_CLIENT_SECRET", "")
# The JWKS a resource server validates the AS's tokens against. Discovered from
# AS_ISSUER when unset; never CONSTRUCTED from it, because
# `<issuer>/.well-known/jwks.json` 404s on Keycloak and that guess is gap G3.
AS_JWKS_URL = os.environ.get("ANDYUR_AS_JWKS", "")
AS_PROVIDER = os.environ.get("ANDYUR_AS_PROVIDER", "reference").strip().lower()
AS_CAPABILITY = os.environ.get("ANDYUR_AS_CAPABILITY", "core").strip().lower()
AS_PROVIDER_SET = "ANDYUR_AS_PROVIDER" in os.environ
AS_CAPABILITY_SET = "ANDYUR_AS_CAPABILITY" in os.environ
AS_RESOURCE_SCOPE = os.environ.get("ANDYUR_AS_RESOURCE_SCOPE", "").strip()
AS_CERTIFICATION_FILE = os.environ.get("ANDYUR_AS_CERTIFICATION_FILE", "").strip()
AS_CERTIFICATION_PUBLIC_KEY_FILE = os.environ.get(
    "ANDYUR_AS_CERTIFICATION_PUBLIC_KEY_FILE", "").strip()
AS_PRODUCT_VERSION = os.environ.get("ANDYUR_AS_PRODUCT_VERSION", "").strip()
# A non-core capability additionally requires the signed monotonic overlay.
# These values are deliberately separate from the legacy v2 core artifact: a
# v2 result must never be reinterpreted as delegated-route evidence.
AS_DELEGATED_OVERLAY_FILE = os.environ.get(
    "ANDYUR_AS_DELEGATED_OVERLAY_FILE", "").strip()
AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE = os.environ.get(
    "ANDYUR_AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE", "").strip()
AS_TENANT = os.environ.get("ANDYUR_AS_TENANT", "").strip()
AS_CLIENT_AUTH_METHOD = os.environ.get(
    "ANDYUR_AS_CLIENT_AUTH_METHOD", "").strip()
AS_POLICY_CONFIG = os.environ.get("ANDYUR_AS_POLICY_CONFIG", "")
try:
    AS_CERTIFICATION_GENERATION = int(os.environ.get(
        "ANDYUR_AS_CERTIFICATION_GENERATION", "0"))
except ValueError:
    AS_CERTIFICATION_GENERATION = 0


def as_problems() -> list[str]:
    """What is missing or contradictory about the external-AS configuration.

    Empty when the AS is not configured at all, which is the supported default.
    """
    from .server import ascertification, asproviders

    provider_problems = asproviders.validate(AS_PROVIDER, AS_CAPABILITY)
    if not AS_TOKEN_ENDPOINT:
        # Nothing else may be set in isolation: a deployment that names an issuer
        # and no endpoint has been half-migrated, and silently minting locally is
        # exactly the "works but wrong" this is meant to prevent.
        # PROVIDER and CAPABILITY carry non-empty defaults ("reference"/"core"),
        # so a truthiness test would never flag them; they are stray when
        # EXPLICITLY set (the _SET flags). The rest default to empty/"" and read
        # by value. Without PROVIDER here, `ANDYUR_AS_PROVIDER=keycloak` alone
        # booted a prod deployment clean -- the very half-migrated shape the
        # message below says is refused.
        stray = [n for n, v in (("ANDYUR_AS_ISSUER", AS_ISSUER),
                                ("ANDYUR_AS_CLIENT_ID", AS_CLIENT_ID),
                                ("ANDYUR_AS_CLIENT_SECRET", AS_CLIENT_SECRET),
                                ("ANDYUR_AS_JWKS", AS_JWKS_URL),
                                ("ANDYUR_AS_PROVIDER", AS_PROVIDER_SET),
                                ("ANDYUR_AS_CAPABILITY", AS_CAPABILITY_SET),
                                ("ANDYUR_AS_PRODUCT_VERSION", AS_PRODUCT_VERSION),
                                ("ANDYUR_AS_RESOURCE_SCOPE", AS_RESOURCE_SCOPE),
                                ("ANDYUR_AS_CERTIFICATION_FILE",
                                 AS_CERTIFICATION_FILE),
                                ("ANDYUR_AS_CERTIFICATION_PUBLIC_KEY_FILE",
                                 AS_CERTIFICATION_PUBLIC_KEY_FILE),
                                ("ANDYUR_AS_DELEGATED_OVERLAY_FILE",
                                 AS_DELEGATED_OVERLAY_FILE),
                                ("ANDYUR_AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE",
                                 AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE),
                                ("ANDYUR_AS_TENANT", AS_TENANT),
                                ("ANDYUR_AS_CLIENT_AUTH_METHOD",
                                 AS_CLIENT_AUTH_METHOD),
                                ("ANDYUR_AS_POLICY_CONFIG", AS_POLICY_CONFIG),
                                ("ANDYUR_AS_CERTIFICATION_GENERATION",
                                 AS_CERTIFICATION_GENERATION)) if v]
        if stray:
            return provider_problems + [f"{', '.join(stray)} set without ANDYUR_AS_TOKEN_ENDPOINT: "
                    "Andyur would keep signing its own access tokens while the "
                    "configuration says otherwise"]
        return provider_problems
    problems = list(provider_problems)
    if PROD and not AS_PROVIDER_SET:
        problems.append(
            "ANDYUR_AS_PROVIDER is required in production; refusing to guess a "
            "vendor protocol from its token endpoint")
    if PROD and not AS_CAPABILITY_SET:
        problems.append(
            "ANDYUR_AS_CAPABILITY is required in production; name the guarantee "
            "this tenant was configured to provide")
    if PROD and AS_PROVIDER != "reference" and not AS_PRODUCT_VERSION:
        problems.append(
            "ANDYUR_AS_PRODUCT_VERSION is required in production so live "
            "certification names the tested product release (use 'managed' "
            "for a rolling SaaS tenant)")
    if PROD and AS_PROVIDER == "reference":
        # The reference AS is a test fixture: env-seeded plaintext users signed
        # with a public example keypair, so anyone can mint tokens it would
        # accept. Requiring "some external AS" is not enough when the fixture
        # itself qualifies -- name the vendor instead.
        problems.append(
            "ANDYUR_AS_PROVIDER=reference is refused in production: the "
            "reference AS is a test fixture (plaintext user store, published "
            "example signing key); configure a real vendor provider")
    if AS_PROVIDER == "entra" and not AS_RESOURCE_SCOPE:
        problems.append(
            "ANDYUR_AS_RESOURCE_SCOPE is required for Entra; it must contain "
            "the closed action-to-request-to-claim scope map")
    elif AS_PROVIDER == "entra":
        try:
            asproviders._entra_scope_map(AS_RESOURCE_SCOPE)
        except asproviders.ProviderConfigurationError as exc:
            problems.append(str(exc))
    if AS_PROVIDER in {"keycloak", "entra", "okta", "auth0",
                       "pingfederate", "pingam"} \
            and not AS_CLIENT_SECRET:
        problems.append(
            f"ANDYUR_AS_CLIENT_SECRET is required for {AS_PROVIDER} by the "
            "currently implemented client-auth profile")
    if not AS_ISSUER:
        problems.append(
            "ANDYUR_AS_ISSUER is required with ANDYUR_AS_TOKEN_ENDPOINT: a "
            "resource server must match `iss` exactly, and an unset issuer "
            "makes that check unconditional on configuration being present")
    if not AS_CLIENT_ID:
        problems.append(
            "ANDYUR_AS_CLIENT_ID is required: the exchange is an authenticated "
            "client call, not an anonymous one")
    if not AS_JWKS_URL:
        problems.append(
            "ANDYUR_AS_JWKS is required: Andyur verifies every issued access "
            "token before releasing it to the resource sidecar")
    if PROD and not AS_TOKEN_ENDPOINT.startswith("https://"):
        problems.append(
            f"ANDYUR_AS_TOKEN_ENDPOINT is {AS_TOKEN_ENDPOINT.split(':')[0]}, not "
            "https: the user's access token and the run's SVID both cross this "
            "leg, and a bearer credential in clear is a credential given away")
    if PROD and AS_JWKS_URL and not AS_JWKS_URL.startswith("https://"):
        problems.append(
            f"ANDYUR_AS_JWKS is {AS_JWKS_URL.split(':')[0]}, not https: an "
            "attacker who substitutes the signing key can mint accepted tokens")
    delegated_settings = (
        AS_DELEGATED_OVERLAY_FILE, AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE,
        AS_TENANT, AS_CLIENT_AUTH_METHOD, AS_POLICY_CONFIG,
        AS_CERTIFICATION_GENERATION,
    )
    if PROD and AS_PROVIDER != "reference" and AS_CAPABILITY == "core":
        if any(delegated_settings):
            problems.append(
                "delegated-overlay settings are present while "
                "ANDYUR_AS_CAPABILITY=core; refusing a silent capability downgrade")
        problems.extend(ascertification.problems(
            AS_CERTIFICATION_FILE, provider=AS_PROVIDER,
            capability=AS_CAPABILITY, issuer=AS_ISSUER,
            token_endpoint=AS_TOKEN_ENDPOINT, jwks_url=AS_JWKS_URL,
            client_id=AS_CLIENT_ID, product_version=AS_PRODUCT_VERSION,
            public_key_file=AS_CERTIFICATION_PUBLIC_KEY_FILE,
            scope_config=AS_RESOURCE_SCOPE))
    elif PROD and AS_PROVIDER != "reference":
        # The signed overlay is necessary but intentionally not sufficient:
        # asproviders.validate above independently rejects any adapter whose
        # real wire cannot carry the selected capability. No provider name or
        # signed document promotes an adapter by itself.
        if AS_CERTIFICATION_FILE or AS_CERTIFICATION_PUBLIC_KEY_FILE:
            problems.append(
                "legacy v2 core certification settings must be unset for a "
                "non-core capability; they cannot authorize delegated routing")
        for variable, value in (
                ("ANDYUR_AS_DELEGATED_OVERLAY_FILE", AS_DELEGATED_OVERLAY_FILE),
                ("ANDYUR_AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE",
                 AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE),
                ("ANDYUR_AS_TENANT", AS_TENANT),
                ("ANDYUR_AS_CLIENT_AUTH_METHOD", AS_CLIENT_AUTH_METHOD),
                ("ANDYUR_AS_POLICY_CONFIG", AS_POLICY_CONFIG),
        ):
            if not value:
                problems.append(f"{variable} is required for non-core authorization")
        if type(AS_CERTIFICATION_GENERATION) is not int \
                or AS_CERTIFICATION_GENERATION <= 0:
            problems.append(
                "ANDYUR_AS_CERTIFICATION_GENERATION must be a positive sealed "
                "generation for non-core authorization")
        if AS_CAPABILITY != "delegated":
            problems.append(
                "the current signed overlay qualifies only "
                "ANDYUR_AS_CAPABILITY=delegated; contextual requires its own "
                "closed matrix and overlay")
        try:
            adapter_client_auth = asproviders.client_auth_method(AS_PROVIDER)
        except asproviders.ProviderConfigurationError:
            adapter_client_auth = ""
        if AS_CLIENT_AUTH_METHOD != adapter_client_auth:
            problems.append(
                "ANDYUR_AS_CLIENT_AUTH_METHOD does not match the selected "
                f"adapter's wire method {adapter_client_auth!r}")
        problems.extend(ascertification.overlay_problems(
            AS_DELEGATED_OVERLAY_FILE, provider=AS_PROVIDER, tenant=AS_TENANT,
            issuer=AS_ISSUER, token_endpoint=AS_TOKEN_ENDPOINT,
            jwks_url=AS_JWKS_URL, client_id=AS_CLIENT_ID,
            client_auth_method=adapter_client_auth,
            policy_config=AS_POLICY_CONFIG, product_version=AS_PRODUCT_VERSION,
            public_key_file=AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE,
            certification_generation=AS_CERTIFICATION_GENERATION))
    return problems
# Clamped the way RUN_TOKEN_TTL above is, rather than raising: config is imported
# by every tool and test in the tree, so an import-time raise turns a bad number
# into a process that cannot start at all, including the one you would use to fix
# it. Clamped LOUDLY, because silently honouring something other than what the
# operator asked for is its own failure.
#
# The floor exists because this value is not only the token's lifetime. The egress
# credential broker caches on the `expires_in` derived from it, so it is also the
# mint rate. Measured at expires_in=5: three tool calls drove twelve exchanges,
# an amplification rather than a saving, against an endpoint sharing a process
# with the worker heartbeat. 30s is still a useful revocation lever.
_EXCHANGE_TTL_FLOOR = 30
_exchange_ttl_asked = int(os.environ.get("ANDYUR_EXCHANGE_TTL", "300"))
EXCHANGE_TTL = max(_exchange_ttl_asked, _EXCHANGE_TTL_FLOOR)
if EXCHANGE_TTL != _exchange_ttl_asked:
    logging.getLogger(__name__).warning(
        "ANDYUR_EXCHANGE_TTL=%s is below the %ss floor and has been raised to it. "
        "That value is the token lifetime AND the credential broker's cache "
        "window, so it would not shorten the revocation window, it would make "
        "every tool call mint afresh.", _exchange_ttl_asked, _EXCHANGE_TTL_FLOOR)

# Model broker (R2): a local proxy that HOLDS the provider API key and injects it
# on the way to the upstream model API, so the agent subprocess runs with no key in
# its environment and a prompt-injected agent cannot exfiltrate it. When
# ANDYUR_BROKER_URL is set, api-mode runs route model calls through it and the key
# is scrubbed from the agent. The broker process itself holds ANTHROPIC_API_KEY.
BROKER_URL = os.environ.get("ANDYUR_BROKER_URL", "")
BROKER_UPSTREAM = os.environ.get("ANDYUR_BROKER_UPSTREAM", "https://api.anthropic.com")
LITELLM_URL = os.environ.get("ANDYUR_LITELLM_URL", "")
# Bind address. A sandboxed agent reaches the broker via the Docker host gateway
# (host.docker.internal), which does NOT resolve to the host's loopback, so under
# sandbox the broker must listen on all interfaces. Off sandbox we keep loopback.
# SECURITY: the broker forwards with the provider key, so on a shared or
# untrusted network its port should still be firewalled to the host. It DOES
# authenticate its callers now (broker._authenticate: a purpose-bound run token,
# required in the production profile); this comment used to say it had no auth
# at all, which was true when written and false for some time after.
_SANDBOX_ON = SANDBOX
BROKER_HOST = os.environ.get(
    "ANDYUR_BROKER_HOST", "0.0.0.0" if _SANDBOX_ON else "127.0.0.1"
)
BROKER_PORT = int(os.environ.get("ANDYUR_BROKER_PORT", "8643"))

# --- Container split --------------------------------------------------------
# How a headless run is executed. Three shapes, increasing in isolation:
#
#   off      ONE process. The runner holds the run token, bridges the platform
#            tools in-process, and spawns the agent CLI itself. The CLI is
#            dropped to its own uid, so the uid split is the boundary.
#   process  TWO processes in ONE container (split Phase 1). A sidecar holds the
#            run token and serves the tools over loopback HTTP + the model proxy;
#            a credential-less agent process drives the SDK and forwards its
#            message stream back. The sidecar spawns the agent process.
#   pod      TWO CONTAINERS (split Phase 2). The daemon launches both: a sidecar
#            container holding every credential, and an agent container holding
#            nothing, joined to the sidecar's network namespace so the loopback
#            channel still works. The container boundary replaces the uid split
#            FOR THE HEADLESS AGENT, which runs unprivileged in its own
#            container. The sidecar keeps SETUID, because conversational runs
#            and graph capture still spawn the CLI inside it.
#
# Conversational runs stay in-process in every mode (their turn-loop lifecycle is
# a later phase). See docs/container-split-plan.md.
_SPLIT_ALIASES = {"off": "off", "0": "off", "false": "off", "": "off",
                  "on": "process", "1": "process", "true": "process",
                  "process": "process", "pod": "pod"}
_SPLIT_RAW = os.environ.get("ANDYUR_AGENT_SPLIT", "off").strip().lower()
AGENT_SPLIT_MODE = _SPLIT_ALIASES.get(_SPLIT_RAW)
if AGENT_SPLIT_MODE is None:
    # Refuse to guess, for the same reason ANDYUR_PROFILE does: an unrecognised
    # value here silently selects the LEAST isolated shape, which is the one an
    # operator setting this variable was trying to move away from.
    raise RuntimeError(
        f"ANDYUR_AGENT_SPLIT='{os.environ.get('ANDYUR_AGENT_SPLIT')}' is not a "
        f"split mode. Use one of: {', '.join(sorted(set(_SPLIT_ALIASES.values())))}."
    )
AGENT_SPLIT = AGENT_SPLIT_MODE != "off"
AGENT_SPLIT_POD = AGENT_SPLIT_MODE == "pod"

# Tool egress is the per-run sidecar (andyur/proxy), full stop. The transitional
# per-run agentgateway broker and the ANDYUR_TOOL_EGRESS switch that selected it
# were deleted once the sidecar passed every live gate (ADR-003). The variable is
# still READ, only to refuse it loudly: a deployment that set it to `agentgateway`
# is pinned to a topology that no longer exists, and silently ignoring the setting
# would run a shape its operator did not choose -- the exact failure the switch's
# refuse-to-guess rule existed to prevent.
_egress = os.environ.get("ANDYUR_TOOL_EGRESS")
if _egress is not None and _egress.strip().lower() not in ("", "sidecar"):
    raise RuntimeError(
        f"ANDYUR_TOOL_EGRESS={_egress!r} is no longer a setting: the per-run "
        "agentgateway tool path was removed (ADR-003) and the per-run sidecar is "
        "the only tool egress. Unset ANDYUR_TOOL_EGRESS."
    )

# Seccomp filter on run containers (see daemon/seccomp.py for what it does and,
# more importantly, what it does not).
#
#   off      no filter of ours; the container runtime's default applies, which
#            on some hosts -- Docker Desktop being one -- is `unconfined`
#   auto     apply the role's profile to every run container (the default: it
#            costs nothing and needs no host support beyond seccomp itself)
#   require  as auto, and prod refuses to start without it
#
# Three values rather than a boolean so an operator who has a reason to run
# without a filter can say so deliberately and see it named in the refusal,
# instead of reaching for ANDYUR_SANDBOX=off, which gives up far more.
_SECCOMP_ALIASES = {"off": "off", "0": "off", "false": "off",
                    "auto": "auto", "on": "auto", "1": "auto", "true": "auto",
                    "": "auto",
                    "require": "require", "required": "require"}
_SECCOMP_RAW = os.environ.get("ANDYUR_SECCOMP", "auto").strip().lower()
SECCOMP_MODE = _SECCOMP_ALIASES.get(_SECCOMP_RAW)
if SECCOMP_MODE is None:
    # Same reason ANDYUR_PROFILE and ANDYUR_AGENT_SPLIT refuse to guess: an
    # unrecognised value would otherwise select the least protected branch,
    # which is the opposite of what someone setting this variable intended.
    raise RuntimeError(
        f"ANDYUR_SECCOMP='{os.environ.get('ANDYUR_SECCOMP')}' is not a seccomp "
        f"mode. Use one of: {', '.join(sorted(set(_SECCOMP_ALIASES.values())))}."
    )
# Whether a per-run token guards the loopback tool service and the A<->B channel.
# Default ON: cheap defense-in-depth for a shared network namespace (it defends
# the ports from other processes, never from the agent).
AGENT_SPLIT_TOKENS = os.environ.get(
    "ANDYUR_AGENT_SPLIT_TOKENS", "on").lower() in ("1", "on", "true")
# The A<->B channel port. In `process` mode the channel takes an ephemeral port
# and hands the URL to the agent process directly. In `pod` mode it must be FIXED
# and known in advance, because the daemon -- not the sidecar -- launches the
# agent container and has to tell it where to connect before the sidecar is up.
# Safe as a constant: each pod has its own network namespace, so two runs on one
# host never contend for it.
CHANNEL_PORT = int(os.environ.get("ANDYUR_CHANNEL_PORT", "8765"))
# How long the sidecar waits for the agent container to open its stream before
# failing the run closed. Covers an agent image that cannot start at all, which
# would otherwise hold the run until the TTL.
AGENT_CONNECT_TIMEOUT = float(os.environ.get("ANDYUR_AGENT_CONNECT_TIMEOUT", "120"))

SERVER_HOST = os.environ.get("ANDYUR_HOST", "127.0.0.1")
SERVER_PORT = int(os.environ.get("ANDYUR_PORT", "8642"))
# mTLS flips the control-plane scheme to https; clients present their SVID.
_SCHEME = "https" if os.environ.get("ANDYUR_MTLS", "off").lower() in ("1", "on", "true") else "http"
SERVER_URL = os.environ.get("ANDYUR_SERVER_URL", f"{_SCHEME}://{SERVER_HOST}:{SERVER_PORT}")

# --- Conversational agents (interactive run mode) --------------------------
# A conversation is one long-lived run (one identity, one container) that stays
# open across many turns with a human present, instead of the default one-shot
# headless run. Every headless security property is preserved; the session just
# lives longer, so it is bounded on every axis below to keep it safe and cheap.
#
# CONVERSATION_IDLE_SECONDS: no new turn from the human within this window closes
#   the session (so an abandoned chat cannot pin a slot + subprocess forever).
CONVERSATION_IDLE_SECONDS = int(os.environ.get("ANDYUR_CONVERSATION_IDLE_SECONDS", "300"))
# CONVERSATION_MAX_SECONDS: hard wall-clock cap on a whole session, regardless of
#   activity. The conversation run token is minted to expire with this, so the
#   session can never outlive its own credential (no token refresh, no escalation
#   surface). Bounded to a sane ceiling.
CONVERSATION_MAX_SECONDS = min(
    int(os.environ.get("ANDYUR_CONVERSATION_MAX_SECONDS", "3600")), 6 * 3600
)
# CONVERSATION_TURN_TTL_SECONDS: one turn's response must complete within this, so
#   a single turn cannot hang the session (the halt/idle checks run between turns).
CONVERSATION_TURN_TTL_SECONDS = int(
    os.environ.get("ANDYUR_CONVERSATION_TURN_TTL_SECONDS", "300")
)
# CONVERSATION_MAX_TURNS: total turns a session will accept before it closes.
CONVERSATION_MAX_TURNS = int(os.environ.get("ANDYUR_CONVERSATION_MAX_TURNS", "200"))
# CONVERSATION_MAX_TURN_BYTES: a single human turn body is rejected (413) above
#   this, so one turn cannot blow the context or the store.
CONVERSATION_MAX_TURN_BYTES = int(
    os.environ.get("ANDYUR_CONVERSATION_MAX_TURN_BYTES", "16384")
)
# OUTPUT_RETENTION_MAX_BYTES: the platform-side ceiling on how much of a stock
#   exec/v1 workload's captured output is stored in the run record, applied ON
#   TOP of the manifest's process.output.max_bytes. The EFFECTIVE bound is the
#   smaller of the two (execlifecycle.capture_output), so a manifest can ask for
#   less but never more than the platform will retain. Output is diagnostic (D3):
#   nothing authorizes on it, so this is a storage bound, not a security one.
OUTPUT_RETENTION_MAX_BYTES = int(
    os.environ.get("ANDYUR_OUTPUT_RETENTION_MAX_BYTES", str(1 << 20))
)
# MAX_CONVERSATIONS: concurrent conversation cap across the whole platform, so
#   interactive sessions cannot starve headless work of every worker slot.
MAX_CONVERSATIONS = int(os.environ.get("ANDYUR_MAX_CONVERSATIONS", "8"))
# MAX_CONVERSATIONS_PER_USER: concurrent conversations one tenant may hold (enforced
#   only under user-auth), so one user cannot occupy every global slot.
MAX_CONVERSATIONS_PER_USER = int(os.environ.get("ANDYUR_MAX_CONVERSATIONS_PER_USER", "3"))
# CONVERSATION_MAX_EVENT_BACKLOG: cap on UNREAD reply events buffered for an
#   operator who has stopped reading (measured against the operator's read cursor);
#   beyond it new turns are refused and the idle timer closes the session.
CONVERSATION_MAX_EVENT_BACKLOG = int(
    os.environ.get("ANDYUR_CONVERSATION_MAX_EVENT_BACKLOG", "2000")
)
# CONVERSATION_MAX_EVENT_BYTES: a single reply event body is truncated above this
#   at the storage boundary, so the untrusted session side cannot store one giant
#   event (belt-and-suspenders; one turn's total output is already bounded by the
#   per-turn TTL and the turn cap).
CONVERSATION_MAX_EVENT_BYTES = int(
    os.environ.get("ANDYUR_CONVERSATION_MAX_EVENT_BYTES", "65536")
)

# Every thread-hosted uvicorn server in the runner (execfront, toolservice,
# toolsidecar, modelproxy, agentchannel) drains for at most this long on stop:
# an open MCP stream or a stalled POST must not hold a Pod's teardown (R MED-3
# on PR #25). ONE constant, so the bound cannot drift between servers.
THREAD_SERVER_GRACEFUL_SHUTDOWN_SECONDS = 1
