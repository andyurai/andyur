# ADR-005: OpenBao credential custody

Status: accepted foundation; credential-exchange service remains in progress.

## Decision

Andyur uses OpenBao as its open-source credential store and cryptographic
service, OpenTofu for encrypted provisioning state/plans, and workload identity
instead of durable vault tokens. OpenBao is a trusted control-plane dependency;
the untrusted agent never receives network access or credentials for it.

Development starts with the digest-pinned OpenBao 2.6.1 stack under
`infra/openbao`. It uses TLS 1.3, encrypted integrated Raft storage, a loopback-
only port declaration on an internal Docker network, non-raw audit records,
read-only filesystem, dropped capabilities, and four non-overlapping policies.
Initialization requires an explicit private recovery directory and creates three
Shamir shares with a threshold of two. No share or root token is written to the
repository, Compose environment, command arguments, or logs.

Production must replace the single development node with three failure-domain-
separated nodes, protected auto-unseal or separately held Shamir shares, two
durable audit sinks, encrypted off-cluster snapshots, tested recovery, and
short-lived SPIFFE/Kubernetes-authenticated access. Development initialization
is not evidence that these production properties exist.

## Security-review mapping

The 13 August architecture review recommends a small trusted credential service
at target-flow step 6 and flags plaintext bearer persistence in F-08. OpenBao
closes the backing-store/custody portion: versioned secret storage, ACLs, audit,
and non-exportable certification signing. It does not itself close F-06. A
separate narrow credential-exchange service must use mature provider clients,
derive authority from verified server state, and return credentials only to the
trusted Envoy path. Envoy continues to own TLS, upstream verification, pooling,
HTTP behavior, retries, and stream lifecycle.

## Development operation

```sh
./run.sh openbao up
ANDYUR_OPENBAO_RECOVERY_DIR=/absolute/private/empty-dir ./run.sh openbao init
./run.sh openbao unseal
./run.sh openbao configure
./run.sh openbao status
```

Distribute unseal shares to separate custodians before treating the instance as
anything beyond local development. `configure` accepts the bootstrap root token
only through a hidden terminal prompt and an stdin pipe. It enables KV v2,
Transit with a non-exportable Ed25519 certification key, and the provisioner,
certifier, runtime-AS, and model-broker policies. It does not mint reusable
application tokens.

`destroy-dev` requires the literal confirmation flag printed by the command and
deletes only the named development data volume. It never deletes the external
recovery directory.

AS provisioning now requires OpenTofu plus an external mode-0600 encryption
configuration that enforces both state and saved-plan encryption. The checked-in
example uses the separately rotating `tofu-state` Transit key and contains no
token. `BAO_TOKEN` must be a short-lived provisioner lease. Provisioning status
lists resource addresses rather than serializing secret outputs.

The credential-service OpenBao client accepts only HTTPS origins, a private
bounded workload-JWT file, a maximum 15-minute login lease, and closed provider,
environment, and credential-kind vocabularies. Its token remains in memory and
is revoked on close. Production test-user retrieval and arbitrary vault paths
are structurally impossible through this API. This is custody plumbing, not yet
the complete exchange endpoint or mature OAuth-client replacement.

After an approved apply, `as-provision store` captures only the two required
OpenTofu outputs in memory and performs a KV v2 create-only (`cas=0`) write to
the exact development provider path. It never prints the client secret and a
rerun cannot silently replace a credential already used by certification.

## Brokered non-delegating SaaS mode

Registry tools now select exactly one authority mode: `managed` for delegated
exchange, `brokered` for an operator-approved OpenBao service credential, or
`passthrough` for no Andyur credential. A brokered tool must declare a closed
lowercase `credential_ref`; the control plane returns it only to the run-
authenticated trusted runner. Managed and passthrough tools are forbidden from
declaring fallback references.

The per-run sidecar authenticates to OpenBao using its private workload token,
reads only `secret/data/production/saas/<credential_ref>`, and accepts a secret
of the shape `{headers: {name: value, ...}}` -- one to eight entries, each with
a valid field-name and a bounded CR/LF-free value.

WHICH names are permitted is NOT decided here, and that is the point. The vault
holds transport material; whether THIS binding may set THIS header is authority
data, declared as `ToolBinding.credential_headers` and enforced at the sidecar
against the binding's own declared set. A returned header the binding never
declared withholds the whole call.

This replaced a hardcoded `{Authorization, X-Api-Key}` pair, which could not
express a vendor authenticating with two headers -- Datadog needs `DD-API-KEY`
and `DD-APPLICATION-KEY` together -- and which stated a platform constant where
a fact about a reviewed binding belonged. Every DECLARED name is stripped from
the agent's request before the trusted values are injected, whether or not the
vault returned that one: a credential replaces, and never appends to something
the agent supplied. The upstream URL
and method remain registry-fixed, and the run's scope, audience ceiling, pin,
call budget, concurrency limit, mTLS identity, and trace attribution remain in
force. Vault failures withhold the call; they never fall back to delegation or a
credential-free request. Values remain in sidecar memory for at most 60 seconds,
the OpenBao lease is at most 15 minutes and revoked at teardown.

An operator must configure OpenBao's JWT auth mount before brokered runs, binding
the role named by `ANDYUR_OPENBAO_RUNTIME_ROLE` to the exact projected
Kubernetes service-account subject/audience or SPIRE JWT-SVID subject/audience.
The runtime also requires `ANDYUR_OPENBAO_ADDR`, a private CA file, and a private
workload JWT file. Static OpenBao tokens are not an accepted runtime substitute.

## Rejected alternatives

- HashiCorp Vault 1.15+ is BSL rather than OSI-open-source. It remains a viable
  supported substitution when its license and commercial model are accepted.
- SOPS and Sealed Secrets encrypt Git artifacts but do not provide leases,
  runtime revocation, workload authentication, or access auditing.
- Synchronizing into ordinary Kubernetes Secrets creates durable plaintext
  copies in the cluster trust domain. CSI/tmpfs file delivery is preferred.
- OpenBao dev mode has an in-memory root token and deliberately weak lifecycle;
  it is prohibited even for this repository's repeatable live gate.
