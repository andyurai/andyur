# Security policy

Andyur is security infrastructure; reports about its own security are taken
seriously and handled with priority.

## Reporting a vulnerability

Email **security@andyur.ai**. Do not open a public issue for anything you
believe is exploitable.

Include what you can: affected component (server, daemon, runner, sidecar,
registrar, CLI), a reproduction or proof of concept, the configuration it
applies to (identity on/off, sandbox on/off, deployment mode), and the impact
you believe it has. Reports that distinguish the shipped default configuration
from an opt-in one are especially useful.

You will receive an acknowledgment within 7 days. Please allow a reasonable
disclosure window before publishing; we will credit reporters in the fix
notes unless you ask otherwise.

## Supported versions

Andyur is pre-release. Only the current main branch receives security fixes.
A supported-versions table will replace this section at the first tagged
release.

## Verifying a release

Release artifacts are signed with the project's cosign key. The public half is
[`docs/release-signing-key.pub`](docs/release-signing-key.pub) in this
repository and is also served from <https://andyur.ai/cosign.pub>. The two are
published separately on purpose: a key that lives only beside the artifacts it
verifies can be replaced along with them. Check that both copies are the same
file before trusting either:

```bash
curl -fsSL https://andyur.ai/cosign.pub | shasum -a 256
shasum -a 256 docs/release-signing-key.pub
# both: 2d13df6ee88d2e9712512ba2aca09c20a9897d9352ec29a8448299443b9b1958
```

Each artifact ships with a `<name>.cosign-bundle.json` beside it. To verify one:

```bash
cosign verify-blob --key docs/release-signing-key.pub \
  --bundle release-manifest.json.cosign-bundle.json \
  --insecure-ignore-tlog=true release-manifest.json
```

Verify `release-manifest.json` first. It names the commit the release was built
from and the digest of every other artifact.

What this does and does not prove:

- It proves the artifact was signed by whoever holds the private half of that
  key. It does not prove when: the signatures are not recorded in a public
  transparency log, which is why `--insecure-ignore-tlog=true` is needed. That
  flag skips the log lookup and nothing else; the key check is unchanged.
- The key is held by one maintainer. If it is ever replaced, the new public key
  and the reason are announced in `CHANGELOG.md` and at the URL above, and
  releases signed with the old key are listed there as trusted or not.
- A package installed with `pip install andyur` is not checked against this key
  by pip. The wheel and sdist attached to the GitHub release carry bundles;
  verify those if you need the signature.

## Scope notes

- The untrusted agent container is assumed hostile by design. Reports that
  an agent can act maliciously *within* its granted authority are expected
  behavior; reports that an agent can EXCEED its granted authority (escape
  the sandbox, widen scope, mint or replay credentials, reach an unapproved
  destination) are exactly what this policy is for.
- Vulnerabilities in composed third-party components (SPIRE, Keycloak, OPA,
  model providers) should go to those projects; how Andyur *integrates* them
  is in scope here.
