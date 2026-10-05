"""Secret redaction, shared by the runner (before content leaves the process)
and the server (a storage-boundary backstop, so redaction is a property of the
boundary and not merely runner convention).

Covers the platform's OWN structural secrets (provider key, run token, JWT-SVID,
bearer headers, sensitive env assignments) AND the common third-party credential
shapes a conversational agent may be handed by a human and asked to echo. It is
pattern matching, so it is a rate, not a boundary: the property that bounds a
compromise is the scoped run token + isolation. Redaction is the safety net under
that, kept broad but conservative (only high-signal shapes) to avoid mangling
normal text.
"""

import re

_SECRET_RE = re.compile(
    # --- the platform's own secrets ---
    r"sk-ant-[A-Za-z0-9_-]{6,}"                                          # Anthropic key
    r"|sk-[A-Za-z0-9]{20,}"                                              # OpenAI-style
    r"|eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]{4,})?"  # JWT / run token
    r"|Bearer\s+[A-Za-z0-9._~+/=-]{20,}"                                 # bearer header (long, so normal "Bearer <word>" chat is not mangled)
    # --- common third-party credentials a human might paste ---
    r"|gh[pousr]_[A-Za-z0-9]{20,}"                                       # GitHub token
    r"|github_pat_[A-Za-z0-9_]{20,}"                                     # GitHub fine-grained PAT
    r"|glpat-[A-Za-z0-9_-]{15,}"                                         # GitLab PAT
    r"|AKIA[0-9A-Z]{12,}|ASIA[0-9A-Z]{12,}"                              # AWS access key id
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"                                     # Slack token
    r"|AIza[0-9A-Za-z_-]{20,}"                                           # Google API key
    r"|-----BEGIN[ A-Z]*PRIVATE KEY-----"                               # PEM private key header
    r"|[A-Za-z][A-Za-z0-9+.-]{0,31}://[^\s:@/]+:[^\s:@/]+@"              # URL-inline user:pass@ (scheme bounded so a long non-URL run stays linear, not O(n^2))
    # --- sensitive env assignments (name=value) ---
    r"|(?:ANTHROPIC_API_KEY|ANDYUR_RUN_TOKEN|ANDYUR_RUN_TOKEN_SECRET|"
    r"AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY)=\S+"
)


# --- token-SHAPED runs the prefix patterns above do not know ---
# The run's own bearer is a bare token_urlsafe(32) (43 chars), keys come as
# sk-proj-/sk-or-/hex/AWS-secret shapes: 40+ characters of a base64url/hex
# alphabet carrying both letters and digits is not a word (R MED-1 on PR #25,
# found first on span attributes, then on the log envelope -- ONE scrubber
# here serves both). Below 40 the platform's own identifiers live (32-hex run
# ids, 36-char UUIDs) and stay readable; a `sha256:` digest is a public fact
# and is exempt by its prefix.
# `=`, `/` and `+` are deliberately OUTSIDE the alphabet, because each of them
# GLUES otherwise-readable things into one long "token": `=` joins `key=value`
# pairs (and swallowed a 36-char UUID after `id=`), and `/` joins URL path
# segments -- `8642/runs/<32-hex run id>/worker-finish` is 56 characters of
# letters and digits, and scrubbing it hid the run id the live gates grep the
# worker log for (seen in the cluster, 2026-08-26). The platform's own mints
# are `secrets.token_urlsafe` (base64URL: `-` and `_` only), so nothing of
# ours escapes; a third-party base64 secret carrying `/` is still caught by
# its `KEY=value` form or its vendor prefix in _SECRET_RE.
#
# RESIDUAL, stated rather than implied (R, PR #25): a BARE third-party secret
# that contains `/` or `+`, appears with no `KEY=` and no vendor prefix, and is
# split by those characters into runs shorter than 40 -- a canonical AWS secret
# access key is the example -- is NOT scrubbed. Shape matching is a rate, not a
# boundary; what bounds a compromise is the scoped run token and isolation. The
# platform's own credentials cannot be split that way (every mint is base64URL),
# and the free-text attribute that made this reachable from a workload (the
# front's raw request path) no longer exists.
_TOKEN_SHAPED = re.compile(
    r"(?<!sha256:)(?<![A-Za-z0-9_\-])"
    r"(?=[A-Za-z0-9_\-]{40,}(?![A-Za-z0-9_\-]))"
    r"(?=[A-Za-z0-9_\-]*[0-9])(?=[A-Za-z0-9_\-]*[A-Za-z])"
    r"[A-Za-z0-9_\-]{40,}")


def redact(s: str | None) -> str:
    """Replace any secret-shaped substring with a placeholder. None -> ''."""
    if not s:
        return "" if s is None else s
    return _TOKEN_SHAPED.sub("<redacted>", _SECRET_RE.sub("<redacted>", s))
