# The reference BYOA agent image: one stdlib-only script on a digest-pinned
# base. Nothing is installed -- an empty dependency tree is the proof that
# `andyur-agent-runtime/v1` needs no Andyur package and no SDK.
#
# The base is pinned by digest, not tag, because this repository's governed
# mode admits only immutable image identity and the reference image holds
# itself to the same standard. (python:3.12-slim as of 2026-08-15.)
FROM python@sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65

# An arbitrary unprivileged uid, set in the image so the agent never runs as
# root even when the launcher forgets --user. The conformance gate ALSO
# passes --user explicitly; defense in depth is cheap here.
USER 65534:65534

COPY agent.py /app/agent.py

# The two ANDYUR_RUNTIME_* environment variables are injected by the
# platform at launch; nothing else is expected or read.
ENTRYPOINT ["python", "/app/agent.py"]
