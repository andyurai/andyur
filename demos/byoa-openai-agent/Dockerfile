# An OpenAI Agents SDK BYOA agent image. It installs the OpenAI Agents SDK and
# NOT andyur -- the dependency tree is the proof. Base pinned by digest
# (python:3.12-slim, 2026-08-15), matching governed-mode immutable identity.
FROM python@sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

USER 65534:65534
COPY agent.py /app/agent.py

# ANDYUR_RUNTIME_URL / ANDYUR_RUNTIME_TOKEN are injected by the platform.
ENTRYPOINT ["python", "/app/agent.py"]
