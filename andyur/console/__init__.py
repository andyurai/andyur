"""Local operator console: a BFF that serves the UI and proxies the control
plane with the operator identity. See `server.py` for the trust model and the
multi-tenant seam."""
from __future__ import annotations

import socket
import webbrowser

from . import server

# HTTP omits a default port from Origin and Host, so the fences' exact
# comparison against "127.0.0.1:<port>" cannot hold there.
_DEFAULT_PORTS = (80, 443)


def _bind(port: int | None) -> tuple[socket.socket, int]:
    """Bind and listen on the console's loopback socket and return it with the
    port it holds. The socket is handed to uvicorn as-is, so the port printed
    in the launch URL is the one actually listening: there is no
    bind/close/rebind window in which another process could take it. It
    listens now because the URL is printed and the browser opened before
    uvicorn starts, and a bound-but-not-listening socket refuses connections
    instead of queueing them. Port None asks the OS for a free one, so two
    consoles never clash and nothing sits on a predictable port a drive-by
    page could guess."""
    if port in _DEFAULT_PORTS:
        raise SystemExit(f"console cannot use port {port}: browsers omit a "
                         f"default port from Origin and Host. Pick another --port.")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # A fixed --port must come back right after Ctrl-C, not after TIME_WAIT.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port or 0))
    except OSError as exc:
        sock.close()
        # The commonest first-run failure with --port is another console (or
        # a dev control plane) already on it; name the port, not errno.
        where = f"127.0.0.1:{port}" if port else "a loopback port"
        raise SystemExit(
            f"console cannot listen on {where}: {exc.strerror}. "
            f"Pick another --port, or omit it for a free one.") from exc
    # uvicorn re-listens on this socket with its own backlog (2048); the
    # number here only matters until it does.
    sock.listen(128)
    return sock, sock.getsockname()[1]


def launch(*, open_browser: bool = True, port: int | None = None) -> None:
    """Start the console.

    TRUST BOUNDARY. Once running, the localhost listener is gated by a
    per-session secret that the page obtains exactly once by exchanging the
    single-use launch token printed on the operator's own terminal. A
    same-machine process that reads that terminal or argv gets a token that
    the first page load has already spent -- a marginal increase over the CLI,
    where any local process running the operator role binary already IS the
    operator.

    Under ANDYUR_USER_AUTH the console additionally signs a HUMAN in (RFC 8252
    PKCE, at launch, before anything is served) and carries that user's token
    on every proxied call, so the control plane scopes to the user and the IdP
    role decides admin. The session secret still gates the browser leg;
    per-request browser SSO (a login page served by the BFF itself) is the next
    step and is tracked in ROADMAP.md gap 11, not built here."""
    import uvicorn

    from .. import authlogin, config, otel

    # Tracing, metrics and the JSON log envelope for this process; on by
    # default, off with ANDYUR_OTEL=off. The console is its own service.
    tracer = otel.setup_tracing(server.SERVICE)
    # Hold the port BEFORE the (up to two minute) login: a port taken during
    # the login window would otherwise throw the completed login away.
    sock, port = _bind(port)
    user_session = None
    if config.USER_AUTH:
        # The console acts as a LOGGED-IN USER; sign in before serving. Same
        # RFC 8252 flow as `andyur auth login`, against the user IdP; the tokens
        # live only in this process (see server.UserSession).
        if not config.OIDC_ISSUER:
            raise SystemExit(
                "ANDYUR_USER_AUTH is on but ANDYUR_OIDC_ISSUER is not set; the "
                "console cannot sign a user in without knowing their IdP")
        if not open_browser:
            # On a headless host the RFC 8252 callback listens on THIS machine's
            # loopback, so a laptop browser cannot reach it: forward the port
            # (ssh -L 8765:127.0.0.1:8765) before opening the printed URL.
            print("--no-browser: open the URL below on a browser that can reach "
                  "this host's loopback (e.g. via `ssh -L 8765:127.0.0.1:8765`)",
                  flush=True)
        try:
            with tracer.start_as_current_span("console.login") as span:
                span.set_attribute("andyur.console.outcome", "failed")
                tokens = authlogin.login(config.OIDC_ISSUER,
                                         audience=config.OIDC_AUDIENCE,
                                         open_browser=open_browser,
                                         client_id=config.CONSOLE_CLIENT_ID,
                                         # Shorter than the CLI's 300s: if the
                                         # IdP has no such client it shows a
                                         # browser error and never redirects,
                                         # and a 5-minute hang before a generic
                                         # timeout is a bad first run.
                                         timeout=120.0)
                span.set_attribute("andyur.console.outcome", "signed_in")
        except Exception as exc:                               # noqa: BLE001
            # Lead with what happened. The registration hint is for the
            # commonest cause of a non-timeout failure (the adopter has not
            # registered this client, ANDYUR_CONSOLE_CLIENT_ID, in their IdP);
            # a slow operator who timed out must not be told to check that.
            hint = ("" if "timed out" in str(exc).lower() or "no callback" in str(exc).lower()
                    else f" Is client {config.CONSOLE_CLIENT_ID!r} registered "
                         f"with a loopback redirect URI (ANDYUR_CONSOLE_CLIENT_ID)?")
            raise SystemExit(
                f"console login failed at the IdP ({config.OIDC_ISSUER}): {exc}.{hint}")
        # The refresh flow must use the SAME client the code was exchanged under.
        user_session = server.UserSession(
            tokens, token_endpoint=tokens["token_endpoint"],
            client_id=config.CONSOLE_CLIENT_ID)
        print("signed in; the console acts as this user (the server decides "
              "admin from the IdP role)", flush=True)

    origin = f"http://127.0.0.1:{port}"
    launch_token = server.new_launch_token()
    app = server.build_app(server.new_session_secret(), origin=origin,
                           launch=launch_token, user_session=user_session)
    # The URL carries the single-use token, never the secret. The page spends
    # it at POST /session on first load and scrubs it from the address bar.
    url = f"{origin}/?launch={launch_token.value}"
    # flush: the server blocks right after, and buffered stdout would leave the
    # operator staring at a blank terminal without the URL they need to open.
    print(f"andyur console -> {url}", flush=True)
    print("  operator-attested BFF; localhost only; single-use launch link",
          flush=True)
    print("  Ctrl-C to stop", flush=True)
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:                                      # noqa: BLE001
            pass
    try:
        # A bounded graceful shutdown: one in-flight proxied call must not hold
        # Ctrl-C for the whole upstream deadline.
        uvicorn.Server(uvicorn.Config(app, log_level="warning",
                                      timeout_graceful_shutdown=5)
                       ).run(sockets=[sock])
    except KeyboardInterrupt:
        # uvicorn re-raises the SIGINT it handled after a clean shutdown (the
        # lifespan has already closed the clients); `uvicorn.run` swallows it
        # the same way, `Server.run` does not.
        pass
