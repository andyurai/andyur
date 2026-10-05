"""The X509-SVID private key on disk, and who else can open it.

WHY THIS FILE EXISTS. `identity.export_tls_pems` writes the workload's private
key to a file because there is no other way to hand it to uvicorn
(--ssl-keyfile) or to httpx (SSLContext.load_cert_chain) -- both take PATHS.
Under the uid split the runner and the UNTRUSTED agent share one filesystem, so
the mode on that file is the only thing between the agent and the credential
that authenticates the workload to the control plane. It shipped at 0644 in a
0755 directory.

WHAT THESE TESTS DO NOT CLAIM. They do not claim the 0644 was reachable in a
real run: it was not (see the report -- ANDYUR_MTLS is never forwarded into a
run container, and container root there cannot even create /app/data). They
assert the file-permission property directly, which is worth asserting on its
own terms, because the day someone forwards ANDYUR_MTLS into a run container is
the day the mode becomes the boundary.

Only the SPIRE Workload API is faked here. The code under test -- the makedirs,
the chmod, the os.open, the write -- is the shipped function, exercised end to
end against a real key and real files.
"""

import datetime
import os
import stat

import pytest

pytest.importorskip("spiffe", reason="py-spiffe is a runtime dependency")

from cryptography import x509                                    # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec          # noqa: E402
from cryptography.x509.oid import NameOID                         # noqa: E402

from andyur import identity                                       # noqa: E402


def _self_signed():
    """A real EC key and a real certificate, so export_tls_pems serialises
    genuine key material rather than a Mock's repr. The point of the test is
    what lands on disk, so what lands on disk has to be the real shape."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "andyur-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    return key, cert


@pytest.fixture
def export(tmp_path, monkeypatch):
    """Point export_tls_pems at a throwaway data dir and stub ONLY the Workload
    API source. Returns a callable that performs one real export."""
    key, cert = _self_signed()

    class _Svid:
        cert_chain = [cert]
        private_key = key

    class _Ctx:
        default_svid = _Svid()

    class _Bundle:
        x509_authorities = [cert]

    class _Source:
        def __init__(self, *a, **kw):
            pass

        def get_x509_context(self):
            return _Ctx()

        def get_bundle_for_trust_domain(self, _td):
            return _Bundle()

        def close(self):
            pass

    import spiffe

    # export_tls_pems does `from spiffe import X509Source` INSIDE the function,
    # so patching the attribute on the module is what the import resolves to.
    monkeypatch.setattr(spiffe, "X509Source", _Source)
    monkeypatch.setenv("ANDYUR_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(identity, "_project_data", lambda: str(tmp_path))

    def _run(role="runner"):
        return identity.export_tls_pems(role)

    return _run


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_the_private_key_is_not_readable_by_anyone_else(export):
    """0600. The group and other bits are the whole assertion: an agent at a
    different uid, sharing this filesystem, must get EACCES on open()."""
    pems = export()
    mode = _mode(pems["key"])
    assert mode == 0o600, f"key.pem is {oct(mode)}, not 0600"
    assert not (mode & 0o077), f"key.pem grants {oct(mode & 0o077)} to group/other"


def test_the_key_directory_blocks_traversal(export):
    """0700 on the directory, so the agent cannot even reach the key to try.
    Defense in depth with the file mode above, and the half that survives a
    future file being added to this directory without the same care."""
    pems = export()
    d = os.path.dirname(pems["key"])
    mode = _mode(d)
    assert mode == 0o700, f"{d} is {oct(mode)}, not 0700"


def test_the_key_is_never_world_readable_even_mid_write(export, tmp_path):
    """THE RACE, asserted rather than assumed.

    A `chmod` after the write is not equivalent: the file exists at 0644 for the
    whole duration of the write, and an agent polling the path wins without
    having to win anything. This observes the mode AT THE MOMENT THE FIRST BYTE
    IS WRITTEN by wrapping os.fdopen -- the last point before content lands --
    and requires it to already be 0600.

    Not an absence-of-evidence check: the observation list must be non-empty, or
    a refactor that stopped writing the key at all would pass silently."""
    observed = []
    real_fdopen = os.fdopen

    def spy(fd, *a, **kw):
        handle = real_fdopen(fd, *a, **kw)
        try:
            observed.append(stat.S_IMODE(os.fstat(fd).st_mode))
        except OSError:
            pass
        return handle

    os.fdopen = spy
    try:
        pems = export()
    finally:
        os.fdopen = real_fdopen

    assert observed, "no fd was opened through os.fdopen: the key write path changed"
    assert all(m == 0o600 for m in observed), (
        f"the key fd was {[oct(m) for m in observed]} before its content was written"
    )
    assert _mode(pems["key"]) == 0o600


def test_a_pre_existing_world_readable_key_is_repaired(export, tmp_path):
    """O_CREAT's mode is IGNORED for a file that already exists, and this
    function re-runs on every export. A key.pem left at 0644 by an older build
    would otherwise keep 0644 forever and receive the new secret. Recreate that
    exact state -- a 0644 file in a 0755 directory -- and require the export to
    fix both."""
    d = tmp_path / "tls" / "runner"
    d.mkdir(parents=True)
    stale = d / "key.pem"
    stale.write_bytes(b"stale")
    os.chmod(stale, 0o644)
    os.chmod(d, 0o755)
    assert _mode(stale) == 0o644 and _mode(d) == 0o755   # the state we are fixing

    pems = export()

    assert _mode(pems["key"]) == 0o600, "an existing 0644 key.pem kept its mode"
    assert _mode(d) == 0o700, "an existing 0755 key directory kept its mode"


def test_the_public_material_is_still_written_and_usable(export):
    """Do not break the callers. client_tls loads these three paths into an
    SSLContext, so the export must still produce a cert chain and a bundle that
    actually parse, and a key that pairs with the cert -- a 'secure' export that
    broke mTLS would be a worse outcome than the 0644."""
    import ssl

    pems = export()
    for name in ("cert", "key", "bundle"):
        assert os.path.exists(pems[name]), f"{name} was not written"

    # The real consumer path: the same two calls client_tls makes. If the key is
    # unreadable to its OWN owner, or does not match the cert, this raises.
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=pems["bundle"])
    ctx.check_hostname = False
    ctx.load_cert_chain(certfile=pems["cert"], keyfile=pems["key"])

    # ...and the bytes really are a private key, not an empty file with a mode.
    body = open(pems["key"], "rb").read()
    assert b"PRIVATE KEY" in body
    serialization.load_pem_private_key(body, password=None)
