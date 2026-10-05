"""The bounded read itself, exercised rather than stubbed.

`read_text_bounded` and the two backends behind it are the actual fix for a
route that read 1001 MiB of agent-written files to return 0.13 MiB. The only
other test on that path monkeypatches `read_text_bounded` away with a spy, so
it asserts the route ASKS for a bound and never that anything HONOURS one --
making the backends read the whole file and return it unsliced survived the
suite, and the S3 backend had never been executed at all.

Every assertion here is on BYTES, and the fixtures are multi-byte on purpose: a
bound that is really in characters is indistinguishable from a correct one when
the fixture is ASCII.
"""
import io
import os
import tracemalloc

import pytest

from andyur import storage, workspace


# 4 bytes in UTF-8, so a limit that is really a character count overshoots 4x.
WIDE = "\U0001F600"


@pytest.fixture
def local(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(storage, "IS_S3", False)
    return storage.LocalBackend()


def test_a_bounded_read_returns_at_most_its_limit_in_bytes(local, tmp_path):
    (tmp_path / "big.txt").write_text(WIDE * 10_000, encoding="utf-8")
    text, more, _n = local.get_bounded("big.txt", 100)
    assert len(text.encode("utf-8")) <= 100
    assert more is True                      # and it SAYS there was more
    # positive control: a file inside the limit comes back whole and says so
    (tmp_path / "small.txt").write_text("hello", encoding="utf-8")
    assert local.get_bounded("small.txt", 100) == ("hello", False, 5)


def test_a_bounded_read_does_not_load_the_whole_file(local, tmp_path):
    """The point of the bound: the bytes past it are never in memory.

    Asserted on ALLOCATION, not on elapsed time and not on file size. A first
    attempt used a 64 GiB sparse file on the theory that reading it whole was
    impossible; macOS read all 64 GiB of zeros in 11.6 s without raising, so
    the test passed either way -- a test that cannot fail, in the file written
    to fix tests that cannot fail. tracemalloc states the property directly:
    reading 512 bytes must allocate ~512 bytes, whatever the file's size.
    """
    size = 256 * 1024 * 1024
    path = tmp_path / "sparse.txt"
    with io.open(path, "wb") as fh:
        fh.truncate(size)                          # sparse: no blocks allocated
    assert path.stat().st_size == size

    tracemalloc.start()
    text, more, _n = local.get_bounded("sparse.txt", 512)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert len(text.encode("utf-8")) <= 512 and more is True
    # generous by three orders of magnitude and still nowhere near the file
    assert peak < 1024 * 1024, f"read 512 bytes and allocated {peak} for a {size}-byte file"


def test_a_cut_inside_a_multibyte_character_does_not_raise(local, tmp_path):
    # The bound is on bytes, so it lands mid-character routinely. A backend
    # that decodes strictly turns a large transcript into a 500.
    (tmp_path / "emoji.txt").write_text(WIDE * 100, encoding="utf-8")
    for limit in range(1, 12):
        text, more, _n = local.get_bounded("emoji.txt", limit)
        assert len(text.encode("utf-8")) <= limit and more is True


def test_a_missing_object_is_None_not_an_empty_read(local):
    assert local.get_bounded("nope.txt", 100) is None


def test_the_workspace_helper_goes_through_the_backend(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(storage, "IS_S3", False)
    monkeypatch.setattr(storage, "_backend", None, raising=False)
    workspace.write_text("agent-x", "transcript.jsonl", WIDE * 5000)
    read = workspace.read_text_bounded("agent-x", "transcript.jsonl", 64)
    assert read is not None
    text, more, _n = read
    assert len(text.encode("utf-8")) <= 64 and more is True
    assert workspace.read_text_bounded("agent-x", "absent.jsonl", 64) is None


def test_the_s3_backend_asks_s3_for_a_range_and_never_reads_the_rest():
    """S3 must not fetch-then-slice: the bytes have to not cross the network.

    A fake client records the request and answers it, so this executes the real
    code path -- which had never run once.
    """
    body = (WIDE * 10_000).encode("utf-8")
    calls = []
    reads = []

    class _Body:
        def __init__(self, data):
            self._data = data
            self._at = 0

        def read(self, size=None):
            # RECORDED. A body read with no size hands the whole object to the
            # caller, and `raw[:limit]` afterwards bounds the RESULT, not the
            # allocation -- which is the entire finding.
            reads.append(size)
            out = self._data[self._at:] if size is None else self._data[self._at:self._at + size]
            self._at += len(out)
            return out

    class _S3:
        def get_object(self, Bucket, Key, **kw):        # noqa: N803 (boto3 spelling)
            calls.append(kw.get("Range"))
            if "Range" not in kw:
                raise AssertionError("the S3 backend fetched the whole object")
            start, end = kw["Range"].removeprefix("bytes=").split("-")
            return {"Body": _Body(body[int(start):int(end) + 1]),
                    "ResponseMetadata": {"HTTPStatusCode": 206}}     # honoured

    backend = storage.S3Backend.__new__(storage.S3Backend)
    backend._s3 = _S3()
    text, more, _n = backend.get_bounded("k", 100)
    assert calls == ["bytes=0-100"]
    assert reads and all(sz is not None and sz <= 101 for sz in reads), reads
    assert len(text.encode("utf-8")) <= 100 and more is True


def test_a_fifo_is_not_read_at_all(local, tmp_path):
    # A FIFO exists() and opening one BLOCKS until a writer appears, with no
    # timeout on this path -- and the caller reads N objects per request inside
    # a threadpool of about forty slots. The workspace is a host directory.
    os.mkfifo(tmp_path / "pipe")
    assert local.get_bounded("pipe", 100) is None       # returns, and returns None
    # positive control: a real file at the same limit still reads
    (tmp_path / "real.txt").write_text("ok", encoding="utf-8")
    assert local.get_bounded("real.txt", 100) == ("ok", False, 2)


def test_an_s3_endpoint_that_ignores_range_is_still_bounded():
    """S3 honours Range; an S3-COMPATIBLE endpoint is not S3.

    One that ignores the header answers 200 with the whole object rather than
    206 with the slice. Asking for a bound is not having one.
    """
    # THE BODY IS SMALLER THAN THE LIMIT, deliberately. With a body larger than
    # the limit, `len(raw) > limit` is already true and the status-code clause
    # is dead -- the fixture decides the test instead of the subject, and
    # deleting the clause survives. Here only the 200 can say "there was more".
    body = b"short"

    class _Body:
        def __init__(self, data):
            self._data = data
            self._at = 0

        def read(self, size=None):
            out = self._data[self._at:] if size is None else self._data[self._at:self._at + size]
            self._at += len(out)
            return out

    class _IgnoresRange:
        def get_object(self, Bucket, Key, **kw):            # noqa: N803
            return {"Body": _Body(body),
                    "ResponseMetadata": {"HTTPStatusCode": 200}}   # not 206

    backend = storage.S3Backend.__new__(storage.S3Backend)
    backend._s3 = _IgnoresRange()
    text, more, _n = backend.get_bounded("k", 100)
    assert len(text.encode("utf-8")) <= 100
    assert more is True, "a 200 answer to a Range request was read as complete"

    # POSITIVE CONTROL: the same short body from an endpoint that DID honour
    # the range (206) is complete, so `more` above is the status code and not
    # a constant.
    class _Honours(_IgnoresRange):
        def get_object(self, Bucket, Key, **kw):            # noqa: N803
            return {"Body": _Body(body),
                    "ResponseMetadata": {"HTTPStatusCode": 206}}

    backend._s3 = _Honours()
    assert backend.get_bounded("k", 100) == ("short", False, 5)


def test_content_that_decodes_to_nothing_still_reports_what_it_cost(local, tmp_path):
    """A caller charging a byte budget must charge what it READ.

    `b"\xff"` is not valid UTF-8 and decodes under errors="ignore" to the empty
    string. A backend that reported only the decoded text let a caller charge
    zero for a full read and keep going: 104,857,600 raw bytes against an 8 MiB
    budget, with the response reporting that nothing had been truncated.
    """
    (tmp_path / "junk.bin").write_bytes(b"\xff" * 10_000)
    text, more, raw = local.get_bounded("junk.bin", 1000)
    assert text == ""                      # nothing survives the decode
    assert more is True
    assert raw == 1000                     # ...and it still cost a full read


def test_the_unbounded_read_refuses_a_fifo_too(local, tmp_path):
    """`get` is what the transcript and exchanges routes use.

    The previous round put the FIFO guard on `get_bounded` and not on `get` --
    the fix applied where the finding was found rather than where the property
    is. Fifty concurrent reads of FIFO-backed transcripts took every request
    thread on the control plane and it stayed dead until a writer appeared.
    """
    os.mkfifo(tmp_path / "pipe2")
    assert local.get("pipe2") is None
    # positive control: a real file at the same key shape still reads
    (tmp_path / "ok.txt").write_text("fine", encoding="utf-8")
    assert local.get("ok.txt") == "fine"


def test_neither_read_path_opens_a_directory_or_a_dangling_symlink(local, tmp_path):
    (tmp_path / "adir").mkdir()
    (tmp_path / "dangling").symlink_to(tmp_path / "nowhere")
    for key in ("adir", "dangling"):
        assert local.get(key) is None
        assert local.get_bounded(key, 100) is None
