"""Storage backend for the agent mind.

The mind (profile, knowledge, instructions, memory, run artifacts) is a set of
text objects keyed by path, e.g. `agents/scout/memory/short_term.md`. Two
backends behind one interface, chosen by ANDYUR_STORAGE:

- **local** (default): files under WORKSPACE_DIR. Zero setup.
- **s3**: objects in an S3-compatible bucket (S3, MinIO, R2, GCS). Every node
  shares the mind with no shared filesystem; the server is the only component
  that touches it, so runners never need storage credentials.

Only the server imports this. Runners read and write the mind over the server's
HTTP API, which is what keeps a sandboxed runner container mount-free.
"""

import shutil

from .config import (
    S3_ACCESS_KEY, S3_BUCKET, S3_ENDPOINT, S3_REGION, S3_SECRET_KEY,
    STORAGE, WORKSPACE_DIR,
)

IS_S3 = STORAGE == "s3"


# NOTHING IN THE WORKSPACE IS OPENED WITHOUT PASSING THIS.
#
# `Path.exists()` is true for a FIFO, and `open()` on a FIFO BLOCKS until a
# writer appears, with no timeout on any read path here. The workspace is a
# host directory and a run may create files under its own prefix, so this is
# reachable: fifty concurrent reads of FIFO-backed transcripts took every
# request thread, and the process stayed dead until the attacker chose to
# release it.
#
# The guard lives in ONE function used by BOTH readers rather than in each of
# them. The previous round put it in `get_bounded` and not in `get` -- the fix
# applied where the finding was found instead of where the property is -- and
# `get` is what the transcript and exchanges routes use.
def _readable_file(key: str):
    """The path for `key` if it is a regular file this process may read, else
    None. A directory, a FIFO, a device or a dangling symlink is not one."""
    path = WORKSPACE_DIR / key
    try:
        if not path.is_file():
            return None
    except OSError:
        return None
    return path


class LocalBackend:
    def get(self, key: str) -> str | None:
        path = _readable_file(key)
        return path.read_text(errors="ignore") if path else None

    def get_bounded(self, key: str, limit: int) -> tuple[str, bool, int] | None:
        """At most `limit` bytes of an object, whether there was more, and HOW
        MANY RAW BYTES were read.

        A run may write its own files, so an object's size is agent-controlled.
        A caller that reads N objects in one request (the workflow graph reads
        every visible run's transcript) cannot bound its own allocation by
        slicing what `get` returned: the whole file is in memory by then.
        Reading is where the bound belongs.

        The RAW count is returned because a caller charging a byte budget has
        to charge what it READ, not what it decoded. `b"\xff" * 8 MiB` decodes
        under errors="ignore" to the empty string, so a caller charging the
        decoded length is charged nothing for eight megabytes and keeps going:
        measured 12.5x over budget, while the response reported that nothing
        had been truncated.

        Truncation is on BYTES and the tail is decoded leniently, because a cut
        at `limit` can land inside a multi-byte character.
        """
        path = _readable_file(key)
        if path is None:
            return None
        with path.open("rb") as fh:
            raw = fh.read(limit + 1)
        more = len(raw) > limit
        kept = raw[:limit]
        return kept.decode("utf-8", "ignore"), more, len(kept)

    def put(self, key: str, text: str) -> None:
        path = WORKSPACE_DIR / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def exists(self, key: str) -> bool:
        return (WORKSPACE_DIR / key).exists()

    def list_prefix(self, prefix: str) -> list[str]:
        base = WORKSPACE_DIR / prefix
        if not base.exists():
            return []
        return [
            str(p.relative_to(WORKSPACE_DIR)) for p in base.rglob("*") if p.is_file()
        ]

    def delete_prefix(self, prefix: str) -> int:
        """Remove everything under `prefix`. Returns the number of files removed.

        The resolved path is required to stay UNDER the workspace root before
        anything is unlinked. `prefix` reaches here from an agent name, and a name
        that escaped validation must not be able to turn a delete into `rm -rf` on
        an arbitrary directory. Callers already validate; this is the layer that
        would actually do the damage, so it checks too."""
        base = (WORKSPACE_DIR / prefix).resolve()
        root = WORKSPACE_DIR.resolve()
        if base == root or root not in base.parents:
            raise ValueError(f"refusing to delete '{prefix}': outside the workspace")
        if not base.exists():
            return 0
        removed = sum(1 for p in base.rglob("*") if p.is_file())
        shutil.rmtree(base)
        return removed


class S3Backend:
    """S3-compatible object storage. Bucket versioning is enabled on init, so
    every overwrite retains the prior version as a durable backstop under the
    application-level version history."""

    def __init__(self) -> None:
        import boto3

        self._s3 = boto3.client(
            "s3",
            endpoint_url=S3_ENDPOINT,
            aws_access_key_id=S3_ACCESS_KEY,
            aws_secret_access_key=S3_SECRET_KEY,
            region_name=S3_REGION,
        )
        self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        from botocore.exceptions import ClientError

        try:
            self._s3.head_bucket(Bucket=S3_BUCKET)
        except ClientError:
            self._s3.create_bucket(Bucket=S3_BUCKET)
        # retain prior versions of every object as a durable backstop
        self._s3.put_bucket_versioning(
            Bucket=S3_BUCKET, VersioningConfiguration={"Status": "Enabled"}
        )

    def get(self, key: str) -> str | None:
        from botocore.exceptions import ClientError

        try:
            resp = self._s3.get_object(Bucket=S3_BUCKET, Key=key)
        except ClientError:
            return None
        return resp["Body"].read().decode("utf-8")

    def get_bounded(self, key: str, limit: int) -> tuple[str, bool] | None:
        """At most `limit` bytes, asked of S3 with a Range header so the bytes
        past it are never transferred, let alone held. See LocalBackend."""
        from botocore.exceptions import ClientError

        try:
            resp = self._s3.get_object(Bucket=S3_BUCKET, Key=key,
                                       Range=f"bytes=0-{limit}")
        except ClientError:
            return None
        # An endpoint that IGNORES Range answers 200 with the whole object
        # instead of 206 with the slice, so the read is bounded here as well:
        # `Body.read()` takes a size, and taking one is the difference between
        # a bound and a request for a bound. S3 itself honours it; an
        # S3-compatible endpoint is not S3.
        raw = resp["Body"].read(limit + 1)
        more = len(raw) > limit or resp.get("ResponseMetadata", {}).get(
            "HTTPStatusCode") == 200
        kept = raw[:limit]
        return kept.decode("utf-8", "ignore"), more, len(kept)

    def put(self, key: str, text: str) -> None:
        self._s3.put_object(Bucket=S3_BUCKET, Key=key, Body=text.encode("utf-8"))

    def exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self._s3.head_object(Bucket=S3_BUCKET, Key=key)
            return True
        except ClientError:
            return False

    def list_prefix(self, prefix: str) -> list[str]:
        keys, token = [], None
        while True:
            kw = {"Bucket": S3_BUCKET, "Prefix": prefix}
            if token:
                kw["ContinuationToken"] = token
            resp = self._s3.list_objects_v2(**kw)
            keys += [o["Key"] for o in resp.get("Contents", [])]
            if not resp.get("IsTruncated"):
                return keys
            token = resp["NextContinuationToken"]

    def delete_prefix(self, prefix: str) -> int:
        """Remove every object under `prefix`. Returns how many were removed.

        Bucket VERSIONING is on (see _ensure_bucket), so delete_objects writes a
        delete marker and the prior versions remain. That is deliberate and worth
        knowing: on S3 this is a logical delete, recoverable by an operator, not a
        shredder. The local backend really does unlink."""
        if not prefix or prefix in ("/", "agents/"):
            raise ValueError(f"refusing to delete '{prefix}': too broad")
        keys = self.list_prefix(prefix)
        for i in range(0, len(keys), 1000):   # delete_objects caps at 1000 per call
            self._s3.delete_objects(
                Bucket=S3_BUCKET,
                Delete={"Objects": [{"Key": k} for k in keys[i:i + 1000]]},
            )
        return len(keys)


_backend = None


def backend():
    global _backend
    if _backend is None:
        _backend = S3Backend() if IS_S3 else LocalBackend()
    return _backend
