# Provenance of `seccomp_base.json`

`seccomp_base.json` is **not our work**. It is the default seccomp profile from
the Moby project, vendored unmodified.

| | |
|---|---|
| Source | https://github.com/moby/moby/blob/v27.3.1/profiles/seccomp/default.json |
| Version | v27.3.1 |
| Retrieved | 6 August 2026 |
| License | Apache License 2.0 (Moby / Docker Inc. and contributors) |
| sha256 | run `shasum -a 256 seccomp_base.json` to compare against the upstream release asset |

## Why it is vendored rather than referenced

`docker run --security-opt seccomp=<file>` **replaces** the runtime's default
profile. There is no mechanism to extend it. So to end up with "the default,
minus a few syscalls", we must ship the default and subtract from it.

Writing our own allowlist instead was the alternative, and it is worse in a way
that is easy to miss: this profile carries argument-level rules that a
name-level allowlist cannot express, notably the `clone` namespace-flag mask
and the `ENOSYS` answer for `clone3` that glibc needs in order to fall back to
`clone`. A hand-written profile would be narrower in syscall names while being
weaker in arguments, which is a net regression on exactly the surface the
filter exists to reduce.

`andyur/daemon/seccomp.py` only ever removes names from this file's allow
groups; it never adds rules. `tests/test_seccomp.py` asserts both of the
argument-level rules above still survive, so an accidental flattening of this
file fails the suite rather than quietly weakening every run.

## Updating it

Replace the file with a newer upstream release, update the table above, and run
`./run.sh test` plus `./run.sh seccomp-verify`. The tests check the properties
we depend on (deny-by-default, the `clone`/`clone3` rules), not the file's
byte content, so a legitimate upstream change should pass.
