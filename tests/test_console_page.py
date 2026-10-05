"""The console page's own behaviour, run under node from the pytest suite.

`andyur/console/static/app.js` had no executable coverage at all, and every one
of the ten page defects this lane found was a bug in TIME or STATE -- a timer
that rearmed twice per tick, a catch-up that became the steady interval, a
cursor two callers read at once. A static check cannot see any of them, and the
live browser gate needs Chrome, a control plane and SPIRE, so it does not run in
CI. tests/console_page_checks.mjs runs the real app.js under a virtual clock and
a stubbed control plane; this puts it in the suite CI actually runs.

node is a TEST dependency for this file (see .github/workflows/ci.yml). It is
not a runtime dependency: the console ships one hand-written script with no
build step and no package.json, which is why the page is served exactly as it
is written.

This test deliberately does NOT skip when node is missing. A skipped test
reports the same green as a passing one, and the whole point of this file is
that the page's behaviour stopped being unverified.
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

from andyur.console import server
from andyur.server import app as app_module

CHECKS = Path(__file__).parent / "console_page_checks.mjs"
# Every check the runner defines. Asserted exactly, not as a floor: see below.
EXPECTED_CHECKS = 64


def test_the_console_page_behaves_under_a_virtual_clock():
    node = shutil.which("node")
    assert node, (
        "node is required to run the console page checks "
        f"({CHECKS.name}). Install Node 18+ (CI installs it via actions/setup-node)."
    )
    # The BFF's own header name is fed in, so the page is asserted against the
    # constant the server checks rather than against a copy in the test.
    # The flow node's REAL key set, from the projection the route uses, so the
    # page is checked against what the server returns and not against a copy.
    node_keys = sorted(set(app_module._RUN_LIST_COLUMNS)
                       - set(app_module._RUN_LIST_OMIT)
                       | {"trace_id", "interface_version", "elided", "index",
                          "exchanges", "exchanges_omitted"})
    env = {**os.environ, "ANDYUR_SESSION_HEADER": server.SESSION_HEADER,
           "ANDYUR_FLOW_NODE_KEYS": ",".join(node_keys)}
    proc = subprocess.run([node, str(CHECKS)], capture_output=True, text=True,
                          cwd=CHECKS.parent.parent, timeout=120, env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # THE EXACT COUNT, not a floor. A floor of 12 against 36 real checks meant
    # the runner could be truncated after check 5 -- losing every XSS check and
    # every flow-truncation check -- and still report green. The count is
    # asserted from the runner's own summary line so adding a check is a
    # one-line update and REMOVING one is a failure.
    summary = re.search(r"(\d+)/(\d+) page checks passed", proc.stdout)
    assert summary, proc.stdout[-2000:]
    passed, total = int(summary.group(1)), int(summary.group(2))
    assert passed == total, proc.stdout[-2000:]
    assert total == EXPECTED_CHECKS, (
        f"the page runner has {total} checks and this test expects "
        f"{EXPECTED_CHECKS}. If you ADDED one, update EXPECTED_CHECKS. If one "
        f"vanished, that is the failure this assertion exists for."
    )
    assert proc.stdout.count("PASS") == total, proc.stdout
