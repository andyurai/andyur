"""Conversational agents: the persistent interactive run mode.

Every headless security property must still hold, and the session is additionally
bounded on every axis. These tests drive the real FastAPI app + coordinator, and
target the threat model directly:

  - the two auth surfaces stay separate (operator drives; the run pulls/replies)
  - a run token confines the session to ITS run (no cross-run turn/reply access)
  - turns are exactly-once and FIFO (the agent cannot replay or reorder)
  - a terminal/closed session rejects new turns (no resurrection)
  - every bound (size, backlog, count, wall-clock via the reaper) is enforced
"""

import pytest
from fastapi.testclient import TestClient

from andyur import config, db
from andyur.server import app as app_module
from andyur.server import conversation, coordinator, runtoken
from andyur.server import heartbeat

client = TestClient(app_module.app)


def rtok(agent, run_id, wf):
    return {"X-Andyur-Run-Token": runtoken.mint(agent, run_id, wf)}


def _conv_run(env, agent):
    """Create an agent and wake a CONVERSATION run for it (pending)."""
    env.agent(agent)
    run = coordinator.maybe_wakeup(agent, "conversation", run_type="conversation")
    wf = env.run_workflow(run)
    return run, wf


@pytest.fixture
def conv(env):
    run, wf = _conv_run(env, "alice")
    return {"agent": "alice", "run": run, "wf": wf}


# -- functional: the turn/event rendezvous -----------------------------------

def test_conversation_run_is_created_and_counted(conv):
    assert env_state(conv["run"]) == "pending"
    assert conversation.count_active() == 1


def test_operator_enqueues_and_session_claims_fifo(conv):
    # operator (no token = operator under trust-local) speaks two turns
    assert client.post(f"/runs/{conv['run']}/turn", json={"body": "first"}).status_code == 201
    assert client.post(f"/runs/{conv['run']}/turn", json={"body": "second"}).status_code == 201
    # the session (run token) claims them in order
    h = rtok("alice", conv["run"], conv["wf"])
    t1 = client.get(f"/runs/{conv['run']}/next-turn", headers=h).json()["turn"]
    t2 = client.get(f"/runs/{conv['run']}/next-turn", headers=h).json()["turn"]
    assert t1["body"] == "first" and t2["body"] == "second"
    # queue now empty
    assert client.get(f"/runs/{conv['run']}/next-turn", headers=h).json()["turn"] is None


def test_a_turn_is_delivered_exactly_once(conv):
    client.post(f"/runs/{conv['run']}/turn", json={"body": "only once"})
    # two racing claims: first wins the CAS, second sees an empty queue
    seq1 = conversation.claim_next_turn(conv["run"])
    seq2 = conversation.claim_next_turn(conv["run"])
    assert seq1 is not None and seq1["body"] == "only once"
    assert seq2 is None


def test_session_replies_and_operator_reads_in_order(conv):
    h = rtok("alice", conv["run"], conv["wf"])
    client.post(f"/runs/{conv['run']}/reply", json={"kind": "chunk", "body": "hel"}, headers=h)
    client.post(f"/runs/{conv['run']}/reply", json={"kind": "chunk", "body": "lo"}, headers=h)
    client.post(f"/runs/{conv['run']}/reply", json={"kind": "turn_end"}, headers=h)
    evs = client.get(f"/runs/{conv['run']}/events", params={"after": 0}).json()["events"]
    assert [e["kind"] for e in evs] == ["chunk", "chunk", "turn_end"]
    assert "".join(e["body"] for e in evs if e["kind"] == "chunk") == "hello"
    # cursor advances: reading after the last seq returns nothing new
    last = evs[-1]["seq"]
    assert client.get(f"/runs/{conv['run']}/events", params={"after": last}).json()["events"] == []


def test_close_enqueues_a_close_sentinel(conv):
    assert client.post(f"/runs/{conv['run']}/close").status_code == 200
    h = rtok("alice", conv["run"], conv["wf"])
    turn = client.get(f"/runs/{conv['run']}/next-turn", headers=h).json()["turn"]
    assert turn["kind"] == "close"


# -- security: cross-run isolation (the strongest property) ------------------

def test_run_token_cannot_pull_another_runs_turns(env):
    a_run, a_wf = _conv_run(env, "alice")
    b_run, b_wf = _conv_run(env, "bob")
    # bob's session presents bob's token but targets alice's run
    r = client.get(f"/runs/{a_run}/next-turn", headers=rtok("bob", b_run, b_wf))
    assert r.status_code == 403


def test_run_token_cannot_reply_into_another_run(env):
    a_run, a_wf = _conv_run(env, "alice")
    b_run, b_wf = _conv_run(env, "bob")
    r = client.post(f"/runs/{a_run}/reply", json={"kind": "chunk", "body": "x"},
                    headers=rtok("bob", b_run, b_wf))
    assert r.status_code == 403


def test_turn_endpoint_rejects_a_non_conversation_run(env):
    env.agent("carol")
    work = coordinator.maybe_wakeup("carol", "work")  # a headless run
    r = client.post(f"/runs/{work}/turn", json={"body": "hi"})
    assert r.status_code == 404  # not a conversation -> no turn surface


# -- bounds: size, backlog, count, terminal, reply-kind ----------------------

def test_oversized_turn_is_refused(conv, monkeypatch):
    monkeypatch.setattr(config, "CONVERSATION_MAX_TURN_BYTES", 8)
    r = client.post(f"/runs/{conv['run']}/turn", json={"body": "way too long a message"})
    assert r.status_code == 413


def test_backlog_cap_refuses_new_turns(conv, monkeypatch):
    monkeypatch.setattr(config, "CONVERSATION_MAX_EVENT_BACKLOG", 2)
    h = rtok("alice", conv["run"], conv["wf"])
    for _ in range(3):
        client.post(f"/runs/{conv['run']}/reply", json={"kind": "chunk", "body": "x"}, headers=h)
    r = client.post(f"/runs/{conv['run']}/turn", json={"body": "hi"})
    assert r.status_code == 429


def test_terminal_run_rejects_turns(conv):
    coordinator.start_run(conv["run"])
    coordinator.finish_run(conv["run"], "done", None)
    r = client.post(f"/runs/{conv['run']}/turn", json={"body": "resurrect?"})
    assert r.status_code == 409


def test_unknown_reply_kind_is_rejected(conv):
    h = rtok("alice", conv["run"], conv["wf"])
    r = client.post(f"/runs/{conv['run']}/reply", json={"kind": "evil", "body": "x"}, headers=h)
    assert r.status_code == 422


def test_conversation_cap_blocks_new_sessions(env, monkeypatch):
    monkeypatch.setattr(config, "MAX_CONVERSATIONS", 1)
    _conv_run(env, "alice")  # fills the single slot
    env.agent("bob")
    assert coordinator.maybe_wakeup("bob", "conversation", run_type="conversation") is None


# -- the reaper keeps a live session but reaps a dead one ---------------------

def test_reaper_keeps_a_live_conversation(conv, monkeypatch):
    monkeypatch.setattr(heartbeat, "config", config)
    coordinator.start_run(conv["run"])
    # a fresh liveness beat: session is alive
    with db.connect() as c:
        c.execute("UPDATE runs SET heartbeat_at = ? WHERE id = ?",
                  (db.utcnow(), conv["run"]))
    heartbeat.recover_stuck_runs()
    assert env_state(conv["run"]) == "running"


def test_reaper_reaps_a_dead_conversation(conv):
    coordinator.start_run(conv["run"])
    # a stale beat: the session process died long ago
    stale = heartbeat._cutoff(config.CONVERSATION_IDLE_SECONDS + 999)
    with db.connect() as c:
        c.execute("UPDATE runs SET heartbeat_at = ?, started_at = ? WHERE id = ?",
                  (stale, stale, conv["run"]))
    heartbeat.recover_stuck_runs()
    assert env_state(conv["run"]) == "failed"


def test_headless_run_still_reaped_by_age(env):
    env.agent("dave")
    run = coordinator.maybe_wakeup("dave", "work")
    coordinator.start_run(run)
    stale = heartbeat._cutoff(heartbeat.RUN_TTL_SECONDS + heartbeat.RUN_GRACE_SECONDS + 999)
    with db.connect() as c:
        c.execute("UPDATE runs SET started_at = ? WHERE id = ?", (stale, run))
    heartbeat.recover_stuck_runs()
    assert env_state(run) == "failed"


# -- token TTL: a conversation token outlives the session --------------------

def test_conversation_run_token_ttl_is_extended():
    assert app_module._run_token_ttl("conversation") == config.CONVERSATION_MAX_SECONDS + 300
    assert app_module._run_token_ttl("work") is None


# -- helper -----------------------------------------------------------------

def env_state(run_id: str) -> str:
    with db.connect() as c:
        return c.execute("SELECT state FROM runs WHERE id = ?", (run_id,)).fetchone()["state"]


# ============================================================================
# Regression tests for red-team findings (all fixed)
# ============================================================================

from andyur.redact import redact


# -- append_event self-defends against a terminal run (concurrency/auth F1a) --

def test_append_event_rejects_a_terminal_run(conv):
    coordinator.start_run(conv["run"])
    coordinator.finish_run(conv["run"], "done", None)
    # even with a (still-valid-looking) session, a finalized run rejects events
    with pytest.raises(conversation.ConversationClosed):
        conversation.append_event(conv["run"], "chunk", "zombie output")


def test_reply_to_terminal_run_is_409(conv):
    h = rtok("alice", conv["run"], conv["wf"])
    coordinator.start_run(conv["run"])
    coordinator.finish_run(conv["run"], "done", None)
    # the run token liveness check 401s first; either way it is refused, never stored
    r = client.post(f"/runs/{conv['run']}/reply", json={"kind": "chunk", "body": "x"}, headers=h)
    assert r.status_code in (401, 409)


# -- seq is unique and monotonic even for many rapid writes (F7) --------------

def test_turn_seqs_are_unique_and_monotonic(conv):
    seqs = [conversation.enqueue_turn(conv["run"], "operator", f"m{i}") for i in range(25)]
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)


def test_event_seqs_are_unique_and_monotonic(conv):
    coordinator.start_run(conv["run"])
    seqs = [conversation.append_event(conv["run"], "chunk", f"c{i}") for i in range(25)]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


def test_duplicate_seq_is_rejected_by_unique_index(conv):
    conversation.enqueue_turn(conv["run"], "operator", "a")
    # forcing a duplicate seq must be rejected by the store, not silently accepted
    with pytest.raises(db.integrity_errors()):
        with db.connect() as c:
            c.execute(
                "INSERT INTO conversation_turns "
                "(id, run_id, seq, kind, sender, body, state, created_at) "
                "VALUES ('dup', ?, 1, 'message', 'operator', 'x', 'pending', ?)",
                (conv["run"], db.utcnow()),
            )


# -- close is never dropped, even under backlog (F3) --------------------------

def test_close_lands_even_when_backlogged(conv, monkeypatch):
    monkeypatch.setattr(config, "CONVERSATION_MAX_EVENT_BACKLOG", 1)
    coordinator.start_run(conv["run"])
    h = rtok("alice", conv["run"], conv["wf"])
    for _ in range(4):
        client.post(f"/runs/{conv['run']}/reply", json={"kind": "chunk", "body": "x"}, headers=h)
    # a MESSAGE is refused (backlogged), but CLOSE must still enqueue the sentinel
    assert client.post(f"/runs/{conv['run']}/turn", json={"body": "m"}).status_code == 429
    assert client.post(f"/runs/{conv['run']}/close").status_code == 200
    turn = client.get(f"/runs/{conv['run']}/next-turn", headers=h).json()["turn"]
    assert turn is not None and turn["kind"] == "close"


# -- backlog measures UNREAD, not total: a reading operator is never throttled (F4)

def test_backlog_counts_unread_not_total(conv, monkeypatch):
    monkeypatch.setattr(config, "CONVERSATION_MAX_EVENT_BACKLOG", 3)
    coordinator.start_run(conv["run"])
    h = rtok("alice", conv["run"], conv["wf"])
    # produce 5 events, but the operator READS them (advancing the cursor)
    for _ in range(5):
        client.post(f"/runs/{conv['run']}/reply", json={"kind": "chunk", "body": "x"}, headers=h)
    evs = client.get(f"/runs/{conv['run']}/events", params={"after": 0}).json()["events"]
    last = evs[-1]["seq"]
    client.get(f"/runs/{conv['run']}/events", params={"after": last})  # ack read cursor
    # now the unread backlog is 0, so a new turn is accepted despite >cap total events
    assert client.post(f"/runs/{conv['run']}/turn", json={"body": "still ok"}).status_code == 201


def test_backlog_blocks_a_non_reading_operator(conv, monkeypatch):
    monkeypatch.setattr(config, "CONVERSATION_MAX_EVENT_BACKLOG", 3)
    coordinator.start_run(conv["run"])
    h = rtok("alice", conv["run"], conv["wf"])
    for _ in range(5):  # operator never reads
        client.post(f"/runs/{conv['run']}/reply", json={"kind": "chunk", "body": "x"}, headers=h)
    assert client.post(f"/runs/{conv['run']}/turn", json={"body": "m"}).status_code == 429


# -- oversized reply event is truncated at the storage boundary (F2) ----------

def test_oversized_event_is_truncated(conv, monkeypatch):
    monkeypatch.setattr(config, "CONVERSATION_MAX_EVENT_BYTES", 16)
    coordinator.start_run(conv["run"])
    conversation.append_event(conv["run"], "chunk", "x" * 1000)
    evs = conversation.read_events(conv["run"], 0)
    assert len(evs[0]["body"]) < 100 and evs[0]["body"].endswith("<truncated>")


# -- redaction: secrets in turns AND replies are scrubbed at storage (F8/F9/F10)

def test_pasted_secret_in_a_turn_is_redacted(conv):
    coordinator.start_run(conv["run"])
    secret = "ghp_" + "a" * 36
    client.post(f"/runs/{conv['run']}/turn", json={"body": f"my token is {secret}"})
    turn = conversation.claim_next_turn(conv["run"])
    assert secret not in turn["body"] and "<redacted>" in turn["body"]


def test_secret_in_a_reply_is_redacted_server_side(conv):
    coordinator.start_run(conv["run"])
    h = rtok("alice", conv["run"], conv["wf"])
    secret = "AKIA" + "A" * 16
    client.post(f"/runs/{conv['run']}/reply", json={"kind": "chunk", "body": f"key={secret}"},
                headers=h)
    evs = client.get(f"/runs/{conv['run']}/events", params={"after": 0}).json()["events"]
    assert secret not in evs[0]["body"] and "<redacted>" in evs[0]["body"]


def test_redactor_covers_common_credentials():
    for s in ["sk-ant-abc123def456", "ghp_" + "a"*36, "AKIA" + "B"*16,
              "xoxb-111-222-abcdef", "AIza" + "c"*35, "glpat-" + "d"*20,
              "postgres://user:pass@host/db", "-----BEGIN RSA PRIVATE KEY-----"]:
        assert "<redacted>" in redact(f"here {s} there"), s
    # a real (long) bearer token is redacted
    assert "<redacted>" in redact("Authorization: Bearer " + "a1b2c3d4" * 5)
    # normal text is left intact, including capital-B "Bearer <word>" chat
    assert redact("the quick brown fox jumps over 12345") == "the quick brown fox jumps over 12345"
    assert redact("the Standard Bearer marched onward") == "the Standard Bearer marched onward"
    assert redact("Bearer capacity was reached at 3:30@office") == "Bearer capacity was reached at 3:30@office"


# -- reaper does not kill a session mid-long-turn when idle < turn_ttl (F5) ---

def test_reaper_window_respects_turn_ttl(conv, monkeypatch):
    # idle shorter than the per-turn TTL: a session mid-turn (last beat ~turn_ttl ago)
    # must NOT be reaped, because the window is max(idle, turn_ttl)+grace
    monkeypatch.setattr(config, "CONVERSATION_IDLE_SECONDS", 30)
    monkeypatch.setattr(config, "CONVERSATION_TURN_TTL_SECONDS", 300)
    coordinator.start_run(conv["run"])
    beat_ago = heartbeat._cutoff(120)  # 120s since last beat: within a 300s turn
    with db.connect() as c:
        c.execute("UPDATE runs SET heartbeat_at = ?, started_at = ? WHERE id = ?",
                  (beat_ago, beat_ago, conv["run"]))
    heartbeat.recover_stuck_runs()
    assert env_state(conv["run"]) == "running"  # not reaped


# ============================================================================
# Regression tests for the final convergence-round findings
# ============================================================================

# These two set `worker`, which their own comments require and which the
# original versions omitted: a run no worker ever claimed was never launched, so
# no runner could have died before /start. Without it they were really testing
# the QUEUED case, which is now deliberately not reaped on this deadline (see
# test_a_queued_run_is_not_reaped_as_a_failure below).

def test_stranded_pending_conversation_is_reaped(conv):
    # a conversation whose runner died before /start: still 'pending', claimed
    # by a worker, created long ago -> the pending reaper must free it (and its
    # scarce slot)
    stale = heartbeat._cutoff(config.CONVERSATION_IDLE_SECONDS + 999)
    with db.connect() as c:
        c.execute("UPDATE runs SET created_at = ?, worker = 'w1' WHERE id = ?",
                  (stale, conv["run"]))
    heartbeat.recover_stuck_runs()
    assert env_state(conv["run"]) in ("failed", "done")
    # the agent is returned to idle so it can be triggered again
    with db.connect() as c:
        st = c.execute("SELECT state FROM agent_status WHERE agent = 'alice'").fetchone()["state"]
    assert st == "idle"


def test_stranded_pending_headless_is_reaped(env):
    env.agent("dave")
    run = coordinator.maybe_wakeup("dave", "work")
    stale = heartbeat._cutoff(heartbeat.RUN_TTL_SECONDS + heartbeat.RUN_GRACE_SECONDS + 999)
    with db.connect() as c:
        c.execute("UPDATE runs SET created_at = ?, worker = 'w1' WHERE id = ?",
                  (stale, run))
    heartbeat.recover_stuck_runs()
    assert env_state(run) in ("failed", "done")


def test_a_queued_run_is_not_reaped_as_a_failure(env):
    """Waiting for capacity is not failing.

    An unclaimed pending run has not been picked up because every slot is busy
    -- the state a queue exists to represent. The reaper failed it on the same
    deadline as a dead runner, so a saturated platform recorded failures against
    agents that had done nothing wrong, hardest exactly when load was highest.
    """
    env.agent("queued")
    run = coordinator.maybe_wakeup("queued", "work")
    stale = heartbeat._cutoff(heartbeat.RUN_TTL_SECONDS + heartbeat.RUN_GRACE_SECONDS + 999)
    with db.connect() as c:                       # old enough, but never claimed
        c.execute("UPDATE runs SET created_at = ? WHERE id = ?", (stale, run))
    heartbeat.recover_stuck_runs()
    assert env_state(run) == "pending"


def test_a_run_queued_past_the_backstop_is_given_up_on(env):
    """It still cannot wait forever: while pending it holds the agent's only
    live-run slot, so the agent could never run again."""
    env.agent("forgotten")
    run = coordinator.maybe_wakeup("forgotten", "work")
    stale = heartbeat._cutoff(heartbeat.QUEUE_MAX_WAIT_SECONDS + 999)
    with db.connect() as c:
        c.execute("UPDATE runs SET created_at = ? WHERE id = ?", (stale, run))
    heartbeat.recover_stuck_runs()
    assert env_state(run) in ("failed", "done")
    with db.connect() as c:
        err = c.execute("SELECT error FROM runs WHERE id = ?", (run,)).fetchone()["error"]
    assert "capacity" in err, f"a capacity wait must not be reported as a crash: {err!r}"


def test_a_long_queued_run_is_not_reaped_the_moment_a_worker_claims_it(env):
    """The queue/claim split is worthless if the claimed deadline runs from
    creation.

    A run that legitimately waited past TTL+grace was failed as "never started"
    on the first tick after assign_runs picked it up, while a healthy runner was
    preparing to start it -- so the 24h backstop snapped back to the TTL the
    instant anything claimed the run, and it bit hardest under sustained load,
    which is the exact case the split was written for.
    """
    env.agent("patient")
    run = coordinator.maybe_wakeup("patient", "work")
    stale = heartbeat._cutoff(heartbeat.RUN_TTL_SECONDS + heartbeat.RUN_GRACE_SECONDS + 999)
    with db.connect() as c:
        c.execute("UPDATE runs SET created_at = ? WHERE id = ?", (stale, run))

    assigned = coordinator.assign_runs("worker-1", 4)     # capacity frees up
    assert any(a["id"] == run for a in assigned)
    heartbeat.recover_stuck_runs()

    assert env_state(run) == "pending", "a freshly claimed run was reaped"
    assert coordinator.start_run(run), "the runner could no longer start it"


def test_a_claimed_run_whose_runner_died_is_still_reaped(env):
    """The other direction: measuring from assignment must not make the stranded
    case unreachable."""
    env.agent("stranded")
    run = coordinator.maybe_wakeup("stranded", "work")
    coordinator.assign_runs("worker-1", 4)
    stale = heartbeat._cutoff(heartbeat.RUN_TTL_SECONDS + heartbeat.RUN_GRACE_SECONDS + 999)
    with db.connect() as c:
        c.execute("UPDATE runs SET assigned_at = ? WHERE id = ?", (stale, run))
    heartbeat.recover_stuck_runs()
    assert env_state(run) in ("failed", "done")


def test_a_queued_conversation_does_not_hold_its_slot_for_a_day(env):
    """A conversation waits with a human attached, and holds one of the scarce
    global MAX_CONVERSATIONS slots while it waits. Giving unclaimed runs a 24h
    backstop meant one worker outage could hold every slot for a day and refuse
    every new conversation platform-wide. Headless work is still worth doing
    late; a session that starts twenty hours on is worth nothing to anybody."""
    env.agent("chatter")
    run = coordinator.maybe_wakeup("chatter", "talk", run_type="conversation")
    stale = heartbeat._cutoff(config.CONVERSATION_IDLE_SECONDS + heartbeat.RUN_GRACE_SECONDS + 999)
    with db.connect() as c:                       # old, and never claimed
        c.execute("UPDATE runs SET created_at = ? WHERE id = ?", (stale, run))
    heartbeat.recover_stuck_runs()
    assert env_state(run) in ("failed", "done"), "the conversation slot is still held"


def test_a_live_conversation_is_still_bounded_by_wall_clock(conv, monkeypatch):
    """A beating session was exempt from every wall-clock limit.

    CONVERSATION_MAX_SECONDS is checked between turns inside the RUNNER, which
    is the process we assume can wedge. A session stuck in its turn loop beats
    on every reply chunk, so it looked healthy forever while holding a scarce
    conversation slot and a live credential.
    """
    monkeypatch.setattr(config, "CONVERSATION_MAX_SECONDS", 60)
    coordinator.start_run(conv["run"])
    old = heartbeat._cutoff(60 + heartbeat.RUN_GRACE_SECONDS + 999)
    now = heartbeat._cutoff(0)
    with db.connect() as c:      # started long ago, but beating right now
        c.execute("UPDATE runs SET started_at = ?, heartbeat_at = ? WHERE id = ?",
                  (old, now, conv["run"]))
    heartbeat.recover_stuck_runs()
    assert env_state(conv["run"]) in ("failed", "done")


def test_fresh_pending_run_is_not_reaped(conv):
    # a just-created pending run must NOT be reaped (it is waiting to start)
    heartbeat.recover_stuck_runs()
    assert env_state(conv["run"]) == "pending"


def test_read_cursor_clamp_keeps_backpressure_for_future_events(conv, monkeypatch):
    # The bug: a huge `after` sets the cursor beyond all real seqs, so FUTURE
    # events (with smaller seqs) are never counted as unread -> backpressure
    # permanently defeated. The clamp pins the cursor to the max real seq, so new
    # events still register as unread.
    monkeypatch.setattr(config, "CONVERSATION_MAX_EVENT_BACKLOG", 2)
    coordinator.start_run(conv["run"])
    h = rtok("alice", conv["run"], conv["wf"])
    for _ in range(5):
        client.post(f"/runs/{conv['run']}/reply", json={"kind": "chunk", "body": "x"}, headers=h)
    # malicious jump: cursor clamps to the real max (5), acknowledging existing events
    client.get(f"/runs/{conv['run']}/events", params={"after": 10_000_000})
    assert client.post(f"/runs/{conv['run']}/turn", json={"body": "ok now"}).status_code == 201
    # now the agent streams MORE than the cap of new events; backpressure must re-engage
    for _ in range(4):
        client.post(f"/runs/{conv['run']}/reply", json={"kind": "chunk", "body": "y"}, headers=h)
    assert client.post(f"/runs/{conv['run']}/turn", json={"body": "blocked"}).status_code == 429


def test_conversation_client_has_no_max_turns_cap():
    # the persistent session must NOT inherit the headless max_turns (which would
    # tear down the whole session when hit); it is bounded by the turn TTL + caps
    from andyur.runner import driver
    import tempfile
    opts = driver._build_options("alice", tempfile.mkdtemp(),
                                 driver.CONVERSATION_SYSTEM_PROMPT, None, "r1", {},
                                 max_turns=None)
    assert opts.max_turns is None
    # headless still capped
    opts2 = driver._build_options("alice", tempfile.mkdtemp(),
                                  driver.SYSTEM_PROMPT, None, "r2", {})
    assert opts2.max_turns == driver.DEFAULT_MAX_TURNS


def test_per_user_conversation_cap(env, monkeypatch):
    # under user-auth, one tenant cannot occupy more than the per-user cap even if
    # global slots remain. maybe_wakeup receives user=owner from trigger_agent.
    monkeypatch.setattr(config, "MAX_CONVERSATIONS", 20)
    monkeypatch.setattr(config, "MAX_CONVERSATIONS_PER_USER", 2)
    for a in ("a1", "a2", "a3"):
        env.agent(a)
    r1 = coordinator.maybe_wakeup("a1", "c", run_type="conversation", user="alice")
    r2 = coordinator.maybe_wakeup("a2", "c", run_type="conversation", user="alice")
    r3 = coordinator.maybe_wakeup("a3", "c", run_type="conversation", user="alice")
    assert r1 and r2 and r3 is None  # alice's 3rd is refused despite free global slots
    # a different tenant is unaffected
    env.agent("b1")
    assert coordinator.maybe_wakeup("b1", "c", run_type="conversation", user="bob") is not None
