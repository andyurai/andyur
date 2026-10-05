// Executable regression tests for andyur/console/static/app.js.
//
// One test per page defect this lane found and fixed. Each is written so that
// restoring the original bug reddens it -- the harness's virtual clock is what
// makes "and then nothing else happened for sixty seconds" an assertion rather
// than a hope.
//
// Run it through pytest -- `pytest tests/test_console_page.py` -- which feeds
// in the server's own constants. Run bare it exits 2 and says which are
// missing, rather than reporting failures that are really a missing fixture:
// "the route's key set is absent" and "the page rendered undefined" are the
// same two lines whether the page is broken or the runner was invoked wrong,
// and only one of those is worth waking someone for.
import { run, check, report, drain, click, readAppJs } from './console_page_harness.mjs';

for (const required of ['ANDYUR_SESSION_HEADER', 'ANDYUR_FLOW_NODE_KEYS']) {
  if (!process.env[required]) {
    console.error(
      `${required} is not set. These checks are driven by pytest, which feeds ` +
      `in the server's own constants so the page is asserted against what the ` +
      `server actually uses rather than against a copy:\n` +
      `    .venv/bin/python -m pytest tests/test_console_page.py -q`);
    process.exit(2);
  }
}

const ok = body => ({ status: 200, body });
const NO_RUNS = ok({ runs: [], next: null });

function baseRoutes(extra = {}) {
  return {
    'GET /healthz': ok({ control_plane: 'http://cp', trace_ui: '' }),
    'GET /api/me': ok({ user_auth: false, sub: null, admin: true }),
    'GET /api/agents': ok([]),
    'GET /api/workers': ok([]),
    'GET /api/runs': NO_RUNS,
    ...extra,
  };
}
const countFetches = (s, needle) => s.fetches.filter(f => f.url.includes(needle)).length;

// --- 1. the Workers page must not leave a timer behind on every tick ---------
{
  const s = await run({ hash: '#/workers', routes: baseRoutes() });
  await s.clock.advance(1);
  const afterFirst = countFetches(s, '/api/workers');
  const timersAfterFirst = s.clock.live;
  await s.clock.advance(60_000);          // ten ticks at the 6 s interval
  const total = countFetches(s, '/api/workers');
  check('the Workers page makes one request per tick, not two per tick compounding',
        total <= afterFirst + 11, `${total} requests in 60 s`);
  check('the Workers page holds exactly one live timer',
        s.clock.live <= 1 && timersAfterFirst <= 1, `${s.clock.live} live timers`);
}

// --- 2. the visibility catch-up must not become a millisecond poll -----------
{
  const s = await run({ hash: '#/workers', routes: baseRoutes() });
  await s.clock.advance(1);
  const before = countFetches(s, '/api/workers');
  // the tab goes away and comes back, which is what the browser gate does
  s.sandbox.document.hidden = true;
  await s.clock.advance(100);
  s.sandbox.document.hidden = false;
  s.sandbox.document._l.visibilitychange();
  await s.clock.advance(1);
  const caughtUp = countFetches(s, '/api/workers');
  check('coming back to the tab catches up at once', caughtUp > before,
        `${before} -> ${caughtUp}`);
  await s.clock.advance(10_000);
  const after = countFetches(s, '/api/workers');
  // at the 6 s interval that is at most two more; at 1 ms it would be ~10000
  check('and then polls at its own interval, not every millisecond',
        after - caughtUp <= 3, `${after - caughtUp} requests in the next 10 s`);
}

// --- 2b. one page holds ONE timer chain, however often the tab flickers ------
{
  // The trigger is hide/show WHILE A FETCH IS IN FLIGHT, so the flicker is
  // fired from inside the in-flight response -- which is exactly the moment
  // the tick is suspended at its own await. clearTimeout cannot stop a tick
  // that has already fired: its handle is spent, so the catch-up arms a fresh
  // chain and the suspended callback arms its own on the way out. One extra
  // chain per repetition, each re-arming forever.
  let flickers = 0;
  const s = await run({
    hash: '#/workers',
    routes: baseRoutes(),
    hooks: {
      beforeResponse: async (state, url) => {
        if (!url.includes('/api/workers') || flickers >= 5) return;
        flickers += 1;
        state.sandbox.document.hidden = true;
        state.sandbox.document._l.visibilitychange();
        state.sandbox.document.hidden = false;
        state.sandbox.document._l.visibilitychange();
      },
    },
  });
  await s.clock.advance(1);
  await s.clock.advance(30_000);
  check('a tab flickering during a fetch leaves one timer, not one per flicker',
        s.clock.live <= 1, `${s.clock.live} live timers after ${flickers} flickers`);
  const before = countFetches(s, '/api/workers');
  await s.clock.advance(60_000);
  const rate = countFetches(s, '/api/workers') - before;
  // one chain at 6 s is ~10 requests in 60 s; N chains is ~10N
  check('and it polls at one chain rate, not N chain rates',
        rate <= 12, `${rate} requests in 60 s`);
}

// --- 3. a conversation event is appended once, whatever raced ----------------
{
  let served = 0;
  const events = [{ seq: 1, kind: 'chunk', body: 'hello ' }, { seq: 2, kind: 'chunk', body: 'world' }];
  const s = await run({
    hash: '#/runs/r1',
    routes: baseRoutes({
      'GET /api/runs/r1': ok({ id: 'r1', agent: 'a', run_type: 'conversation',
                               state: 'running', reason: 'r', created_at: '2026-08-26T10:00:00' }),
      'GET /api/runs/r1/events': () => {
        served += 1;
        // The server answers `after=<cursor>`; a page that re-reads the same
        // cursor from two callers gets the same events twice. Serve them
        // unconditionally so the PAGE has to be the thing that de-duplicates.
        return ok({ events });
      },
    }),
  });
  await s.clock.advance(1);
  await s.clock.advance(2100);
  await s.clock.advance(2100);
  const html = s.el('turns').innerHTML || s.el('follow').innerHTML;
  const hellos = (html.match(/hello/g) || []).length;
  check('a conversation event is rendered once however many ticks saw it',
        hellos === 1, `${hellos} copies after ${served} polls`);
}

// --- 4. a terminal run stops polling ----------------------------------------
{
  const s = await run({
    hash: '#/runs/done1',
    routes: baseRoutes({
      'GET /api/runs/done1': ok({ id: 'done1', agent: 'a', run_type: 'work', state: 'done',
                                  reason: 'r', summary: 'out', created_at: '2026-08-26T10:00:00' }),
      'GET /api/runs/done1/exchanges': ok({ exchanges: [] }),
    }),
  });
  await s.clock.advance(1);
  await s.clock.advance(3100);            // let the first scheduled tick fire
  const settled = countFetches(s, '/api/runs/done1');
  await s.clock.advance(60_000);
  const after = countFetches(s, '/api/runs/done1');
  check('a run that has ended is not polled forever', after === settled,
        `${after - settled} further requests in 60 s`);
  check('and its page holds no live timer', s.clock.live === 0, `${s.clock.live} live timers`);
}

// --- 5. the Runs page keeps the pages the operator walked back to ------------
{
  const page1 = { runs: [{ id: 'r9', agent: 'a', state: 'done', reason: '', created_at: '9' }],
                  next: 'CURSOR1' };
  const page2 = { runs: [{ id: 'r8', agent: 'a', state: 'done', reason: '', created_at: '8' }],
                  next: null };
  const s = await run({
    hash: '#/runs',
    routes: baseRoutes({
      'GET /api/runs': url => ok(url.includes('before=CURSOR1') ? page2 : page1),
    }),
  });
  await s.clock.advance(1);
  await click(s, 'runs-older');
  const walked = s.el('list').innerHTML;
  check('walking back adds the older page', walked.includes('r8') && walked.includes('r9'),
        `r9=${walked.includes('r9')} r8=${walked.includes('r8')}`);
  await s.clock.advance(6100);            // the background refresh
  const afterTick = s.el('list').innerHTML;
  check('and the background refresh does not throw the walked page away',
        afterTick.includes('r8') && afterTick.includes('r9'),
        `r9=${afterTick.includes('r9')} r8=${afterTick.includes('r8')}`);
  // two fast clicks must not duplicate a row
  // TWO CLICKS WITH NO AWAIT BETWEEN THEM, which is what a fast operator does
  await Promise.all([click(s, 'runs-older'), click(s, 'runs-older')]);
  const html = s.el('list').innerHTML;
  const r8s = (html.match(/#\/runs\/r8/g) || []).length;
  check('and clicking Older twice does not list a run twice', r8s <= 2,
        `${r8s} references to r8 (one row = 2: the tr and its link)`);
  const tables = (html.match(/<table>/g) || []).length;
  check('the list is one table, so its header still describes its rows',
        tables === 1, `${tables} tables`);
}

// --- 6. only a transport failure claims the control plane is unreachable -----
{
  const s = await run({
    hash: '#/workers',
    routes: baseRoutes({ 'GET /api/workers': { status: 404, body: { detail: 'no' } } }),
  });
  await s.clock.advance(1);
  await s.clock.advance(6100);
  const header = s.el('cp').textContent || '';
  check('a 404 from an older server is not reported as an outage',
        !header.includes('unreachable'), header.slice(0, 70));
}
{
  const s = await run({
    hash: '#/workers',
    routes: baseRoutes({ 'GET /api/workers': { status: 502, body: { reason: 'upstream_unreachable' } } }),
  });
  await s.clock.advance(1);
  await s.clock.advance(6100);
  const header = s.el('cp').textContent || '';
  check('a 502 IS reported as an outage (the positive control)',
        header.includes('unreachable'), header.slice(0, 70));
}

// --- 7. a failing page does not leave the previous one on screen -------------
{
  const s = await run({
    hash: '#/runs/missing',
    routes: baseRoutes({ 'GET /api/runs/missing': { status: 404, body: { detail: 'no such run' } } }),
  });
  await s.clock.advance(1);
  const view = s.el('view').innerHTML;
  check('a page whose load fails says so instead of showing the last one',
        view.includes('no such run') || view.includes('Loading') === false,
        view.slice(0, 90));
}

// --- 8. a truncated escape in the hash does not stop the router --------------
{
  const s = await run({ hash: '#/runs/%', routes: baseRoutes() });
  await s.clock.advance(1);
  check('a truncated percent-escape in the URL does not freeze the page',
        s.crashes.length === 0 && (s.el('view').innerHTML || '').length > 0,
        s.crashes[0] || 'the view rendered something');
}


// --- 9. the graph says when it is not the whole workflow ---------------------
// The route caps runs, tasks/messages, bytes per transcript, bytes per request
// and distinct names per run, and reports each. Rendering the sum as an exact
// number while any of them fired states a total that is not the total: on a
// 200-run workflow the page said "2016 model calls" where the truth was
// 252,800, and drew "no transcript" on 184 nodes that all had one.
{
  const flow = {
    state: 'active', truncated_runs: true, truncated_items: true, truncated_reads: true,
    tasks: [], messages: [], edges: [],
    nodes: [
      {agent: 'a', state: 'done', depth: 0, elided: false, index: 0, id: 'n1',
       run_type: 'work', reason: 'r', exchanges: {models: {m: 3}, tools: {}, truncated: true}},
      {agent: 'b', state: 'done', depth: 0, elided: false, index: 1, id: 'n2',
       run_type: 'work', reason: 'r', exchanges: null, exchanges_omitted: 'budget'},
    ],
  };
  const s = await run({
    hash: '#/workflows/wf1',
    routes: baseRoutes({ 'GET /api/workflows/wf1/flow': ok(flow) }),
  });
  await s.clock.advance(1);
  const view = s.el('view').innerHTML;
  check('the counts are marked as lower bounds when anything was left out',
        view.includes('at least'), view.slice(0, 120));
  check('and the page says WHY it is not the whole workflow',
        view.includes('not the whole workflow') && view.includes('read budget'),
        view.includes('not the whole workflow') ? 'named' : 'silent');
  const svg = s.el('flowSvg').innerHTML;
  check('a node the budget skipped is not labelled as having no transcript',
        svg.includes('transcript not read') && !svg.includes('no transcript · trace only'),
        svg.includes('transcript not read') ? 'distinguished' : 'conflated');
  check('and a partly-counted node says so',
        svg.includes('counted in part only'));
}

// --- 10. the page reads no node field the route does not return -------------
// Third instance of one class in this lane: protoOf read a field the list
// projection had dropped; interface_version was added with no reader; and the
// flow node changed projection under readers that no test named.
//
// The key set comes from the ROUTE, injected by pytest from the real
// projection, not from a list copied into this file. A hand-copied NODE_KEYS
// was itself a second source of truth for run_list_view and already differed
// from it -- so it answered "reads nothing outside my copy" rather than
// "reads nothing the route does not return".
{
  const returned = process.env.ANDYUR_FLOW_NODE_KEYS.split(',').filter(Boolean);
  check('the route\'s own node key set reached this runner',
        returned.length >= 10, `${returned.length} keys`);
  const flow = {
    state: 'active', truncated_runs: false, truncated_items: false,
    truncated_reads: false, tasks: [], messages: [], edges: [],
    nodes: [Object.fromEntries(returned.map(k => [k, k === 'elided' ? false
             : k === 'index' || k === 'depth' ? 0 : k === 'exchanges' ? null : 'v']))],
  };
  const s = await run({
    hash: '#/workflows/wfk',
    routes: baseRoutes({ 'GET /api/workflows/wfk/flow': ok(flow) }),
  });
  await s.clock.advance(1);
  check('the flow page renders a node built ONLY from what the route returns',
        (s.el('flowSvg').innerHTML || '').includes('<svg'), 'drew the graph');
  check('and does so with no uncaught error', s.crashes.length === 0, s.crashes[0] || '');
  // undefined is what a missing field looks like once it reaches the markup
  check('and nothing it drew reads as a missing field',
        !(s.el('flowSvg').innerHTML || '').includes('undefined'),
        (s.el('flowSvg').innerHTML || '').slice(0, 120));
}

// --- 11. the header line names what is down ---------------------------------
// Six causes reach that line and five are not the control plane. Saying
// "control plane unreachable" for all six sends the operator to the wrong
// machine.
for (const [reason, expect] of [
  ['identity_unavailable', 'SPIRE'],
  ['idp_error', 'IdP'],
  ['upstream_unreachable', 'control plane'],
]) {
  const s = await run({
    hash: '#/workers',
    routes: baseRoutes({ 'GET /api/workers': { status: 503, body: { reason } } }),
  });
  await s.clock.advance(1);
  await s.clock.advance(6100);
  const header = s.el('cp').textContent || '';
  check(`a ${reason} failure names its own subject`, header.includes(expect),
        header.slice(0, 80));
}

// --- 12. an already-finished run is not polled even once ---------------------
{
  const s = await run({
    hash: '#/runs/fin',
    routes: baseRoutes({
      'GET /api/runs/fin': ok({ id: 'fin', agent: 'a', run_type: 'work', state: 'done',
                                reason: 'r', summary: 'out', created_at: '2026-08-26T10:00:00' }),
      'GET /api/runs/fin/exchanges': ok({ exchanges: [] }),
    }),
  });
  await s.clock.advance(1);
  const settled = countFetches(s, '/api/runs/fin');
  await s.clock.advance(10_000);
  check('opening a finished run issues no stray poll at all',
        countFetches(s, '/api/runs/fin') === settled,
        `${countFetches(s, '/api/runs/fin') - settled} stray requests`);
  check('and it arms no timer', s.clock.live === 0, `${s.clock.live} live timers`);
}

// --- 13. every notice reaches a screen reader --------------------------------
{
  const s = await run({ hash: '#/agents', routes: baseRoutes() });
  await s.clock.advance(1);
  const src = readAppJs();
  check('the toast container is a live region',
        /aria-live/.test(src) && /role', 'status'|role="status"/.test(src),
        'toast() sets role=status and aria-live');
  check('the scope chip group has an accessible name',
        /role="group" aria-labelledby=/.test(src));
}


// --- 14. server text is escaped before it reaches the page -------------------
// esc() is the page's only XSS defence and nothing exercised it: neutering the
// character class survived every console test. The CSP makes an injected
// <script> inert, which is defence in depth, not a reason to stop escaping --
// an injected attribute or element still rewrites what the operator is looking
// at, and the operator is deciding whether to delete an agent.
{
  const nasty = '</td><script>x</script>" onmouseover="y" `+`';
  const s = await run({
    hash: '#/runs',
    routes: baseRoutes({
      'GET /api/runs': ok({ runs: [{ id: 'r1', agent: nasty, state: 'done',
                                     reason: nasty, created_at: '2026-08-26' }], next: null }),
    }),
  });
  await s.clock.advance(1);
  const html = s.el('list').innerHTML;
  check('the row rendered at all (positive control)', html.includes('&lt;'), html.slice(0, 60));
  check('a server-supplied string cannot open a tag',
        !html.includes('<script>'), html.includes('<script>') ? 'raw <script> in the DOM' : 'escaped');
  check('nor close one, nor add an attribute',
        !html.includes('</td><script') && !html.includes(' onmouseover="'),
        'quotes and angle brackets escaped');
  check('and a backtick cannot open a template substitution',
        !html.includes('`+`'), 'backtick escaped');
}


// --- 15. a partly-counted transcript is on the graph AND its own node --------
{
  const flow = {
    state: 'active', truncated_runs: false, truncated_items: false, truncated_reads: false,
    tasks: [], messages: [], edges: [],
    nodes: [{agent: 'a', state: 'done', depth: 0, elided: false, index: 0, id: 'n1',
             run_type: 'work', reason: 'r',
             exchanges: {models: {m: 3}, tools: {t: 1}, truncated: true}}],
  };
  const s = await run({
    hash: '#/workflows/wf2',
    routes: baseRoutes({ 'GET /api/workflows/wf2/flow': ok(flow) }),
  });
  await s.clock.advance(1);
  // per-file truncation alone, with no request-level flag, must still be said
  check('a node counted only in part is marked even when no request-level flag is set',
        s.el('flowSvg').innerHTML.includes('counted in part only'));
  check('and the totals are marked as lower bounds because of it',
        (s.el('view').innerHTML || '').includes('at least'));
}


// --- 16. the page authenticates under the header the BFF actually checks -----
{
  const s = await run({ hash: '#/agents', routes: baseRoutes(), storedSecret: 'SEKRIT' });
  await s.clock.advance(1);
  const api = s.fetches.filter(f => f.url.startsWith('/api/'));
  check('the page made an API call at all (positive control)', api.length > 0);
  const header = process.env.ANDYUR_SESSION_HEADER || 'andyur-console-session';
  check('every API call carries the session secret under the BFF\'s header name',
        api.every(f => f.headers[header] === 'SEKRIT'),
        JSON.stringify(api[0] && api[0].headers));
  // and under NO other header: a console sending it twice, or under a second
  // name, is a console whose auth surface is not the one the BFF fences
  const extra = new Set();
  for (const f of api) {
    for (const k of Object.keys(f.headers)) {
      if (k !== header && String(f.headers[k]) === 'SEKRIT') extra.add(k);
    }
  }
  check('and under no other header name', extra.size === 0, [...extra].join(','));
}

// --- the actor line states HOW the subject was established --------------------
//
// The platform carries provenance beside the subject everywhere (runtoken.py:
// `sub` alone answers "who" and a resource server also needs "says who"), and
// the console used to render a bare name. An `asserted` subject means an
// authenticated operator SAID the run acts for Alice; nobody authenticated
// Alice. Shown identically to an IdP-verified one, that is an asserted identity
// displayed as a proven one -- on the surface we put in front of people.
{
  const RUN = (extra) => ({
    id: 'r1', agent: 'opensre', state: 'done', created_at: '2026-08-27T00:00:00',
    workflow_id: 'wf-1', depth: 0, scope: [], ...extra,
  });
  const headerFor = async (extra) => {
    const s = await run({ hash: '#/runs/r1',
      routes: baseRoutes({ 'GET /api/runs/r1': ok(RUN(extra)) }) });
    await s.clock.advance(1);
    return s.elements.get('runHeader')?.innerHTML || '';
  };

  const asserted = await headerFor({ acting_user: 'Alice', user_asserted_by: 'asserted' });
  check('an asserted actor says it was asserted',
        asserted.includes('Alice') && asserted.includes('asserted by operator'), asserted.slice(0, 200));
  check('and is marked as the weaker claim, not styled like a verified one',
        /class="prov weak"/.test(asserted), asserted.slice(0, 200));

  const idp = await headerFor({ acting_user: 'Alice', user_asserted_by: 'idp' });
  check('an IdP-verified actor says so instead',
        idp.includes('verified by IdP'), idp.slice(0, 200));
  // the positive control that makes the two assertions above mean something:
  // if every actor rendered "weak", the weak check could not fail
  check('and is NOT marked weak (positive control on the distinction)',
        !/class="prov weak"/.test(idp), idp.slice(0, 200));

  const unknown = await headerFor({ acting_user: 'Alice', user_asserted_by: null });
  check('an actor with no recorded provenance is reported, not guessed',
        unknown.includes('provenance not recorded'), unknown.slice(0, 200));
  check('and a run with no actor at all still renders none',
        (await headerFor({})).includes('none'));
}

// --- the golden path renders as one story, from the API alone ----------------
//
// RC freeze 4.2: the whole MVP story must be demonstrable from the product
// surface, "without opening a database, kubectl, Jaeger or source code".
// Sources are fixed by docs/lane-a-action-contract.md.
{
  const RUN = {
    id: 'r9', agent: 'opensre', state: 'running', created_at: '2026-08-27T11:40:00',
    workflow_id: 'wf-9', depth: 0, scope: [],
    input: '{"incident":"INC-4471"}',
    acting_user: 'Alice', user_asserted_by: 'asserted',
    subject_context: '{"service":"checkout-prod"}', pin_asserted_by: 'operator',
    summary: 'bad deployment',
  };
  const ACTION = {
    id: 'a1', run_id: 'r9', tool: 'rollback_deployment', target: 'prod/checkout',
    decision: 'approval_required', decision_reason: 'write_requires_approval',
    approved_by: 'operator', approved_by_asserted_by: 'operator_api',
    result: 'succeeded', result_detail: 'observed revision 41',
  };
  const storyFor = async (runRow, actions) => {
    const routes = baseRoutes({ 'GET /api/runs/r9': ok(runRow) });
    routes['GET /api/runs/r9/actions'] = actions === undefined
      ? { status: 404, body: { detail: 'not found' } } : ok(actions);
    const s = await run({ hash: '#/runs/r9', routes });
    await s.clock.advance(1);
    return s.elements.get('storyPanel')?.innerHTML || '';
  };

  const full = await storyFor(RUN, [ACTION]);
  for (const [field, needle] of [
    ['incident',    'INC-4471'],
    ['agent',       'opensre'],
    ['actor',       'Alice'],
    ['resource',    'checkout-prod'],
    ['diagnosis',   'bad deployment'],
    ['requested',   'rollback_deployment'],
    ['decision',    'approval required'],
    ['approved by', 'operator'],
    ['result',      'succeeded'],
  ]) {
    check(`the story shows ${field}`, full.includes(needle), full.slice(0, 300));
  }
  check('the resource comes from the PIN and carries its provenance',
        full.includes('pinned by operator'), full.slice(0, 300));
  check('the approver carries provenance, not a bare name',
        full.includes('via operator_api'), full.slice(0, 300));

  // a decision outside the closed set is shown LOUDLY, never dropped or guessed
  const drift = await storyFor(RUN, [{ ...ACTION, decision: 'probably_fine' }]);
  check('a decision outside the contract is surfaced, not hidden',
        drift.includes('unknown decision') && drift.includes('probably_fine'),
        drift.slice(0, 300));
  // ...and the positive control that makes that mean something
  check('a decision INSIDE the closed set is not flagged unknown',
        !full.includes('unknown decision'), full.slice(0, 300));

  // Missing evidence is not evidence that nothing happened.
  const notBuilt = await storyFor(RUN, undefined);
  check('a 404 from the not-yet-built endpoint does not break the page',
        notBuilt.includes('Alice') && notBuilt.includes('INC-4471'),
        notBuilt.slice(0, 300));
  check('and it names the action evidence as unavailable rather than empty',
        notBuilt.includes('action data unavailable')
        && !notBuilt.includes('no consequential action requested')
        && !notBuilt.includes('allowed') && !notBuilt.includes('denied'),
        notBuilt.slice(0, 300));

  const genuinelyEmpty = await storyFor(RUN, []);
  check('a successful empty action list says no action was requested',
        genuinelyEmpty.includes('no consequential action requested'),
        genuinelyEmpty.slice(0, 300));
  check('and a successful empty list is not reported as unavailable',
        !genuinelyEmpty.includes('action data unavailable'),
        genuinelyEmpty.slice(0, 300));
}

process.exit(report() ? 0 : 1);
