// Runs andyur/console/static/app.js under a minimal DOM with a VIRTUAL CLOCK
// and a stubbed control plane, so the page's timer, paging and cursor logic can
// be asserted the way any other logic is.
//
// WHY THIS EXISTS. Every one of the ten page defects that shipped in this lane
// -- a Workers request storm that doubled every tick, a one-millisecond poll
// flood after a tab switch, duplicate conversation events, a stale page
// painting into the next, a Runs page that lost every walked page every six
// seconds -- was a bug in TIME and STATE, invisible to a static check and
// awkward to provoke in a real browser. The live browser gate proves the page
// works; this proves it keeps working.
//
// It is deliberately not a DOM implementation. Elements record what was written
// to them; assertions are made on the fetch log, the timer log and the rendered
// HTML string. Anything needing real layout or real event dispatch belongs in
// infra/verify-console-browser.py, which drives actual Chrome.
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP_JS = path.join(HERE, '..', 'andyur', 'console', 'static', 'app.js');

// ---- the virtual clock ------------------------------------------------------
// Real timers would make every assertion a race. Here time only moves when a
// test moves it, so "what did the page do over the next sixty seconds" is a
// question with one answer.
class Clock {
  constructor() { this.now = 0; this.next = 1; this.timers = new Map(); this.armed = []; }
  setTimeout(fn, delay) {
    const id = this.next++;
    const at = this.now + (delay || 0);
    this.timers.set(id, { fn, at });
    this.armed.push({ id, delay: delay || 0, at });
    return id;
  }
  clearTimeout(id) { this.timers.delete(id); }
  get live() { return this.timers.size; }
  // Advance to `ms`, firing due timers in time order. Async so the page's own
  // awaits inside a tick settle before the next one fires.
  async advance(ms) {
    const end = this.now + ms;
    for (let guard = 0; guard < 100000; guard++) {
      let due = null;
      for (const [id, t] of this.timers) {
        if (t.at <= end && (due === null || t.at < this.timers.get(due).at)) due = id;
      }
      if (due === null) { this.now = end; return; }
      const t = this.timers.get(due);
      this.timers.delete(due);
      this.now = t.at;
      await t.fn();
      await drain();
    }
    throw new Error('advance did not converge: a timer is rearming with no delay');
  }
}
// Let every already-resolved promise continuation run.
const drain = () => new Promise(r => setImmediate(r));

// The page's own boot() is async, so a defect that throws inside it surfaces as
// an UNHANDLED REJECTION, which ends the node process before a single check has
// printed. Recorded against the running scenario instead, so the check written
// for that defect is the thing that reports it.
let activeState = null;
process.on('unhandledRejection', reason => {
  if (activeState) activeState.crashes.push(String(reason));
  else throw reason;
});

// ---- the minimal DOM --------------------------------------------------------
function makeElement(id) {
  const el = {
    id,
    _html: '',
    textContent: '',
    dataset: {},
    hidden: false,
    value: '',
    scrollTop: 0, scrollHeight: 0, clientHeight: 0,
    children: [],
    classList: {
      _set: new Set(),
      add(c) { this._set.add(c); },
      remove(c) { this._set.delete(c); },
      toggle(c, on) { const v = on === undefined ? !this._set.has(c) : !!on;
                      v ? this._set.add(c) : this._set.delete(c); return v; },
      contains(c) { return this._set.has(c); },
    },
    setAttribute() {}, removeAttribute() {}, addEventListener() {},
    focus() {}, remove() {}, requestSubmit() {},
    appendChild(c) { this.children.push(c); },
    insertAdjacentHTML(_, html) { this._html += html; },
    querySelectorAll() { return []; },
    querySelector() { return null; },
    get firstChild() { return this.children[0] || null; },
  };
  Object.defineProperty(el, 'innerHTML', {
    get() { return this._html; },
    // Writing innerHTML replaces the subtree, so any id inside the OLD markup
    // is gone. Modelled, because "a stale page paints into the next one" is
    // exactly a write landing in an element the new page never created.
    set(v) { this._html = String(v); },
  });
  return el;
}

export async function run(scenario) {
  const clock = new Clock();
  const elements = new Map();
  const el = id => {
    if (!elements.has(id)) elements.set(id, makeElement(id));
    return elements.get(id);
  };
  const fetches = [];
  const store = new Map();
  const state = {
    hash: '', search: '', routes: scenario.routes || {},
    clock, fetches, el, elements,
    // set by the scenario to fail a route or slow it down
    hooks: scenario.hooks || {},
  };

  async function fakeFetch(url, opts = {}) {
    const method = (opts.method || 'GET').toUpperCase();
    // HEADERS RECORDED. What the page SENDS is the property; what the source
    // CONTAINS is not. A source-literal check for the session header name was
    // satisfied by STORE_KEY, which happens to hold the identical string, so a
    // console that authenticated under the wrong header name entirely was
    // invisible to three thousand tests.
    fetches.push({ url, method, at: clock.now, headers: opts.headers || {} });
    const hook = state.hooks.beforeResponse;
    if (hook) await hook(state, url, method);
    const handler = state.routes[`${method} ${url.split('?')[0]}`] || state.routes[url] ||
                    state.routes[`${method} ${url}`];
    let out = typeof handler === 'function' ? await handler(url, opts, state) : handler;
    if (out === undefined) out = { status: 200, body: {} };
    const status = out.status === undefined ? 200 : out.status;
    const text = typeof out.body === 'string' ? out.body : JSON.stringify(out.body ?? {});
    return {
      ok: status >= 200 && status < 300,
      status,
      async text() { return text; },
      async json() { return JSON.parse(text); },
    };
  }

  const document = {
    hidden: false,
    getElementById: id => (elements.has(id) ? elements.get(id) : el(id)),
    querySelectorAll: () => [],
    querySelector: () => null,
    createElement: () => makeElement('created'),
    addEventListener(type, fn) { (this._l ||= {})[type] = fn; },
    _l: {},
  };
  const location = {
    get search() { return state.search; },
    get hash() { return state.hash; },
    set hash(v) { state.hash = v; if (sandbox.__onhashchange) sandbox.__onhashchange(); },
    pathname: '/',
  };
  const sandbox = {
    console, URLSearchParams, JSON, Math, Set, Map, Promise, Object, Array, String,
    Number, Boolean, Date, isNaN, parseInt, parseFloat, encodeURIComponent,
    decodeURIComponent, TypeError, Error, RangeError,
    document, location, fetch: fakeFetch,
    setTimeout: (fn, d) => clock.setTimeout(fn, d),
    clearTimeout: id => clock.clearTimeout(id),
    history: { replaceState() {} },
    sessionStorage: {
      getItem: k => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: k => store.delete(k),
    },
    window: { addEventListener(type, fn) { if (type === 'hashchange') sandbox.__onhashchange = fn; } },
    confirm: () => true,
    MouseEvent: class {},
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  state.sandbox = sandbox;
  state.session = store;

  // The page exchanges a launch token at boot; give it one unless the scenario
  // wants the no-session path.
  if (scenario.storedSecret !== null) store.set('andyur-console-session',
                                                scenario.storedSecret || 'test-secret');
  state.hash = scenario.hash || '#/agents';

  // A page that THROWS is a failure of the page, not of this harness, so the
  // throw is recorded and the scenario continues to its assertions. Without
  // this, a defect that crashes the script (an unguarded decodeURIComponent on
  // a truncated escape, say) took the whole run down and the named check that
  // exists for it never reported anything.
  state.crashes = [];
  activeState = state;
  const guard = fn => (...a) => {
    try {
      const out = fn(...a);
      return out && typeof out.catch === 'function'
        ? out.catch(e => { state.crashes.push(String(e)); }) : out;
    } catch (e) { state.crashes.push(String(e)); }
  };
  sandbox.setTimeout = (fn, d) => clock.setTimeout(guard(fn), d);
  try {
    vm.runInContext(fs.readFileSync(APP_JS, 'utf8'), sandbox, { filename: 'app.js' });
  } catch (e) {
    state.crashes.push(String(e));
  }
  for (const type of Object.keys(document._l)) {
    document._l[type] = guard(document._l[type]);
  }
  if (sandbox.__onhashchange) sandbox.__onhashchange = guard(sandbox.__onhashchange);
  await drain();
  await drain();
  return state;
}

// ---- the assertions ---------------------------------------------------------
const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok, detail });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`);
}
export function report() {
  const failed = results.filter(r => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} page checks passed`);
  return failed.length === 0;
}
// Fire the page's own delegated click handler for a data-action, the way a
// real click reaches it: app.js binds ONE listener per event type and lets the
// nearest data-action decide, so this is the real path and not a back door
// into a function the page never exposes (its ACTIONS table is a `const` and
// is deliberately not reachable from outside the script).
export async function click(state, action, data = {}) {
  const target = { dataset: { action, ...data }, tagName: 'BUTTON' };
  target.closest = sel => (sel === '[data-action]' ? target : null);
  const listener = state.sandbox.document._l.click;
  if (!listener) throw new Error('the page registered no click listener');
  listener({ target, preventDefault() {} });
  await drain();
  await drain();
  await drain();
}

// The page's own source, for the few assertions that are about what the script
// READS rather than what it does.
export function readAppJs() { return fs.readFileSync(APP_JS, 'utf8'); }

export { check, drain };
