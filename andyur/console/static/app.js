'use strict';
// The console page. Everything here renders what the control plane returns
// and never decides authority: the server enforces every owner/admin gate no
// matter what this script shows or hides. No inline script or handlers exist
// (the CSP forbids them); every click is delegated from data-action
// attributes, and every page is a hash route so a run or a chain is linkable.

// ---- session ----------------------------------------------------------------
// The launch URL carries a single-use launch token. It is exchanged exactly
// once at POST /session for the session secret. The secret lives in this
// variable and in the tab's sessionStorage (same origin only, cleared when
// the tab closes) so a reload does not strand the operator on a spent link.
const SESSION_HEADER = 'andyur-console-session';
const STORE_KEY = 'andyur-console-session';
let SECRET = null;
const LAUNCH = new URLSearchParams(location.search).get('launch') || '';

function scrubUrl(){
  // Keep the launch token out of the address bar and history once the BFF has
  // answered for it (spent or refused). A network failure leaves it in place
  // so a retry can still spend it.
  try { if (location.search) history.replaceState({}, '', location.pathname + location.hash); } catch (e) {}
}
function store(v){ try { v === null ? sessionStorage.removeItem(STORE_KEY) : sessionStorage.setItem(STORE_KEY, v); } catch (e) {} }
function stored(){ try { return sessionStorage.getItem(STORE_KEY); } catch (e) { return null; } }

// Who this console session is, from GET /me. RENDERING ONLY: the server
// enforces every admin/owner gate no matter what this object says.
let ME = {user_auth:false, sub:null, admin:false};
let CP = {control_plane: '', trace_ui: ''};
let CP_TEXT = '';

function $(id){ return document.getElementById(id); }

async function api(method, path, body){
  let r;
  try {
    r = await fetch('/api'+path, {
      method,
      headers: {[SESSION_HEADER]: SECRET, 'content-type':'application/json'},
      body: body ? JSON.stringify(body) : undefined
    });
  } catch (e) {
    // The console process itself did not answer. Give that the shape every
    // caller expects, with the status the header line reads as an outage
    // rather than as an answer.
    throw {status: 0, reason: 'console_unreachable', detail: 'the console did not answer'};
  }
  return unwrap(r);
}

async function unwrap(r){
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch(e){ data = text; }
  if (!r.ok){
    // The control plane's `detail` is sometimes an object or a list.
    let detail = data && data.detail !== undefined ? data.detail
               : (typeof data === 'string' ? data : '');
    if (detail !== null && typeof detail === 'object') detail = JSON.stringify(detail);
    throw {status:r.status, detail: detail || r.statusText, reason: data && data.reason};
  }
  return data;
}

async function openSession(){
  if (LAUNCH){
    const r = await fetch('/session', {
      method: 'POST',
      headers: {'content-type':'application/json'},
      body: JSON.stringify({launch: LAUNCH})
    });
    scrubUrl();
    let data;
    try { data = await unwrap(r); }
    catch (e) {
      // the same tab re-opened its own spent link: its session is still good
      if (e.reason === 'launch_spent' && stored()) { SECRET = stored(); return; }
      throw e;
    }
    SECRET = data.secret;
    store(SECRET);
    return;
  }
  const s = stored();
  if (!s) throw {status: 0, reason: 'no_session',
                 detail: 'This tab has no console session and the page was opened without a launch link.'};
  SECRET = s;
}

// The page cannot work without a session; say why and how to get one instead
// of letting every call fail with its own toast. The sentence is the server's.
function blocked(e){
  $('view').innerHTML = `<div class="card"><div class="blocked">
    <div>${esc(e.detail || 'No console session.')}</div>
    <div class="muted">Start the console and open the link it prints:</div>
    <pre>andyur console</pre></div></div>`;
}

function sessionDead(e){
  // The BFF says bad_session only for its own secret check: the console was
  // restarted and this tab's stored secret is from the old process.
  if (e && e.reason === 'bad_session'){ store(null); SECRET = null; blocked(e); return true; }
  return false;
}

function toast(msg, kind){
  const box = $('toast');
  // Every action's result -- created, deleted, run failed -- arrives only here.
  // Without a live region a screen reader is told none of them, so the operator
  // who most needs the confirmation is the one who never gets it.
  if (!box.dataset.live){ box.setAttribute('role', 'status'); box.setAttribute('aria-live', 'polite'); box.dataset.live = '1'; }
  while (box.children.length >= 5) box.firstChild.remove();
  const el = document.createElement('div');
  el.className = 't'+(kind?' '+kind:'');
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(()=>el.remove(), 4200);
}
// Escape for HTML text and quoted-attribute contexts: server data (agent
// names, descriptions, manifest fields, transcript text) is interpolated into
// markup and data-* attributes, so quotes and backticks are included
// independent of any server-side validation.
function esc(s){ return String(s==null?'':s).replace(/[&<>"'`]/g, c=>(
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'}[c])); }
function short(id){ return id ? String(id).slice(0, 12) + (String(id).length > 12 ? '…' : '') : ''; }
function fmtJson(v){ try { return typeof v === 'string' ? v : JSON.stringify(v, null, 2); } catch (e) { return String(v); } }
function tryParse(s){ try { return JSON.parse(s); } catch (e) { return null; } }

// The header line says when the control plane stopped answering, and stays
// until it answers again; toasts are for actions, not for a background poll.
// Only a transport-class failure earns that sentence: a 404 from an older
// server or a 403 on halt is an ANSWER, and docs/observability.md promises
// this line means upstream_unreachable / upstream_timeout.
//
// AND IT NAMES WHAT IS DOWN. Six different causes reach this line and five of
// them are not the control plane: the console process itself did not answer,
// SPIRE is not serving the operator an SVID, the IdP refused a refresh. Saying
// "control plane unreachable" for all six sends the operator to the wrong
// machine. The reason the BFF already returns is the answer, so use it.
const UNREACHABLE = new Set([0, 502, 503, 504]);
const DOWN_SUBJECT = {
  console_unreachable: 'the console process is not answering',
  identity_unavailable: 'no operator identity (is the SPIRE agent serving SVIDs?)',
  idp_error: 'the IdP refused to refresh this session',
  upstream_unreachable: 'control plane unreachable',
  upstream_timeout: 'the control plane did not answer in time',
  upstream_protocol_error: 'the control plane answered badly',
  upstream_too_large: 'the control plane sent more than the console will hold',
};
function setStatus(err){
  if (err && !UNREACHABLE.has(err.status)) return;
  if (!err){ delete $('cp').dataset.since; $('cp').textContent = CP_TEXT; return; }
  if (!$('cp').dataset.since) $('cp').dataset.since = new Date().toLocaleTimeString();
  const subject = DOWN_SUBJECT[err.reason] || 'control plane unreachable';
  $('cp').textContent = `${subject} since ${$('cp').dataset.since} (${err.reason || err.status || err})`;
}
function clearStatus(){ setStatus(null); }

function traceLink(traceId){
  if (!traceId) return '<span class="muted">none</span>';
  const t = `<code class="mono">${esc(short(traceId))}</code>`;
  if (!CP.trace_ui) return t;
  return `${t} <a href="${esc(CP.trace_ui.replace('{trace_id}', traceId))}" target="_blank" rel="noopener">open trace</a>`;
}
function kv(k, v, mono){ return `<div><div class="k">${esc(k)}</div><div class="v${mono?' mono':''}">${v}</div></div>`; }

// ---- routing ------------------------------------------------------------------
// #/agents[/<name>]  #/catalog[/<id>]  #/runs[/<id>]  #/workflows/<id>
// #/launch/<agent>  #/workers
let PAGE = null;           // the current page object {name, timer, ...}
function route(){
  // A hand-typed or truncated escape (`#/runs/%`) throws out of
  // decodeURIComponent. The raw segment is a better answer than a router that
  // stops and leaves the page frozen on whatever was there before.
  const parts = location.hash.replace(/^#\/?/, '').split('/').map(p => {
    try { return decodeURIComponent(p); } catch (e) { return p; }
  });
  return {name: parts[0] || 'agents', arg: parts[1] || null};
}
function go(hash){ location.hash = hash; }

function stopPage(){
  if (PAGE && PAGE.timer) clearTimeout(PAGE.timer);
  PAGE = null;
}
// A page's background refresh: one call at a time, doubling backoff to 60 s
// while it fails, reset by the next success. Never toasts.
//
// `first` overrides the delay for THIS arming only. Every re-arm reads
// `page.base`, so the visibility catch-up (which wants one immediate call)
// cannot turn its own delay into the steady interval and flood the BFF.
// A page function must never call `schedule` from inside its own tick: that
// leaves two live timers per tick. Split the shell from the loader instead.
function schedule(page, fn, base, first){
  page.failures = page.failures || 0;
  page.tick = fn; page.base = base;
  // ONE CHAIN PER PAGE, enforced by a generation counter rather than by
  // clearTimeout. clearTimeout cannot stop a tick that has ALREADY FIRED and is
  // suspended at its own `await fn()`: its handle is spent, so the visibility
  // catch-up clears nothing, arms a fresh chain, and the in-flight callback
  // then arms its own on the way out. Two chains, each re-arming forever, one
  // more per hide/show that lands during a fetch. `once()` stops concurrent
  // FETCHES; it does not stop concurrent chains.
  //
  // The guard is on the RE-ARM only, deliberately. Guarding the tick's entry as
  // well is redundant for the chain count and worse on its own: a superseded
  // tick that returns early is the visibility catch-up's own fetch being
  // dropped, so the operator's tab comes back to a stale page.
  const gen = (page.gen = (page.gen || 0) + 1);
  page.timer = setTimeout(async () => {
    if (PAGE !== page) return;
    if (!document.hidden){
      try { await fn(); page.failures = 0; clearStatus(); }
      catch (e) { if (sessionDead(e)) return; page.failures += 1; setStatus(e); }
    }
    if (PAGE === page && page.gen === gen && !page.stopped) schedule(page, fn, base);
  }, first !== undefined ? first : Math.min(base * Math.pow(2, page.failures), 60000));
}
// A run that has ended has nothing further to say; asking forever is a request
// storm with no reader.
function stopTicking(page){
  // `stopped` is what the re-arm consults, so a tick already suspended inside
  // its own await does not re-arm on the way out; clearing the handle stops one
  // that has not fired yet.
  page.stopped = true;
  if (page.timer) clearTimeout(page.timer);
  page.timer = null;
}
// One in-flight load per page. The tick, a click and the visibility catch-up
// all fire independently; two of them appending to the same list is the bug.
// A skipped call is not lost work: the next tick makes it.
async function once(page, fn){
  if (page.busy) return;
  page.busy = true;
  try { return await fn(); } finally { page.busy = false; }
}

async function render(){
  if (!SECRET) return;
  stopPage();
  const r = route();
  const tab = r.name === 'launch' ? 'agents' : r.name === 'workflows' ? 'runs' : r.name;
  document.querySelectorAll('.tab').forEach(x => {
    const on = x.dataset.tab === tab;
    x.classList.toggle('active', on);
    // Colour alone does not reach a screen reader.
    if (on) x.setAttribute('aria-current', 'page'); else x.removeAttribute('aria-current');
  });
  // Every page that awaits before it paints would otherwise leave the PREVIOUS
  // page on screen under the new URL, and leave it there for good if the load
  // fails.
  $('view').innerHTML = '<div class="card"><div class="empty">Loading…</div></div>';
  const page = {name: r.name, arg: r.arg};
  PAGE = page;
  try {
    if (r.name === 'agents') await agentsPage(page);
    else if (r.name === 'catalog') await catalogPage(page);
    else if (r.name === 'runs' && r.arg) await runPage(page);
    else if (r.name === 'runs') await runsPage(page);
    else if (r.name === 'workflows' && r.arg) await flowPage(page);
    else if (r.name === 'launch' && r.arg) await launchPage(page);
    else if (r.name === 'workers') await workersPage(page);
    else go('#/agents');
    clearStatus();
  } catch (e) {
    if (sessionDead(e)) return;
    if (PAGE === page) $('view').innerHTML =
      `<div class="card"><div class="empty">${esc(e.detail || e.status || e)}</div></div>`;
    toast('load failed: '+(e.detail||e), 'err'); setStatus(e);
  }
}
async function refresh(){ await render(); }

// ---- Agents -------------------------------------------------------------------
function adminOwnerView(){ return ME.user_auth && ME.admin; }

async function agentsPage(page){
  page.ownerFilter = page.ownerFilter || '';
  $('view').innerHTML = `<div class="cols">
    <div class="card"><h2>Agents<span class="spacer"></span><span class="muted" id="listCount"></span></h2><div id="list"></div></div>
    <div>
      <div class="card" id="detailCard" hidden><h2><span id="detailTitle">Agent</span><span class="spacer"></span>
        <button data-action="close-detail" class="close" aria-label="close">&#x2715;</button></h2><div id="detail" class="body"></div></div>
      <div class="card"><h2>Create agent<span class="spacer"></span><span class="muted" id="createFrom"></span></h2>
        <form class="create body" id="createForm">
          <div class="row2">
            <div><label for="c_name">name</label><input id="c_name" placeholder="e.g. sentinel" required></div>
            <div><label for="c_reg">registry agent id (optional)</label><input id="c_reg" placeholder="agt_… (ceiling comes from the manifest)"></div>
          </div>
          <label for="c_desc">description</label><input id="c_desc" placeholder="what this agent is for">
          <label for="c_scope">scope <span class="muted">(ignored when a registry id is set)</span></label>
          <input id="c_scope" placeholder="comma,separated,entity,types">
          <div><button class="primary" type="submit">Create</button></div>
        </form></div>
    </div></div>`;
  $('createForm').addEventListener('submit', ev => { ev.preventDefault(); doCreate(); });
  page.lastList = '';
  const load = () => loadAgents(page);
  await load();
  if (page.arg) await showAgent(page, page.arg);
  schedule(page, load, 4000);
}

async function loadAgents(page){
  return once(page, () => loadAgentsOnce(page));
}
async function loadAgentsOnce(page){
  const all = await api('GET','/agents');
  if (PAGE !== page) return;
  const owners = [...new Set(all.map(a=>a.owner).filter(Boolean))].sort();
  const agents = (adminOwnerView() && page.ownerFilter) ? all.filter(a=>a.owner===page.ownerFilter) : all;
  $('listCount').textContent = agents.length+' agents';
  const filter = (adminOwnerView() && owners.length)
    ? `<div class="filter"><label for="ownerFilter">owner</label>
         <select id="ownerFilter" data-action="owner-filter">
           <option value="">all (${owners.length})</option>
           ${owners.map(o=>`<option value="${esc(o)}" ${o===page.ownerFilter?'selected':''}>${esc(o)}</option>`).join('')}
         </select></div>` : '';
  let html;
  if (!agents.length){
    html = filter + '<div class="empty">No agents yet. Create one below, or from the Catalog.</div>';
  } else {
    const ownerCol = adminOwnerView();
    const rows = agents.sort((a,b)=>a.name.localeCompare(b.name)).map(a=>{
      const st = esc(a.state), n = esc(a.name);
      const paused = a.paused ? 'paused' : st;
      const mine = !ME.user_auth || a.owner===ME.sub;
      // A clickable <tr> announces itself as a row, not as a link. The name
      // cell carries the real anchor (focusable, announced, openable in a new
      // tab); the row click is the mouse convenience on top of it.
      return `<tr class="row ${a.name===page.arg?'sel':''}" data-action="go" data-href="#/agents/${encodeURIComponent(a.name)}">
        <td class="name"><a href="#/agents/${encodeURIComponent(a.name)}">${n}</a></td>
        ${ownerCol?`<td class="muted">${esc(a.owner||'')}</td>`:''}
        <td><span class="pill ${paused}">${a.paused?'paused':st}</span></td>
        <td class="muted">${esc(a.description||'')}</td>
        <td><div class="actions">
          ${mine?`<button data-action="go" data-href="#/launch/${encodeURIComponent(a.name)}">Launch</button>`:''}
          ${a.paused?`<button data-action="act" data-name="${n}" data-verb="resume">Resume</button>`
                    :`<button data-action="act" data-name="${n}" data-verb="pause">Pause</button>`}
          <button class="danger" data-action="del" data-name="${n}">Delete</button>
        </div></td></tr>`;
    }).join('');
    html = filter + `<table><thead><tr><th>Name</th>${ownerCol?'<th>Owner</th>':''}<th>State</th><th>Description</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  }
  // Skip the DOM rebuild when nothing changed: a rebuild every tick destroys
  // text selection and hover state for no reason.
  if (page.lastList !== html){ $('list').innerHTML = html; page.lastList = html; }
}

async function showAgent(page, name){
  const a = await api('GET','/agents/'+encodeURIComponent(name));
  if (PAGE !== page) return;
  const runs = (a.recent_runs||[]).map(r=>`<tr class="row" data-action="go" data-href="#/runs/${esc(r.id)}">
      <td><a href="#/runs/${encodeURIComponent(r.id)}"><code class="mono">${esc(short(r.id))}</code></a></td><td>${esc(r.run_type)}</td>
      <td><span class="pill ${esc(r.state)}">${esc(r.state)}</span></td><td class="muted">${esc(r.reason||'')}</td>
      ${ME.admin && r.workflow_id ? `<td><div class="actions">
        <button data-action="halt-wf" data-id="${esc(r.workflow_id)}" data-verb="halt">Halt wf</button>
        <button data-action="halt-wf" data-id="${esc(r.workflow_id)}" data-verb="unhalt">Unhalt</button></div></td>` : '<td></td>'}</tr>`).join('')
    || `<tr><td colspan="5" class="muted">no runs yet</td></tr>`;
  const prof = a.profile;
  const scope = (prof && prof.scope ? prof.scope.split(',').filter(Boolean) : []);
  const n = esc(name);
  const mine = !ME.user_auth || a.owner===ME.sub;
  $('detailTitle').textContent = 'Agent · '+name;
  $('detail').innerHTML = `
    <div><span class="pill ${a.paused?'paused':esc(a.state)}">${a.paused?'paused':esc(a.state)}</span>
      ${a.registry_agent_id?`<span class="pill">from <a href="#/catalog/${encodeURIComponent(a.registry_agent_id)}">${esc(a.registry_agent_id)}</a></span>`:''}</div>
    <div class="k">Description</div><div>${esc(a.description)||'<span class="muted">none</span>'}</div>
    ${prof?`<div class="k">SPIFFE id</div><div><code class="mono">${esc(prof.spiffe_id||'')}</code></div>
            <div class="k">Scope</div><div class="chips">${scope.map(s=>`<span class="chip">${esc(s.trim())}</span>`).join('')||'<span class="muted">none</span>'}</div>`
          :'<div class="k">Profile</div><div class="muted">missing (corrupt record)</div>'}
    <div class="k">Recent runs <a href="#/runs" class="muted">(all runs)</a></div>
    <table><tbody>${runs}</tbody></table>
    <div class="k">Lifecycle</div>
    <div class="actions lifecycle">
      ${mine ? `<button class="primary" data-action="go" data-href="#/launch/${encodeURIComponent(name)}">Launch a run</button>`
             : `<span class="muted">owned by ${esc(a.owner||'')}; only the owner launches</span>`}
      ${a.paused?`<button data-action="act" data-name="${n}" data-verb="resume">Resume</button>`
                :`<button data-action="act" data-name="${n}" data-verb="pause">Pause</button>`}
      <button class="danger" data-action="del" data-name="${n}">Delete</button>
    </div>`;
  $('detailCard').hidden = false;
}

async function act(name, verb){
  try{
    await api('POST','/agents/'+encodeURIComponent(name)+'/'+verb, {});
    toast(verb+' → '+name, 'ok');
    await render();
  }catch(e){ toast(verb+' failed: '+(e.detail||e), 'err'); }
}
async function del(name){
  if (!confirm('Delete agent "'+name+'" and everything it owns?')) return;
  try{
    await api('DELETE','/agents/'+encodeURIComponent(name)+'?force=true');
    toast('deleted '+name, 'ok');
    go('#/agents');
    await render();
  }catch(e){ toast('delete failed: '+(e.detail||e), 'err'); }
}
async function doCreate(){
  const body = {name:val('c_name'), description:val('c_desc'), scope:val('c_scope')};
  const reg = val('c_reg'); if (reg) body.registry_agent_id = reg;
  try{
    await api('POST','/agents', body);
    toast('created '+body.name, 'ok');
    go('#/agents/'+encodeURIComponent(body.name));
  }catch(e){ toast('create failed: '+(e.detail||e), 'err'); }
}
function val(id){ return $(id).value.trim(); }

// ---- Catalog -------------------------------------------------------------------
async function catalogPage(page){
  $('view').innerHTML = `<div class="cols">
    <div class="card"><h2>Registry catalog<span class="spacer"></span><span class="muted" id="listCount"></span></h2><div id="list"></div></div>
    <div class="card" id="detailCard" hidden><h2><span id="detailTitle">Manifest</span><span class="spacer"></span>
      <button data-action="close-detail" class="close" aria-label="close">&#x2715;</button></h2><div id="detail" class="body"></div></div></div>`;
  const data = await api('GET','/v1/registry/agents');
  if (PAGE !== page) return;
  const agents = data.agents||[];
  $('listCount').textContent = agents.length+' definitions';
  if (!agents.length){
    $('list').innerHTML = '<div class="empty">The registry is empty (set ANDYUR_AGENT_REGISTRY_DIR or governed mode).</div>';
  } else {
    $('list').innerHTML = `<table><thead><tr><th>Name</th><th>Agent id</th></tr></thead><tbody>${
      agents.sort((a,b)=>a.name.localeCompare(b.name)).map(a=>
        `<tr class="row ${a.agent_id===page.arg?'sel':''}" data-action="go" data-href="#/catalog/${encodeURIComponent(a.agent_id)}">
          <td class="name"><a href="#/catalog/${encodeURIComponent(a.agent_id)}">${esc(a.name)}</a></td>
          <td><code class="mono">${esc(a.agent_id)}</code></td></tr>`).join('')}</tbody></table>`;
  }
  if (page.arg) await showManifest(page, page.arg);
}

async function showManifest(page, id){
  const m = await api('GET','/v1/registry/agents/'+encodeURIComponent(id)+'/resolve');
  if (PAGE !== page) return;
  const tools = (m.tools||[]).map(t=>`<span class="chip">${esc(t.name||t.resource_id||'tool')}${t.mcp_tools?' · '+esc(t.mcp_tools.join(', ')):''}</span>`).join('') || '<span class="muted">none</span>';
  const acts = (m.ceiling&&m.ceiling.actions||[]).map(a=>`<span class="chip">${esc(a)}</span>`).join('') || '<span class="muted">unrestricted</span>';
  const rt = m.runtime;
  $('detailTitle').textContent = 'Manifest · '+m.name;
  $('detail').innerHTML = `
    <div class="kv">
      ${kv('agent id', esc(m.agent_id), true)}
      ${kv('registry', m.registry_digest ? 'governed · signed snapshot' : 'manifest mode · no digest')}
      ${kv('registry digest', m.registry_digest ? esc(short(m.registry_digest)) : '<span class="muted">none</span>', true)}
      ${kv('interface', rt && rt.interface_version ? esc(rt.interface_version) : 'native', true)}
      ${kv('image', rt && rt.image_ref ? esc(rt.image_ref) + (rt.image_digest ? ' @ ' + esc(short(rt.image_digest)) : '') : '<span class="muted">none</span>', true)}
      ${kv('command', rt && rt.command ? esc(rt.command.join(' ')) : '<span class="muted">none</span>', true)}
      ${kv('granted model', m.model ? esc(m.model) : '<span class="muted">default</span>')}
    </div>
    <div class="k">Tools</div><div class="chips">${tools}</div>
    <div class="k">Ceiling · actions</div><div class="chips">${acts}</div>
    <div class="k">Instructions</div><pre>${esc(m.instructions||'')}</pre>
    <div class="actions lifecycle"><button class="primary" data-action="prefill" data-id="${esc(m.agent_id)}" data-name="${esc(m.name)}">Create instance from this manifest</button></div>`;
  $('detailCard').hidden = false;
}
function prefillFromManifest(id, name){
  go('#/agents');
  render().then(() => {
    $('c_reg').value = id; $('c_name').value = name;
    $('createFrom').textContent = 'from '+id;
    $('c_name').focus();
    toast('filled the create form; set a name and Create', 'ok');
  });
}

// ---- Launch --------------------------------------------------------------------
async function launchPage(page){
  const name = page.arg;
  const a = await api('GET','/agents/'+encodeURIComponent(name));
  if (PAGE !== page) return;
  let rt = null;
  if (a.registry_agent_id){
    try { rt = (await api('GET','/v1/registry/agents/'+encodeURIComponent(a.registry_agent_id)+'/resolve')).runtime; } catch (e) {}
  }
  const scope = (a.profile && a.profile.scope ? a.profile.scope.split(',').filter(Boolean) : []);
  const proto = rt && rt.interface_version ? rt.interface_version : 'native';
  $('view').innerHTML = `<div class="cols">
    <div class="card"><h2>Launch a run<span class="spacer"></span><span class="muted">${esc(name)} · ${esc(proto)}</span></h2>
      <form class="launch body" id="launchForm">
        <div><label for="l_reason">reason</label><input id="l_reason" value="triggered from the console"></div>
        <div><label for="l_type">run type</label>
          <select id="l_type"><option value="work">work (headless)</option><option value="conversation">conversation (live turns)</option></select></div>
        <div><label for="l_input">input <span class="muted">· JSON or text; the manifest bounds it and the control plane refuses over its cap by name</span></label>
          <textarea id="l_input" placeholder='{"ticket": 4471}'></textarea></div>
        <div><label id="l_scope_label">scope <span class="muted">· the scopes this agent declares. The control plane asks its policy decision point for each one and grants what it permits, so a run can end with fewer than you tick; the run page shows what was actually granted.</span></label>
          <div class="chips" id="l_scope" role="group" aria-labelledby="l_scope_label">${scope.map(s=>`<button type="button" class="chip on" aria-pressed="true" data-action="toggle-chip" data-scope="${esc(s.trim())}">${esc(s.trim())}</button>`).join('')||'<span class="muted">no scope declared</span>'}</div></div>
        <div><label for="l_pin">subject context pin <span class="muted">· optional, key=value per line</span></label>
          <textarea id="l_pin" placeholder="tenant=acme"></textarea></div>
        <div id="l_error"></div>
        <div class="actions"><button class="primary" type="submit">Start run</button>
          <button type="button" data-action="go" data-href="#/agents/${encodeURIComponent(name)}">Cancel</button></div>
      </form></div>
    <div class="card"><h2>What happens</h2><div class="body">
      <div class="note">POST /agents/${esc(name)}/trigger. Owner only; an admin cannot start a run as another owner. A run already live on this agent answers 409; input the manifest refuses answers 422; both are shown here by the server's own words.</div>
      <div class="note mt8">After 201 this page opens the run and follows it.</div></div></div></div>`;
  $('launchForm').addEventListener('submit', ev => { ev.preventDefault(); doLaunch(name, scope); });
}
async function doLaunch(name, declared){
  const body = {reason: val('l_reason') || 'triggered from the console', run_type: $('l_type').value};
  const raw = $('l_input').value.trim();
  if (raw){ const j = tryParse(raw); body.input = j === null ? raw : j; }
  const on = [...document.querySelectorAll('#l_scope .chip.on')].map(c=>c.dataset.scope);
  if (declared.length && on.length !== declared.length) body.scope = on;
  const pin = {};
  $('l_pin').value.split('\n').map(l=>l.trim()).filter(Boolean).forEach(l => { const i = l.indexOf('='); if (i > 0) pin[l.slice(0,i).trim()] = l.slice(i+1).trim(); });
  if (Object.keys(pin).length) body.subject_context = pin;
  $('l_error').innerHTML = '';
  try{
    const r = await api('POST','/agents/'+encodeURIComponent(name)+'/trigger', body);
    toast('run started', 'ok');
    go('#/runs/'+encodeURIComponent(r.run_id));
  }catch(e){
    $('l_error').innerHTML = `<div class="note err"><b>${esc(e.status)}</b> · ${esc(e.detail||e)}</div>`;
  }
}

// ---- Runs list -------------------------------------------------------------------
async function runsPage(page){
  page.filters = page.filters || {agent: '', state: ''};
  page.pages = [];        // the `next` cursors walked so far
  $('view').innerHTML = `<div class="card"><h2>Runs<span class="spacer"></span><span class="muted" id="listCount"></span></h2>
    <div class="filter">
      <label for="f_agent">agent</label><select id="f_agent" data-action="runs-filter"><option value="">all</option></select>
      <label for="f_state">state</label><select id="f_state" data-action="runs-filter"><option value="">any</option>
        ${['pending','running','done','failed','cancelled'].map(s=>`<option ${page.filters.state===s?'selected':''}>${s}</option>`).join('')}</select>
      <span class="muted">${adminOwnerView() ? 'every owner' : 'your agents'} · newest first</span></div>
    <div id="list"></div>
    <div class="body actions"><button data-action="runs-older" id="older" hidden>Older</button></div></div>`;
  try {
    const agents = await api('GET','/agents');
    $('f_agent').innerHTML = '<option value="">all</option>' + agents.map(a=>`<option ${a.name===page.filters.agent?'selected':''}>${esc(a.name)}</option>`).join('');
  } catch (e) {}
  const load = () => loadRuns(page, null);
  await load();
  schedule(page, load, 6000);
}

// `page.pages` is the whole list: one entry per keyset page walked, in order.
// The 6 s tick reloads only the HEAD page and leaves the walked ones alone, so
// a refresh cannot throw away what the operator paged back to, and the DOM is
// rebuilt from that one array so it cannot drift from it.
async function loadRuns(page, before){
  return once(page, async () => {
    const q = new URLSearchParams({limit: '50'});
    if (page.filters.agent) q.set('agent', page.filters.agent);
    if (page.filters.state) q.set('state', page.filters.state);
    if (before) q.set('before', before);
    const data = await api('GET','/runs?'+q.toString());
    if (PAGE !== page) return;
    if (!before) page.pages[0] = {before: null, runs: data.runs, next: data.next};
    else if (!page.pages.some(p => p.before === before)) page.pages.push({before, runs: data.runs, next: data.next});
    renderRuns(page);
  });
}
function renderRuns(page){
  // Runs created while the operator was paging push older rows across the page
  // boundary, so the same run can arrive on two pages. The id decides, and the
  // newest page holding it wins.
  const seen = new Set(), runs = [];
  for (const p of page.pages) for (const r of (p.runs || [])){
    if (seen.has(r.id)) continue;
    seen.add(r.id); runs.push(r);
  }
  const rows = runs.map(r => `<tr class="row" data-action="go" data-href="#/runs/${esc(r.id)}">
      <td class="name mono"><a href="#/runs/${encodeURIComponent(r.id)}">${esc(short(r.id))}</a></td>
      <td>${esc(r.agent)}</td><td class="mono">${esc(protoOf(r))}</td>
      <td><span class="pill ${esc(r.state)}">${esc(r.state)}</span></td><td class="muted">${esc(r.reason||'')}</td>
      <td class="muted">${esc((r.created_at||'').replace('T',' ').slice(0,19))}</td></tr>`).join('');
  $('list').innerHTML = rows
    ? `<table><thead><tr><th>run</th><th>agent</th><th>protocol</th><th>state</th><th>reason</th><th>created</th></tr></thead><tbody>${rows}</tbody></table>`
    : '<div class="empty">No runs match.</div>';
  $('listCount').textContent = runs.length + ' shown';
  const last = page.pages[page.pages.length - 1];
  $('older').hidden = !(last && last.next);
}
function olderCursor(page){
  const last = page.pages && page.pages[page.pages.length - 1];
  return last ? last.next : null;
}
// The list row carries `interface_version` (the list projection has no
// runtime_resolution: a page of exec/v1 summaries would exceed the response
// cap); the run row carries the full resolution. One reader for both.
function protoOf(r){
  const rr = typeof r.runtime_resolution === 'string' ? tryParse(r.runtime_resolution) : r.runtime_resolution;
  const iv = r.interface_version || (rr && rr.interface_version);
  return (iv || 'native') + ' · ' + (r.run_type || 'work');
}

// ---- Run page ----------------------------------------------------------------
const TERMINAL = new Set(['done', 'failed', 'cancelled']);
function isExec(r){ return protoOf(r).startsWith('exec/v1'); }

async function runPage(page){
  const id = page.arg;
  const r = await api('GET','/runs/'+encodeURIComponent(id));
  if (PAGE !== page) return;
  page.run = r;
  page.cursor = 0; page.events = []; page.exchanges = null;
  const mode = r.run_type === 'conversation' ? 'conversation' : isExec(r) ? 'exec' : 'work';
  page.mode = mode;
  $('view').innerHTML = `
    <div class="card"><h2>Run<span class="spacer"></span>
      <span class="crumbs"><a href="#/agents/${encodeURIComponent(r.agent)}">${esc(r.agent)}</a> · <code class="mono">${esc(id)}</code></span></h2>
      <div class="body kv" id="runHeader"></div>
      <div class="body pt0"><span class="eyebrow">reason</span> ${esc(r.reason||'')}</div></div>
    <div class="card mb"><h2>Story<span class="spacer"></span><span class="muted">what happened, and what Andyur decided</span></h2>
      <div class="body kv" id="storyPanel"></div></div>
    <div class="cols-wide">
      <div class="card"><h2 id="followTitle">Follow</h2><div id="follow"></div></div>
      <div>
        <div class="card mb"><h2>Input</h2><div class="body"><pre>${esc(r.input ? fmtJson(tryParse(r.input) ?? r.input) : 'none')}</pre></div></div>
        <div class="card mb"><h2>Runtime</h2><div class="body kv" id="runtimeCard"></div></div>
        <div class="card"><h2>Exchanges<span class="spacer"></span><span class="muted" id="exchCount"></span></h2><div id="exchanges"></div></div>
      </div></div>`;
  renderRunHeader(page);
  renderRuntime(page);
  await loadAction(page);
  renderStory(page);
  await followTick(page);
  // followTick calls stopTicking once a terminal run's exchanges are in, but
  // arming unconditionally here re-armed anyway: opening an ALREADY-FINISHED
  // run still issued one stray poll three seconds later, because schedule only
  // consults page.stopped on the RE-arm.
  if (!page.stopped) schedule(page, () => followTick(page), mode === 'conversation' ? 2000 : 3000);
}
// WHO, AND SAYS WHO. The platform carries provenance beside the subject
// everywhere it goes -- runtoken.py's own words are that `sub` alone answers
// "who" and a resource server also needs "says who" -- and the console was
// throwing that away at the last hop, rendering a bare name.
//
// That is not cosmetic. An `asserted` subject means an authenticated operator
// SAID this run acts for Alice; nobody authenticated Alice. Displaying that
// identically to an IdP-verified one shows an ASSERTED identity as a PROVEN
// one, in the artifact we put in front of people. The same shape of defect --
// a signal that reads stronger than its evidence -- has turned up three times
// this week in test harnesses; this is the one place it would be on screen.
function actorLine(r){
  if (!r.acting_user) return '<span class="muted">none</span>';
  const src = r.user_asserted_by;
  // Only two values exist (runtoken.SUB_SRC_IDP / SUB_SRC_ASSERTED). Anything
  // else, including a NULL from before the column existed, is reported as
  // unknown rather than guessed -- a run whose provenance we cannot state is
  // exactly the run where guessing is worst.
  const how = src === 'idp'      ? 'verified by IdP'
            : src === 'asserted' ? 'asserted by operator'
            : 'provenance not recorded';
  const weak = src !== 'idp' ? ' weak' : '';
  return esc(r.acting_user) + ` <span class="prov${weak}">(${esc(how)})</span>`;
}
// THE GOLDEN PATH, in one block: incident to result, from the product surface
// alone. The MVP exit criterion is that this reads without opening a database,
// kubectl, Jaeger or source (RC freeze plan 4.2), so every field below comes
// from the HTTP API and nothing is inferred.
//
// Sources are fixed by docs/lane-a-action-contract.md. The four action fields
// are NEW there; the other six already exist on the run.
const DECISIONS = {
  denied:            {label: 'denied',            cls: 'failed'},
  allowed:           {label: 'allowed',           cls: 'done'},
  approval_required: {label: 'approval required', cls: 'queued'},
};
const RESULTS = {
  succeeded:     {label: 'succeeded',     cls: 'done'},
  failed:        {label: 'failed',        cls: 'failed'},
  not_attempted: {label: 'not attempted', cls: 'idle'},
};
// A value outside the closed set is shown AS the unknown value, loudly, not
// dropped and not guessed. The contract makes these closed on the server and
// observability.py raises on anything outside them, so an unknown here means
// the two have drifted -- which an operator must see rather than have hidden.
function closedSet(map, value, what){
  if (value === null || value === undefined) return '<span class="muted">none</span>';
  const hit = map[value];
  if (!hit) return `<span class="pill failed">unknown ${esc(what)}: ${esc(value)}</span>`;
  return `<span class="pill ${hit.cls}">${esc(hit.label)}</span>`;
}
// WHO, AND SAYS WHO -- the same pair the actor uses. An approver rendered as a
// bare name claims an identity was proven when it was asserted.
function withProvenance(subject, src, how){
  if (!subject) return '<span class="muted">none</span>';
  const weak = src !== 'idp' ? ' weak' : '';
  return esc(subject) + ` <span class="prov${weak}">(${esc(how(src))})</span>`;
}
// The consequential action this run requested, if any. A failed request does
// not take down the rest of the run page, but it also MUST NOT be rendered as
// an empty list: "the evidence is unavailable" and "nothing was requested"
// are different claims. page.actionsLoaded carries that distinction.
async function loadAction(page){
  page.action = null;
  page.actionsLoaded = false;
  try {
    const rows = await api('GET', '/runs/' + encodeURIComponent(page.arg) + '/actions');
    // one consequential action per run in MVP; the newest is the story's
    if (Array.isArray(rows) && rows.length) page.action = rows[rows.length - 1];
    page.actionsLoaded = true;
  } catch (e) {
    // deliberately keep the rest of the page usable; renderStory names the
    // missing evidence instead of inventing a decision from its absence.
  }
}
function renderStory(page){
  const r = page.run, a = page.action || null;
  const pin = typeof r.subject_context === 'string' ? tryParse(r.subject_context) : r.subject_context;
  const resource = pin ? Object.values(pin).join(' · ') : null;
  $('storyPanel').innerHTML = [
    kv('incident', r.input ? esc(fmtJson(tryParse(r.input) ?? r.input)).slice(0, 200) : '<span class="muted">none</span>'),
    kv('agent', `<a href="#/agents/${encodeURIComponent(r.agent)}">${esc(r.agent)}</a>`, true),
    kv('actor', actorLine(r)),
    kv('resource', resource
        ? withProvenance(resource, r.pin_asserted_by, s => s ? `pinned by ${s}` : 'pin provenance not recorded')
        : '<span class="muted">unpinned</span>'),
    kv('diagnosis', r.summary ? esc(r.summary) : '<span class="muted">not reported yet</span>'),
    kv('requested', a ? `${esc(a.tool)} <code class="mono">${esc(a.target)}</code>`
                      : page.actionsLoaded
                        ? '<span class="muted">no consequential action requested</span>'
                        : '<span class="pill failed">action data unavailable</span>', true),
    kv('decision', a ? closedSet(DECISIONS, a.decision, 'decision') +
        (a.decision_reason ? ` <span class="prov">(${esc(a.decision_reason)})</span>` : '')
        : '<span class="muted">none</span>'),
    kv('approved by', a && a.approved_by
        ? withProvenance(a.approved_by, a.approved_by_asserted_by,
                         s => s ? `via ${s}` : 'provenance not recorded')
        : '<span class="muted">no approval required</span>'),
    kv('result', a ? closedSet(RESULTS, a.result, 'result') +
        (a.result_detail ? ` <span class="prov">(${esc(a.result_detail)})</span>` : '')
        : '<span class="muted">none</span>'),
    kv('trace', traceLink(r.trace_id), true),
  ].join('');
}
function renderRunHeader(page){
  const r = page.run;
  const rr = typeof r.runtime_resolution === 'string' ? tryParse(r.runtime_resolution) : r.runtime_resolution;
  $('runHeader').innerHTML = [
    kv('state', `<span class="pill ${esc(r.state)}">${esc(r.state)}</span>`),
    kv('protocol', esc(protoOf(r)), true),
    kv('digest', r.registry_digest ? esc(short(r.registry_digest)) : '<span class="muted">none · manifest mode</span>', true),
    kv('workflow', r.workflow_id ? `<a href="#/workflows/${encodeURIComponent(r.workflow_id)}">${esc(short(r.workflow_id))}</a> · depth ${esc(r.depth||0)}` : '<span class="muted">none</span>', true),
    kv('trace', traceLink(r.trace_id), true),
    kv('timing', `${esc((r.created_at||'').replace('T',' ').slice(0,19))}${r.finished_at?' → '+esc(r.finished_at.replace('T',' ').slice(11,19)):''}`),
    kv('image', rr && rr.image_ref ? esc(rr.image_ref) : '<span class="muted">none</span>', true),
    kv('acting user', actorLine(r)),
  ].join('');
}
function renderRuntime(page){
  const r = page.run;
  const rr = (typeof r.runtime_resolution === 'string' ? tryParse(r.runtime_resolution) : r.runtime_resolution) || {};
  const scope = typeof r.scope === 'string' ? tryParse(r.scope) : r.scope;
  $('runtimeCard').innerHTML = [
    kv('interface', esc(rr.interface_version || 'native'), true),
    kv('policy revision', esc(rr.policy_revision || 'none'), true),
    kv('command', rr.command ? esc([].concat(rr.command).join(' ')) : '<span class="muted">none</span>', true),
    kv('scope', `<div class="chips">${(scope||[]).map(s=>`<span class="chip">${esc(s)}</span>`).join('')||'<span class="muted">agent default</span>'}</div>`),
    kv('worker', r.worker ? esc(r.worker) : '<span class="muted">none</span>', true),
    kv('error', r.error ? esc(r.error) : '<span class="muted">none</span>'),
  ].join('');
}

async function followTick(page){
  return once(page, () => followTickOnce(page));
}
async function followTickOnce(page){
  const id = page.arg;
  const fresh = await api('GET','/runs/'+encodeURIComponent(id));
  if (PAGE !== page) return;
  const wasTerminal = TERMINAL.has(page.run.state);
  page.run = fresh;
  renderRunHeader(page);
  renderRuntime(page);
  if (page.mode === 'conversation') await followConversation(page);
  else if (page.mode === 'exec') renderExec(page);
  else renderWork(page);
  if (PAGE !== page) return;
  // exchanges: once, when the transcript exists (native runs, at the end)
  if (page.mode !== 'exec' && TERMINAL.has(fresh.state) && page.exchanges === null){
    try {
      page.exchanges = (await api('GET','/runs/'+encodeURIComponent(id)+'/exchanges')).exchanges;
    } catch (e) { page.exchanges = e.status === 404 ? [] : null; if (e.status !== 404) throw e; }
    // The operator navigated while that read was in flight: this run's
    // exchanges must not land in the next run's card.
    if (PAGE !== page) return;
    renderExchanges(page);
  } else if (page.mode === 'exec' && page.exchanges === null){
    page.exchanges = [];
    $('exchanges').innerHTML = '<div class="empty">exec/v1 runs have no transcript: stdout only, above</div>';
  } else if (page.exchanges === null){
    $('exchanges').innerHTML = `<div class="empty">available when the run ends</div>`;
  }
  if (!wasTerminal && TERMINAL.has(fresh.state)) toast('run '+fresh.state, fresh.state === 'done' ? 'ok' : 'err');
  // A run that has ended and whose transcript has been read has nothing more
  // to report: stop asking rather than polling a finished row forever.
  if (TERMINAL.has(fresh.state) && page.exchanges !== null) stopTicking(page);
}

async function followConversation(page){
  const id = page.arg;
  const data = await api('GET','/runs/'+encodeURIComponent(id)+'/events?after='+page.cursor);
  if (PAGE !== page) return;
  // Two readers can hold the same cursor (a sent turn and the scheduled tick
  // both call followTick). `seq`, not arrival, decides what is new, so a race
  // repeats no event.
  for (const ev of data.events){
    if (ev.seq <= page.cursor) continue;
    page.events.push(ev); page.cursor = ev.seq;
  }
  const live = !TERMINAL.has(page.run.state);
  $('followTitle').innerHTML = `Conversation<span class="spacer"></span><span class="muted">${live ? 'following · cursor '+page.cursor : 'ended'}</span>`;
  let turns = [], cur = null;
  for (const ev of page.events){
    if (ev.kind === 'chunk'){ if (!cur){ cur = {text: ''}; turns.push(cur); } cur.text += ev.body || ''; }
    else if (ev.kind === 'turn_end'){ cur = null; }
    else if (ev.kind === 'session_end'){ turns.push({end: true}); cur = null; }
    else if (ev.kind === 'error'){ turns.push({error: ev.body}); cur = null; }
  }
  const html = turns.map((t, i) => t.end ? `<div class="turn muted">session ended</div>`
    : t.error ? `<div class="turn note err">${esc(t.error)}</div>`
    : `<div class="turn"><span class="k">${esc(page.run.agent)} · turn ${i+1}${cur === t ? ' · streaming' : ''}</span><div>${esc(t.text)}${cur === t && live ? '<span class="cursor"></span>' : ''}</div></div>`).join('')
    || `<div class="empty">${live ? 'waiting for the first reply' : 'no reply recorded'}</div>`;
  const mine = !ME.user_auth || page.run.acting_user === ME.sub;
  const wantBox = live && mine;
  if (wantBox !== page.hasBox){
    // The send box is rebuilt only when it appears or goes away. Rebuilding it
    // on every 2 s tick throws away whatever the operator is part-way through
    // typing.
    $('follow').innerHTML = `<div class="turns" id="turns"></div>` + (wantBox ? `
    <form class="sendbox" id="turnForm"><input id="turnText" placeholder="Send a turn to the agent" autocomplete="off">
      <button class="primary" type="submit">Send</button><button type="button" data-action="close-run">Close session</button></form>` : '');
    const f = $('turnForm'); if (f) f.addEventListener('submit', ev => { ev.preventDefault(); sendTurn(page); });
    page.hasBox = wantBox; page.lastTurns = null;
  }
  if (html === page.lastTurns) return;
  const box = $('turns');
  // Follow the tail only for a reader who is already at it: yanking the view
  // to the bottom every tick makes scrolling back through a long run
  // impossible.
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.innerHTML = html;
  page.lastTurns = html;
  if (atBottom) box.scrollTop = box.scrollHeight;
}
async function sendTurn(page){
  const text = val('turnText'); if (!text) return;
  try { await api('POST','/runs/'+encodeURIComponent(page.arg)+'/turn', {body: text}); $('turnText').value = ''; await followTick(page); }
  catch (e) { toast('turn failed: '+(e.detail||e), 'err'); }
}
async function closeRun(page){
  try { await api('POST','/runs/'+encodeURIComponent(page.arg)+'/close'); toast('session closing', 'ok'); await followTick(page); }
  catch (e) { toast('close failed: '+(e.detail||e), 'err'); }
}

function renderWork(page){
  const r = page.run;
  const live = !TERMINAL.has(r.state);
  $('followTitle').innerHTML = `Transcript<span class="spacer"></span><span class="muted">${live ? 'polling state every 3 s' : esc(r.state)}</span>`;
  if (live){
    $('follow').innerHTML = `<div class="empty">Running. A headless run has no live feed; the transcript is written once when the run ends.</div>`;
  } else {
    $('follow').innerHTML = `<div class="body">${r.summary ? `<div class="k">Summary</div><pre>${esc(r.summary)}</pre>` : '<div class="muted">no summary recorded</div>'}
      ${r.error ? `<div class="note err mt8">${esc(r.error)}</div>` : ''}</div>`;
  }
}
function renderExec(page){
  const r = page.run;
  const live = !TERMINAL.has(r.state);
  $('followTitle').innerHTML = `Captured output<span class="spacer"></span><span class="muted">${live ? 'no progress signal for a stock process' : 'stdout + stderr'}</span>`;
  const truncated = r.summary && /TRUNCAT/i.test(r.summary);
  $('follow').innerHTML = live
    ? `<div class="empty">Running. Output arrives when the process exits.</div>`
    : `<div class="body"><pre>${esc(r.summary || '')}</pre>
       ${truncated ? '<div class="note warn mt8">Output was truncated at the manifest cap.</div>' : ''}
       <div class="note mt8">This is captured text from a stock process. It is diagnostic only: never read by an authorization decision and never treated as proof of what the run did.</div>
       ${r.error ? `<div class="note err mt8">${esc(r.error)}</div>` : ''}</div>`;
}
function renderExchanges(page){
  const ex = page.exchanges || [];
  $('exchCount').textContent = ex.length ? `${ex.filter(e=>e.kind==='model').length} model · ${ex.filter(e=>e.kind==='tool').length} tool` : '';
  if (!ex.length){ $('exchanges').innerHTML = '<div class="empty">no transcript recorded</div>'; return; }
  $('exchanges').innerHTML = `<div class="turns">${ex.map(e => {
    if (e.kind === 'turn') return `<div class="turn"><span class="k">you · turn ${esc(e.seq)}</span><div>${esc(e.text)}</div></div>`;
    if (e.kind === 'model') return `<div class="turn"><span class="k">model · ${esc(e.model||'')}</span><div>${e.blocks.map(b =>
        b.type === 'text' ? esc(b.text) : b.type === 'tool_use' ? `<span class="chip">tool_use · ${esc(b.name)}</span>` : '<span class="chip">thinking</span>').join(' ')}</div></div>`;
    if (e.kind === 'tool') return `<div class="turn"><span class="k">tool · ${esc(e.name)}${e.is_error?' · error':''}</span>
        <pre>${esc(fmtJson(e.input))}</pre>${e.result !== null && e.result !== undefined ? `<pre>${esc(fmtJson(e.result))}</pre>` : '<span class="muted">no result recorded</span>'}</div>`;
    if (e.kind === 'result') return `<div class="turn muted">result · ${e.is_error ? 'error' : 'ok'} · ${esc(e.num_turns)} turns · ${esc(e.duration_ms)} ms</div>`;
    return '';
  }).join('')}</div>`;
}

// ---- Flow page -----------------------------------------------------------------
// The graph is drawn from ONE call. /flow carries each visible run's model and
// tool call COUNTS, so a 200-run workflow is one request rather than 200 full
// transcript reads through the BFF; a run's exchange BODIES are fetched only
// when its node is selected. Nothing in the SVG uses a var() presentation
// attribute: SVG 2 has no such thing, so every colour is a class in app.css.
async function flowPage(page){
  const id = page.arg;
  const flow = await api('GET','/workflows/'+encodeURIComponent(id)+'/flow');
  if (PAGE !== page) return;
  page.flow = flow; page.sel = null; page.ex = {};
  const tally = pick => flow.nodes.reduce((a, nd) =>
    a + Object.values((nd.exchanges && pick(nd.exchanges)) || {}).reduce((x, y) => x + y, 0), 0);
  const nRuns = flow.nodes.length, nModel = tally(c => c.models), nTool = tally(c => c.tools);
  // THE COUNTS ARE ONLY EXACT WHEN NOTHING WAS LEFT OUT. The route caps the
  // runs it draws, the tasks and messages it reads, the bytes it reads per
  // transcript and per request, and the distinct model/tool names per run --
  // and it reports each of those. Rendering the sum as a bare number while any
  // of them fired states a total that is not the total.
  const partial = flow.truncated_runs || flow.truncated_items || flow.truncated_reads
    || flow.nodes.some(nd => nd.exchanges && nd.exchanges.truncated)
    || flow.nodes.some(nd => nd.exchanges_omitted);
  const approx = partial ? 'at least ' : '';
  const why = [
    flow.truncated_runs ? `only the first ${nRuns} runs are drawn` : '',
    flow.truncated_items ? 'not every task and message is listed' : '',
    flow.truncated_reads ? 'some transcripts were not read (graph read budget)' : '',
    flow.nodes.some(nd => nd.exchanges && nd.exchanges.truncated)
      ? 'some transcripts were counted only in part' : '',
  ].filter(Boolean);
  $('view').innerHTML = `
    <div class="card"><h2>Workflow<span class="spacer"></span><code class="mono">${esc(id)}</code></h2>
      <div class="body kv">${kv('state', `<span class="pill ${esc(flow.state)}">${esc(flow.state)}</span>`)}
        ${kv('runs', esc(approx + nRuns))}${kv('model calls', esc(approx + nModel))}${kv('tool calls', esc(approx + nTool)+' <span class="muted">(refusals arrive with the run event plane)</span>')}
        ${ME.admin ? kv('containment', `<span class="actions"><button data-action="halt-wf" data-id="${esc(id)}" data-verb="halt">Halt</button><button data-action="halt-wf" data-id="${esc(id)}" data-verb="unhalt">Unhalt</button></span>`) : ''}</div></div>
    <div class="cols-wide">
      <div class="card flow"><h2>Flow<span class="spacer"></span><span class="muted">edges = what woke each run</span></h2>
        ${why.length ? `<div class="body pb0"><div class="note warn">This graph is not the whole workflow: ${esc(why.join('; '))}. The counts above are lower bounds.</div></div>` : ''}
        <div class="body" id="flowSvg"></div>
        <div class="legend"><span>▢ agent run</span><span>⬡ model</span><span>▭ tool</span><span>◌ run you may not read</span><span>select a node or edge for its exchanges</span></div></div>
      <div class="card"><h2 id="exTitle">Exchange</h2><div id="exPanel"><div class="empty">Select a node or an edge.</div></div></div></div>`;
  drawFlow(page);
}
// How tall one column entry is: the run box plus a lane per model and per tool.
// A fixed row height overlaps the moment a run calls more than two tools.
const NODE_W = 200, BOX_H = 60, MODEL_H = 40, TOOL_H = 36;
function nodeHeight(n){
  if (n.elided || !n.exchanges) return BOX_H + 10;
  return BOX_H + 10 + MODEL_H * Object.keys(n.exchanges.models || {}).length
                    + TOOL_H * Object.keys(n.exchanges.tools || {}).length
                    + (n.exchanges.truncated ? 18 : 0);
}
function drawFlow(page){
  const f = page.flow;
  const byDepth = {};
  f.nodes.forEach(n => { (byDepth[n.depth||0] = byDepth[n.depth||0] || []).push(n); });
  const colW = 360, pad = 20, gap = 24;
  const pos = {};
  let height = pad;
  const depths = Object.keys(byDepth).map(Number).sort((a, b) => a - b);
  depths.forEach(d => {
    let y = pad;
    byDepth[d].forEach(n => { pos[n.index] = {x: pad + d*colW, y}; y += nodeHeight(n) + gap; });
    height = Math.max(height, y);
  });
  const width = pad*2 + colW*(depths[depths.length-1] + 1);
  let svg = '';
  const E = esc;
  // agent-agent edges
  f.edges.forEach((e, i) => {
    const a = pos[e.from], b = pos[e.to];
    const x1 = a.x+NODE_W, y1 = a.y+30, x2 = b.x, y2 = b.y+30, mx = (x1+x2)/2;
    const sel = page.sel === 'edge:'+i;
    // A cause of null is an edge into a run this caller may not read: the
    // server withholds it because a reason embeds task titles and sender names.
    svg += `<g class="node ${sel?'sel':''}" data-action="flow-select" data-key="edge:${i}"><path class="edge" d="M${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}"/>
      <rect class="badge" x="${mx-40}" y="${(y1+y2)/2-10}" width="80" height="18" rx="9"/><text class="badge-t" x="${mx}" y="${(y1+y2)/2+3}" text-anchor="middle">${E(e.cause || 'hidden')}</text></g>`;
  });
  f.nodes.forEach(n => {
    const p = pos[n.index];
    const sel = page.sel === 'run:'+n.index;
    if (n.elided){
      svg += `<g class="node"><rect class="elided" x="${p.x}" y="${p.y}" width="${NODE_W}" height="${BOX_H}" rx="10"/>
        <text class="n-title dim" x="${p.x+12}" y="${p.y+23}">${E(n.agent)}</text>
        <text class="n-sub" x="${p.x+12}" y="${p.y+42}">not visible to you · depth ${E(n.depth)}</text></g>`;
      return;
    }
    svg += `<g class="node ${sel?'sel':''}" data-action="flow-select" data-key="run:${n.index}"><rect class="box" x="${p.x}" y="${p.y}" width="${NODE_W}" height="${BOX_H}" rx="10"/>
      <text class="n-title" x="${p.x+12}" y="${p.y+23}">${E(n.agent)}</text>
      <text class="n-sub" x="${p.x+12}" y="${p.y+42}">${E(short(n.id))}</text>
      <rect class="chip-r" x="${p.x+136}" y="${p.y+10}" width="54" height="17" rx="8"/><text class="chip-t ${n.state==='pending'?'warn':''}" x="${p.x+163}" y="${p.y+22}" text-anchor="middle">${E(n.state)}</text></g>`;
    if (!n.exchanges){
      // "not read" and "there is nothing to read" are different facts and the
      // graph must not say the second when it means the first.
      const label = n.exchanges_omitted === 'budget'
        ? 'transcript not read · graph read budget' : 'no transcript · trace only';
      svg += `<text class="n-sub" x="${p.x+12}" y="${p.y+80}">${E(label)}</text>`;
      return;
    }
    let yy = p.y + 70;
    Object.entries(n.exchanges.models || {}).forEach(([m, calls]) => {
      const key = 'model:'+n.index+':'+m, s = page.sel === key;
      svg += `<g class="node ${s?'sel':''}" data-action="flow-select" data-key="${E(key)}"><line class="link" x1="${p.x+100}" y1="${p.y+BOX_H}" x2="${p.x+100}" y2="${yy}"/>
        <polygon class="hex" points="${p.x+34},${yy} ${p.x+166},${yy} ${p.x+180},${yy+16} ${p.x+166},${yy+32} ${p.x+34},${yy+32} ${p.x+20},${yy+16}"/>
        <text class="n-lab" x="${p.x+100}" y="${yy+20}" text-anchor="middle">${E(m)} · ${E(calls)}</text></g>`;
      yy += MODEL_H;
    });
    Object.entries(n.exchanges.tools || {}).forEach(([t, calls]) => {
      const key = 'tool:'+n.index+':'+t, s = page.sel === key;
      svg += `<g class="node ${s?'sel':''}" data-action="flow-select" data-key="${E(key)}"><line class="link" x1="${p.x+100}" y1="${p.y+BOX_H}" x2="${p.x+100}" y2="${yy}"/>
        <rect class="tool" x="${p.x+20}" y="${yy}" width="160" height="30" rx="4"/>
        <text class="n-lab" x="${p.x+100}" y="${yy+19}" text-anchor="middle">${E(t)} · ${E(calls)}</text></g>`;
      yy += TOOL_H;
    });
    if (n.exchanges.truncated){
      svg += `<text class="n-sub" x="${p.x+12}" y="${yy+12}">counted in part only</text>`;
    }
  });
  $('flowSvg').innerHTML = `<svg viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">${svg}</svg>`;
}
// `kind:index:name`, where a model or tool NAME may itself contain ':'
// (`anthropic:claude-…`, an MCP tool id). Only the first two separators are.
function splitKey(key){
  const i1 = key.indexOf(':'), i2 = key.indexOf(':', i1 + 1);
  return i2 < 0 ? [key.slice(0, i1), key.slice(i1 + 1), null]
                : [key.slice(0, i1), key.slice(i1 + 1, i2), key.slice(i2 + 1)];
}
async function flowSelect(page, key){
  page.sel = key; drawFlow(page);
  const f = page.flow, [kind, a, b] = splitKey(key);
  let title = 'Exchange', body = '';
  if (kind === 'edge'){
    const e = f.edges[+a], child = f.nodes[e.to], parent = f.nodes[e.from];
    title = `${esc(parent.agent)} → ${esc(child.agent)}${e.cause ? ' · '+esc(e.cause) : ''}`;
    const items = e.cause === 'task' ? f.tasks.filter(t=>t.assignee===child.agent) : e.cause === 'message' ? f.messages.filter(m=>m.recipient===child.agent) : [];
    body = `<div class="body"><div class="k">reason</div><div>${e.reason ? esc(e.reason) : '<span class="muted">not visible to you</span>'}</div>` + (items.length ? items.map(it => it.title !== undefined
      ? `<div class="k">task · ${esc(it.state)}</div><div><b>${esc(it.title)}</b></div><pre>${esc(it.detail||'')}</pre>${it.result?`<div class="k">result</div><pre>${esc(it.result)}</pre>`:''}`
      : `<div class="k">message · ${esc(it.state)}</div><pre>${esc(it.body||'')}</pre>`).join('') : '<div class="k">payload</div><div class="muted">none recorded, or not visible to you</div>') + '</div>';
  } else if (kind === 'run'){
    const n = f.nodes[+a];
    title = `${esc(n.agent)} · run`;
    body = `<div class="body kv">${kv('run', `<a href="#/runs/${encodeURIComponent(n.id)}">${esc(short(n.id))}</a>`, true)}${kv('state', `<span class="pill ${esc(n.state)}">${esc(n.state)}</span>`)}
      ${kv('woken by', esc(n.run_type)+' · '+esc(n.reason||''))}${kv('depth', esc(n.depth), true)}${kv('trace', traceLink(n.trace_id), true)}</div>`;
  } else {
    const n = f.nodes[+a];
    // Bodies for THIS run only, and only now that a reader asked for them.
    if (page.ex[n.id] === undefined){
      $('exTitle').textContent = `${n.agent} → ${b}`;
      $('exPanel').innerHTML = '<div class="empty">reading the transcript…</div>';
      try { page.ex[n.id] = (await api('GET','/runs/'+encodeURIComponent(n.id)+'/exchanges')).exchanges; }
      catch (e) { page.ex[n.id] = null; }
      if (PAGE !== page || page.sel !== key) return;
    }
    const exs = (page.ex[n.id]||[]).filter(e => kind === 'model' ? (e.kind==='model' && (e.model||'model')===b) : (e.kind==='tool' && e.name===b));
    page.exIdx = (page.exKey === key) ? page.exIdx : 0; page.exKey = key;
    const i = Math.min(page.exIdx, exs.length-1), e = exs[i];
    title = `${esc(n.agent)} → ${esc(b)} · call ${i+1} of ${exs.length}`;
    body = e ? `<div class="body">${kind === 'tool'
      ? `<div class="k">input</div><pre>${esc(fmtJson(e.input))}</pre><div class="k">result${e.is_error?' · error':''}</div><pre>${esc(fmtJson(e.result))}</pre>`
      : `<div class="k">blocks</div><div>${e.blocks.map(x => x.type==='text' ? `<div>${esc(x.text)}</div>` : `<span class="chip">${esc(x.type)}${x.name?' · '+esc(x.name):''}</span>`).join('')}</div>${e.usage?`<div class="k">usage</div><pre>${esc(fmtJson(e.usage))}</pre>`:''}`}
      <div class="k">source</div><div class="muted">transcript.jsonl, as the runner redacted it</div>
      <div class="actions mt10"><button data-action="ex-prev" ${i<=0?'disabled':''}>Previous</button><button data-action="ex-next" ${i>=exs.length-1?'disabled':''}>Next</button></div></div>`
      : `<div class="empty">${page.ex[n.id] === null ? 'no transcript · trace only' : 'no calls'}</div>`;
  }
  $('exTitle').innerHTML = title;
  $('exPanel').innerHTML = body;
}

// ---- Workers -------------------------------------------------------------------
// The shell is built once and the loader is the tick. When the page function
// IS the tick it calls schedule() on every pass, leaving a second live timer
// each time: 1024 timers and 1024 GET /workers a minute in.
async function workersPage(page){
  $('view').innerHTML = `<div class="card"><h2>Workers<span class="spacer"></span><span class="muted" id="workerCount"></span></h2><div id="list"></div></div>`;
  const load = () => loadWorkers(page);
  await load();
  schedule(page, load, 6000);
}
async function loadWorkers(page){
  return once(page, async () => {
    const workers = await api('GET','/workers');
    if (PAGE !== page) return;
    $('workerCount').textContent = workers.length + ' workers';
    $('list').innerHTML = workers.length
      ? `<table><thead><tr><th>Worker</th><th>Slots</th><th></th><th>Last heartbeat</th></tr></thead><tbody>${workers.map(w=>`<tr>
      <td class="name"><code class="mono">${esc(w.id)}</code></td><td>${esc(w.slots)}</td>
      <td><span class="pill ${w.alive?'running':'paused'}">${w.alive?'alive':'gone'}</span></td><td class="muted">${esc(w.last_heartbeat||'')}</td></tr>`).join('')}</tbody></table>`
      : '<div class="empty">No workers have ever sent a heartbeat.</div>';
  });
}

async function haltWf(id, verb){
  if (verb==='halt' && !confirm('Halt workflow '+id+'? Nothing further spawns under it.')) return;
  try{ await api('POST','/workflows/'+encodeURIComponent(id)+'/'+verb); toast(verb+' → '+id, 'ok'); await render(); }
  catch(e){ toast(verb+' failed: '+(e.detail||e), 'err'); }
}

// ---- event delegation -------------------------------------------------------
// One listener per event type; the nearest data-action decides. A button
// inside a clickable row wins over the row because closest() finds it first.
// A row is not focusable: the real <a> in its first cell is what a keyboard
// and a screen reader use, so there is no fake widget to give key handling to.
const ACTIONS = {
  'refresh':       () => refresh(),
  'go':            el => go(el.dataset.href),
  'close-detail':  () => go('#/'+route().name),
  'act':           el => act(el.dataset.name, el.dataset.verb),
  'del':           el => del(el.dataset.name),
  'prefill':       el => prefillFromManifest(el.dataset.id, el.dataset.name),
  'halt-wf':       el => haltWf(el.dataset.id, el.dataset.verb),
  'toggle-chip':   el => el.setAttribute('aria-pressed', el.classList.toggle('on') ? 'true' : 'false'),
  'runs-older':    () => PAGE && PAGE.name === 'runs' && loadRuns(PAGE, olderCursor(PAGE)).catch(e=>toast('load failed: '+(e.detail||e),'err')),
  'close-run':     () => PAGE && closeRun(PAGE),
  'flow-select':   el => PAGE && flowSelect(PAGE, el.dataset.key).catch(e=>toast('load failed: '+(e.detail||e),'err')),
  'ex-prev':       () => { if (PAGE){ PAGE.exIdx = Math.max(0, (PAGE.exIdx||0)-1); flowSelect(PAGE, PAGE.sel); } },
  'ex-next':       () => { if (PAGE){ PAGE.exIdx = (PAGE.exIdx||0)+1; flowSelect(PAGE, PAGE.sel); } },
};
function dispatch(ev){
  const el = ev.target.closest('[data-action]');
  if (!el || el.tagName === 'SELECT') return;
  const fn = ACTIONS[el.dataset.action];
  if (fn) { ev.preventDefault(); fn(el); }
}
document.addEventListener('click', dispatch);
document.addEventListener('change', ev => {
  const el = ev.target.closest('select[data-action]');
  if (!el || !PAGE) return;
  if (el.dataset.action === 'owner-filter'){ PAGE.ownerFilter = el.value; loadAgents(PAGE).catch(e=>toast('load failed: '+(e.detail||e),'err')); }
  if (el.dataset.action === 'runs-filter'){
    // A new filter is a new list: the pages walked under the old one describe
    // rows this query may not even return.
    PAGE.filters = {agent: $('f_agent').value, state: $('f_state').value};
    PAGE.pages = [];
    loadRuns(PAGE, null).catch(e=>toast('load failed: '+(e.detail||e),'err'));
  }
});
window.addEventListener('hashchange', render);
// A background tab does not poll; when it comes back it catches up at once
// instead of waiting out the interval (or the backoff it had reached).
document.addEventListener('visibilitychange', () => {
  if (document.hidden || !PAGE || !PAGE.tick || PAGE.stopped) return;
  clearTimeout(PAGE.timer);
  PAGE.failures = 0;
  // `0` is the delay for THIS arming only; the re-arm inside schedule() reads
  // page.base, so catching up cannot become a millisecond poll loop.
  schedule(PAGE, PAGE.tick, PAGE.base, 0);
});

// ---- boot -------------------------------------------------------------------
// Exchange the launch token (or reuse the tab's session), learn who we are
// (drives which chrome renders), then render the route.
async function boot(){
  // The trace link and the header line both come from /healthz. Learning it
  // AFTER the first page has painted leaves a deep-linked run with no trace
  // link until the next tick.
  try {
    CP = await (await fetch('/healthz')).json();
    CP_TEXT = 'control plane: ' + CP.control_plane;
    if (!$('cp').dataset.since) $('cp').textContent = CP_TEXT;
  } catch (e) {}
  try{
    await openSession();
  }catch(e){
    blocked(e);
    return;
  }
  try{
    ME = await api('GET','/me');
  }catch(e){
    if (sessionDead(e)) return;
    toast('sign-in check failed: '+(e.detail||e), 'err');
  }
  if (ME.user_auth) $('who').textContent = ME.sub + (ME.admin ? ' · admin' : '');
  if (ME.admin) $('workersTab').hidden = false;
  if (!location.hash) go('#/agents'); else render();
}
boot();
