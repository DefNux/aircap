'use strict';
/* AIRCAP console. No build step, no external dependencies. */

const $ = (s, r = document) => r.querySelector(s);
const state = { view: 'overview', overview: null, cache: {}, sel: {} };

/* ---------- helpers ---------- */
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const pill = (text, kind) => `<span class="pill ${kind || 'muted'}">${esc(text)}</span>`;
const sevPill = (s) => pill(s, ['critical', 'high', 'medium', 'low'].includes(s) ? s : 'muted');
const riskPill = (n) => pill(n, n >= 70 ? 'critical' : n >= 40 ? 'high' : n >= 20 ? 'medium' : 'low');
const fmt = (n) => (n === null || n === undefined ? '—' : n);

function toast(title, body, kind) {
  const el = document.createElement('div');
  el.className = `toast ${kind || ''}`;
  el.innerHTML = `<div class="th">${esc(title)}</div>${body ? `<div class="tb">${esc(body)}</div>` : ''}`;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), kind === 'err' ? 9000 : 5000);
}

function busy(on, text) {
  $('#busytext').textContent = text || 'Working…';
  $('#busy').classList.toggle('on', !!on);
}

async function api(path, opts = {}) {
  const res = await fetch(`/api/v1${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let json;
  try { json = await res.json(); } catch { throw new Error(`${res.status} ${res.statusText}`); }
  if (!res.ok) throw new Error(json.error || json.detail || `${res.status} ${res.statusText}`);
  return json.data;
}

async function act(label, fn) {
  busy(true, label);
  try { return await fn(); }
  catch (e) { toast(label + ' failed', e.message, 'err'); return null; }
  finally { busy(false); }
}

/* minimal markdown: headings, tables, lists, quotes, code, bold, hr */
function md(src) {
  const lines = String(src || '').split('\n');
  let out = '', inTable = false, inList = false, head = false;
  const inline = (t) => esc(t)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  const closeList = () => { if (inList) { out += '</ul>'; inList = false; } };
  const closeTable = () => { if (inTable) { out += '</tbody></table></div>'; inTable = false; head = false; } };

  for (const raw of lines) {
    const l = raw.trimEnd();
    if (/^\|/.test(l)) {
      const cells = l.split('|').slice(1, -1).map((c) => c.trim());
      if (/^[-:\s|]+$/.test(l)) { head = true; out += '<tbody>'; continue; }
      if (!inTable) { closeList(); out += '<div class="tablewrap"><table><thead>'; inTable = true; }
      const tag = head ? 'td' : 'th';
      out += '<tr>' + cells.map((c) => `<${tag}>${inline(c)}</${tag}>`).join('') + '</tr>';
      if (!head) out += '</thead>';
      continue;
    }
    closeTable();
    if (/^#{1,6}\s/.test(l)) {
      closeList();
      const n = l.match(/^#+/)[0].length;
      out += `<h${Math.min(n, 3)}>${inline(l.replace(/^#+\s*/, ''))}</h${Math.min(n, 3)}>`;
    } else if (/^>\s?/.test(l)) { closeList(); out += `<blockquote>${inline(l.replace(/^>\s?/, ''))}</blockquote>`; }
    else if (/^[-*]\s/.test(l)) { if (!inList) { out += '<ul>'; inList = true; } out += `<li>${inline(l.replace(/^[-*]\s/, ''))}</li>`; }
    else if (/^(-{3,}|_{3,})$/.test(l)) { closeList(); out += '<hr>'; }
    else if (!l.trim()) { closeList(); }
    else { closeList(); out += `<p>${inline(l)}</p>`; }
  }
  closeList(); closeTable();
  return out;
}

function table(cols, rows, opts = {}) {
  if (!rows.length) return `<div class="empty"><p>${esc(opts.empty || 'Nothing to show.')}</p></div>`;
  return `<div class="tablewrap ${opts.scroll ? 'scroll' : ''}"><table><thead><tr>${
    cols.map((c) => `<th${c.num ? ' class="mono"' : ''}>${esc(c.label)}</th>`).join('')
  }</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}

/* ---------- views ---------- */
const VIEWS = {};

VIEWS.overview = {
  icon: '▦', label: 'Overview',
  async render() {
    const o = await api('/overview');
    state.overview = o;
    const f = o.lab.vuln_flags;
    const on = Object.entries(f).filter(([, v]) => v).map(([k]) => k);
    const c = o.containment;
    const d = o.discovery;

    return `
    <div class="head">
      <div>
        <h2>Capability overview</h2>
        <p>Current lab posture, telemetry, containment state and discovery findings. Every
        number here is read live from the same modules the CLI uses.</p>
      </div>
      <div class="spacer"></div>
      <div class="actions">
        <button class="btn primary" data-go="attacks">Run attacks →</button>
      </div>
    </div>

    ${o.corpus.pollution.length ? `<div class="note crit"><strong>Corpus polluted:</strong>
      ${o.corpus.pollution.map(esc).join(', ')} — leftover documents change retrieval ranking and
      skew every detection count. Reset the lab before running attacks.</div>` : ''}

    ${c.active ? `<div class="note warn"><strong>${c.active} containment action(s) active.</strong>
      Attacks will be blocked while these are in effect — that is the point, but reset or lift
      before measuring a fresh baseline.</div>` : ''}

    <div class="grid cards">
      <div class="card"><h3>Lab posture</h3>
        <div class="big">${on.length ? on.length : 'Hardened'}</div>
        <div class="sub">${on.length ? on.length + ' vulnerability toggle(s) on' : 'no vulnerability toggles'}</div>
      </div>
      <div class="card"><h3>Model plane</h3>
        <div class="big" style="font-size:18px">${esc(o.lab.model_backend)}</div>
        <div class="sub mono">${esc(o.lab.model_id)}</div>
      </div>
      <div class="card"><h3>Invocations logged</h3>
        <div class="big">${o.telemetry.invocations}</div>
        <div class="sub">${Object.entries(o.telemetry.files).map(([k, v]) => `${k.split('-')[0]} ${v}`).join(' · ')}</div>
      </div>
      <div class="card"><h3>Containment</h3>
        <div class="big" style="color:${c.active ? 'var(--high)' : 'var(--ok)'}">${c.active}</div>
        <div class="sub">${c.audit_entries} audit entries</div>
      </div>
      <div class="card"><h3>Incidents</h3>
        <div class="big">${o.incidents}</div>
        <div class="sub">${o.counts.runbooks} runbooks available</div>
      </div>
      <div class="card"><h3>Shadow AI posture</h3>
        <div class="big" style="font-size:18px;color:${
          d ? (d.posture === 'critical' ? 'var(--crit)' : d.posture === 'elevated' ? 'var(--high)' : 'var(--ok)') : 'var(--fg-3)'
        }">${d ? esc(d.posture) : 'not scanned'}</div>
        <div class="sub">${d ? `${d.findings_total} findings, ${d.unsanctioned} unsanctioned` : 'run a scan'}</div>
      </div>
    </div>

    <div class="split" style="margin-top:16px">
      <div class="panel"><header><h3>Vulnerability toggles</h3></header><div class="body">
        <div class="kv">${Object.entries(f).map(([k, v]) =>
          `<dt>${esc(k)}</dt><dd>${v ? pill('ON', 'high') : pill('off', 'ok')}</dd>`).join('')}
          <dt>max_tool_depth</dt><dd>${o.lab.max_tool_depth}</dd>
          <dt>max_prompt_chars</dt><dd>${o.lab.max_prompt_chars}</dd>
          <dt>guardrail</dt><dd>${o.lab.guardrail_id ? esc(o.lab.guardrail_id) : pill('none', 'high')}</dd>
        </div>
        <p style="color:var(--fg-2);font-size:12px;margin:12px 0 0">Toggles are set per-attack from
        each manifest, so this shows the process default rather than what any single attack ran under.</p>
      </div></div>

      <div class="panel"><header><h3>Active containment</h3><div class="spacer"></div>
        ${c.active ? '<button class="btn sm danger" id="lift">Lift all</button>' : ''}
      </header><div class="body">
        ${c.active ? `<div class="kv">
          ${c.quarantined_documents.length ? `<dt>quarantined</dt><dd>${c.quarantined_documents.map(esc).join('<br>')}</dd>` : ''}
          ${c.disabled_tools.length ? `<dt>tools disabled</dt><dd>${c.disabled_tools.map(esc).join('<br>')}</dd>` : ''}
          ${c.blocked_egress_hosts.length ? `<dt>hosts blocked</dt><dd>${c.blocked_egress_hosts.map(esc).join('<br>')}</dd>` : ''}
          ${c.revoked_principals.length ? `<dt>principals revoked</dt><dd>${c.revoked_principals.map(esc).join('<br>')}</dd>` : ''}
          ${c.enforce_output_filter ? '<dt>output filter</dt><dd>enforced</dd>' : ''}
        </div>` : '<div class="empty"><p>No containment in effect. The lab is in its normal state.</p></div>'}
      </div></div>
    </div>`;
  },
  bind() {
    $('#lift')?.addEventListener('click', async () => {
      const r = await act('Lifting containment', () => api('/containment/lift', { method: 'POST' }));
      if (r) { toast('Containment lifted', `${r.lifted} action(s) reversed, ${r.retained_as_evidence.length} artifact(s) retained as evidence`, 'good'); go('overview'); }
    });
  },
};

VIEWS.attacks = {
  icon: '⚔', label: 'Attacks',
  async render() {
    const list = await api('/attacks');
    state.cache.attacks = list;
    const rows = list.map((a) => `<tr>
      <td><label class="chk"><input type="checkbox" data-atk="${esc(a.id)}"> <span class="mono">${esc(a.id)}</span></label></td>
      <td class="wrap"><strong>${esc(a.name)}</strong><div style="color:var(--fg-2);font-size:12px;margin-top:3px">${esc(a.description)}</div>
        ${a.notes ? `<div style="color:var(--high);font-size:12px;margin-top:6px">${esc(a.notes)}</div>` : ''}</td>
      <td class="mono">${a.atlas.map((t) => `<a href="https://atlas.mitre.org/techniques/${esc(t)}" target="_blank" rel="noopener">${esc(t)}</a>`).join('<br>')}</td>
      <td class="mono">${Object.keys(a.posture).length ? Object.keys(a.posture).map(esc).join('<br>') : pill('hardened', 'ok')}</td>
      <td class="mono">${a.expect.map(esc).join(' ')}</td>
      <td>${a.baseline_prevents ? pill('prevented', 'ok') : pill(a.control_layer === 'cloud' ? 'cloud control' : 'no control', a.control_layer === 'cloud' ? 'accent' : 'crit')}</td>
      <td><button class="btn sm" data-run1="${esc(a.id)}">Run</button></td>
    </tr>`);

    return `
    <div class="head">
      <div><h2>Attack pack</h2>
        <p>Ten reproducible attacks against the lab's RAG agent. Each declares the posture it needs,
        its ATLAS mapping, the detections it should trigger, and whether the hardened baseline is
        expected to prevent it.</p></div>
      <div class="spacer"></div>
      <div class="actions">
        <label class="chk"><input type="checkbox" id="keep" checked> Keep planted docs</label>
        <button class="btn" id="runsel">Run selected</button>
        <button class="btn primary" id="runall">Run all 10</button>
        <button class="btn" id="runhard" title="Run every attack with all controls enabled">Control test</button>
      </div>
    </div>
    <div class="note"><strong>Keep planted docs</strong> leaves attack artifacts in the corpus so the
    IR engine has something real to quarantine. Leave it on if you intend to run incident response next.</div>
    <div id="result"></div>
    <div class="panel"><header><h3>Attacks</h3></header><div class="body flush">
      ${table([{label:''},{label:'Attack'},{label:'ATLAS'},{label:'Posture'},{label:'Expects'},{label:'Hardened baseline'},{label:''}], rows)}
    </div></div>`;
  },
  bind() {
    const run = async (ids, hardened) => {
      const r = await act(hardened ? 'Running control test' : 'Running attacks',
        () => api('/attacks/run', { method: 'POST', body: { ids, hardened, keep_artifacts: $('#keep').checked } }));
      if (!r) return;
      $('#result').innerHTML = renderAttackResult(r);
      toast(hardened ? 'Control test complete' : 'Attack run complete',
        `${r.succeeded}/${r.total} succeeded in ${r.duration_s}s`,
        hardened ? (r.control_test_passed ? 'good' : 'err') : 'good');
    };
    $('#runall')?.addEventListener('click', () => run(null, false));
    $('#runhard')?.addEventListener('click', () => run(null, true));
    $('#runsel')?.addEventListener('click', () => {
      const ids = [...document.querySelectorAll('[data-atk]:checked')].map((e) => e.dataset.atk);
      if (!ids.length) return toast('Nothing selected', 'Tick at least one attack.', 'err');
      run(ids, false);
    });
    document.querySelectorAll('[data-run1]').forEach((b) =>
      b.addEventListener('click', () => run([b.dataset.run1], false)));
  },
};

function renderAttackResult(r) {
  const rows = r.results.map((x) => `<tr>
    <td class="mono">${esc(x.id)}</td>
    <td class="wrap"><strong>${esc(x.name)}</strong><div style="color:var(--fg-2);font-size:12px;margin-top:3px">${esc(x.detail)}</div></td>
    <td>${x.succeeded ? pill('succeeded', 'crit') : pill('blocked', 'ok')}</td>
    ${r.mode === 'hardened' ? `<td>${x.matches_expectation ? pill('as expected', 'ok') : pill('UNEXPECTED', 'crit')}</td>` : ''}
  </tr>`);
  const cols = [{label:'ID'},{label:'Result'},{label:'Outcome'}];
  if (r.mode === 'hardened') cols.push({label:'vs manifest'});
  return `<div class="panel"><header>
      <h3>${r.mode === 'hardened' ? 'Control test' : 'Attack run'} — ${r.succeeded}/${r.total} succeeded</h3>
      <div class="spacer"></div>
      <span class="mono" style="color:var(--fg-3);font-size:12px">run ${esc(r.run_id)} · ${r.duration_s}s</span>
    </header><div class="body">
      ${r.mode === 'hardened' ? (r.control_test_passed
        ? `<div class="note"><strong>Control test passed.</strong> Every outcome matched its manifest.
           ${r.residual_risk.length} documented residual risk(s) reproduced as expected:
           ${r.residual_risk.map((x) => esc(x.id)).join(', ')} — these have no preventive control yet.</div>`
        : `<div class="note crit"><strong>Control test FAILED.</strong> An outcome did not match its manifest.</div>`) : ''}
      ${table(cols, rows)}
    </div></div>`;
}

VIEWS.detections = {
  icon: '◎', label: 'Detections',
  async render() {
    const list = await api('/detections');
    const rows = list.map((d) => `<tr class="clickable" data-det="${esc(d.id)}">
      <td class="mono"><strong>${esc(d.id)}</strong></td>
      <td>${sevPill(d.severity)}</td>
      <td class="mono">${esc(d.plane)}</td>
      <td class="wrap"><strong>${esc(d.title)}</strong>
        <div style="color:var(--fg-2);font-size:12px;margin-top:3px">${esc(d.description)}</div></td>
      <td class="mono">${esc(d.atlas)}</td>
      <td class="mono" id="hits-${esc(d.id)}">—</td>
    </tr>`);
    return `
    <div class="head">
      <div><h2>Detection library</h2>
        <p>Fourteen detections over the DuckDB views. These SQL rules are authoritative; the Sigma
        and Wazuh equivalents in the repo are ports of them. Click a row to see the matching evidence.</p></div>
      <div class="spacer"></div>
      <div class="actions"><button class="btn primary" id="rundet">Run all detections</button></div>
    </div>
    <div id="detsummary"></div>
    <div class="panel"><header><h3>Rules</h3><div class="spacer"></div>
      <span style="color:var(--fg-3);font-size:12px">click a row for evidence</span></header>
      <div class="body flush">${table(
        [{label:'ID'},{label:'Sev'},{label:'Plane'},{label:'Detection'},{label:'ATLAS'},{label:'Hits'}], rows)}</div></div>
    <div id="detrows"></div>`;
  },
  bind() {
    $('#rundet')?.addEventListener('click', async () => {
      const r = await act('Running detections', () => api('/detections/run', { method: 'POST' }));
      if (!r) return;
      r.detections.forEach((d) => {
        const cell = $(`#hits-${d.id}`);
        if (cell) cell.innerHTML = d.hits
          ? `<span style="color:var(--crit);font-weight:700">${d.hits}</span>`
          : '<span style="color:var(--fg-3)">0</span>';
      });
      $('#detsummary').innerHTML = `<div class="note"><strong>${r.fired}/${r.total} detections fired.</strong>
        ${r.total - r.fired ? 'Silent: ' + esc(r.detections.filter((d) => !d.hits).map((d) => d.id).join(', ')) + '.' : 'All rules matched something.'}</div>`;
      toast('Detections complete', `${r.fired}/${r.total} fired`, 'good');
    });
    document.querySelectorAll('[data-det]').forEach((tr) => tr.addEventListener('click', async () => {
      const r = await act('Loading evidence', () => api(`/detections/${tr.dataset.det}/rows`));
      if (!r) return;
      $('#detrows').innerHTML = `<div class="panel"><header><h3>${esc(r.id)} — ${esc(r.title)}</h3>
        <div class="spacer"></div>${sevPill(r.severity)}</header><div class="body">
        <div class="kv" style="margin-bottom:12px">
          <dt>atlas</dt><dd>${esc(r.atlas)}</dd><dt>owasp</dt><dd>${esc(r.owasp)}</dd>
          <dt>nist csf</dt><dd>${esc(r.nist)}</dd><dt>plane</dt><dd>${esc(r.plane)}</dd></div>
        <details style="margin-bottom:12px"><summary style="cursor:pointer;color:var(--accent);font-size:13px">Show SQL</summary>
          <pre style="margin-top:8px;color:var(--fg-2)">${esc(r.sql)}</pre></details>
        ${table(r.columns.map((c) => ({ label: c })),
          r.rows.map((row) => '<tr>' + row.map((c) => `<td class="mono">${esc(c ?? '')}</td>`).join('') + '</tr>'),
          { scroll: true, empty: 'This detection matched nothing. Run attacks first.' })}
      </div></div>`;
      $('#detrows').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }));
  },
};

VIEWS.matrix = {
  icon: '▩', label: 'Matrix',
  async render() {
    return `<div class="head"><div><h2>Coverage matrix</h2>
      <p>Every attack cross-referenced against every detection, compared with what each attack's
      manifest predicted. A red cell is an expectation gap: a detection that was predicted and did
      not fire.</p></div><div class="spacer"></div>
      <div class="actions"><button class="btn primary" id="buildm">Build matrix</button></div></div>
      <div id="mx"><div class="empty"><p>Run attacks, then build the matrix.</p></div></div>`;
  },
  bind() {
    $('#buildm')?.addEventListener('click', async () => {
      const m = await act('Building matrix', () => api('/matrix'));
      if (!m) return;
      const sym = { hit_expected: 'X', hit_unexpected: '+', missed: '!', none: '·' };
      const head = m.detections.map((d) => `<th class="vert">${esc(d)}</th>`).join('');
      const body = m.grid.map((row) => `<tr><td class="rowhead" title="${esc(row.name)}">${esc(row.attack)}</td>${
        row.cells.map((c, i) => `<td><div class="cell ${c}" title="${esc(row.attack)} × ${esc(m.detections[i])}: ${c.replace('_', ' ')}">${sym[c]}</div></td>`).join('')
      }</tr>`).join('');
      $('#mx').innerHTML = `
        ${m.gaps.length
          ? `<div class="note crit"><strong>${m.gaps.length} expectation gap(s).</strong> ${
              m.gaps.map((g) => `${esc(g.attack)} expected ${esc(g.detection)}`).join('; ')}.</div>`
          : '<div class="note"><strong>All attack expectations satisfied.</strong> Every predicted detection fired.</div>'}
        ${m.silent.length ? `<div class="note warn"><strong>Silent detections:</strong> ${esc(m.silent.join(', '))} — no telemetry matched these rules in this run.</div>` : ''}
        <div class="panel"><header><h3>${m.fired}/${m.total} detections fired</h3></header><div class="body">
          <div class="tablewrap"><table class="matrix"><thead><tr><th></th>${head}</tr></thead><tbody>${body}</tbody></table></div>
          <div class="legend">
            <span><span class="cell hit_expected" style="width:20px;height:20px">X</span> fired as predicted</span>
            <span><span class="cell hit_unexpected" style="width:20px;height:20px">+</span> fired, unpredicted</span>
            <span><span class="cell missed" style="width:20px;height:20px">!</span> predicted, did not fire</span>
            <span><span class="cell none" style="width:20px;height:20px">·</span> no hit</span>
          </div>
          <p style="color:var(--fg-2);font-size:12px;margin:14px 0 0">A <strong>+</strong> is not an
          error — it means coverage is broader than predicted. Each one is worth checking by hand to
          confirm it is genuine rather than a false positive.</p>
        </div></div>`;
      toast('Matrix built', `${m.fired}/${m.total} detections fired, ${m.gaps.length} gap(s)`, m.gaps.length ? 'err' : 'good');
    });
  },
};

VIEWS.ir = {
  icon: '✚', label: 'Response',
  async render() {
    const books = await api('/runbooks');
    const incidents = await api('/incidents');
    state.cache.incidents = incidents;
    const rows = books.map((b) => `<tr>
      <td class="mono"><strong>${esc(b.id)}</strong></td>
      <td>${sevPill(b.severity)}</td>
      <td class="wrap"><strong>${esc(b.title)}</strong>
        <div style="color:var(--fg-2);font-size:12px;margin-top:4px">${esc(b.triage.split('\n')[0])}</div></td>
      <td class="mono">${b.detections.map(esc).join(' ')}</td>
      <td class="num">${b.collect.length}</td>
      <td class="mono">${b.contain.length
        ? b.contain.map((c) => esc(c.action)).join('<br>')
        : pill('none', 'high')}</td>
      <td class="mono" style="font-size:11px">${b.nist_csf.map(esc).join(' ')}</td>
    </tr>`);
    return `
    <div class="head"><div><h2>Incident response</h2>
      <p>Nine executable runbooks covering all fourteen detections. Triage collects evidence and
      changes nothing. Respond also applies containment, which the running lab honours — so the same
      attack will then fail.</p></div><div class="spacer"></div>
      <div class="actions">
        <button class="btn" id="triage">Triage (dry run)</button>
        <button class="btn primary" id="respond">Respond &amp; contain</button>
      </div></div>
    <div class="note warn"><strong>Respond mutates the lab.</strong> It quarantines documents,
    disables tools and blocks hosts. Containment overrides the vulnerability toggles by design.
    Reverse it any time from Overview or with <span class="mono">make ir-lift</span>.</div>
    <div id="irresult"></div>
    <div class="panel"><header><h3>Runbooks</h3></header><div class="body flush">
      ${table([{label:'ID'},{label:'Sev'},{label:'Runbook'},{label:'Detections'},{label:'Packs',num:1},{label:'Containment'},{label:'NIST CSF'}], rows)}
    </div></div>
    <div class="panel"><header><h3>Incidents</h3><div class="spacer"></div>
      <span style="color:var(--fg-3);font-size:12px">${incidents.length} on disk</span></header>
      <div class="body flush">${incidents.length ? `<div class="split">
        <div class="list" id="inclist">${incidents.map((i) => `<button data-inc="${esc(i.id)}">
          <div class="t">${esc(i.runbook)}</div>
          <div class="s">${esc(i.id.replace(/^INC-/, ''))} · ${i.evidence_packs} packs</div></button>`).join('')}</div>
        <div id="incdetail" style="padding:15px"><div class="empty"><p>Select an incident.</p></div></div>
      </div>` : '<div class="empty"><p>No incidents yet. Run attacks, then triage.</p></div>'}
    </div>`;
  },
  bind() {
    const run = async (mode) => {
      const r = await act(mode === 'respond' ? 'Executing runbooks and containing' : 'Collecting evidence',
        () => api('/ir/run', { method: 'POST', body: { mode, runbooks: null } }));
      if (!r) return;
      $('#irresult').innerHTML = `<div class="panel"><header>
        <h3>${r.mode === 'respond' ? 'Response' : 'Triage'} — ${r.opened} incident(s) opened</h3>
        <div class="spacer"></div>${r.containment_active ? pill(r.containment_active + ' containment active', 'high') : pill('no containment', 'ok')}
        </header><div class="body">${table(
          [{label:'Runbook'},{label:'Sev'},{label:'Triggered by'},{label:'Evidence'},{label:'Time to detectable'},{label:'MTTD (modelled)'},{label:'Incident'}],
          r.incidents.map((i) => `<tr>
            <td class="mono"><strong>${esc(i.runbook)}</strong><div style="color:var(--fg-2);font-size:11px">${esc(i.title)}</div></td>
            <td>${sevPill(i.severity)}</td>
            <td class="mono">${Object.entries(i.triggered_by).map(([d, n]) => `${esc(d)}(${n})`).join(' ')}</td>
            <td class="num">${i.metrics.measured_evidence_rows} rows</td>
            <td class="num">${fmt(i.metrics.measured_time_to_detectable_s)}s</td>
            <td class="num" style="color:var(--fg-3)">${fmt(i.metrics.modelled_mttd_s)}s</td>
            <td class="mono" style="font-size:11px">${esc(i.incident)}</td></tr>`),
          { empty: 'No runbook matched a fired detection. Run attacks first.' })}
        <p style="color:var(--fg-2);font-size:12px;margin:12px 0 0"><strong>Time to detectable</strong>
        is measured from telemetry. <strong>MTTD is modelled</strong> — measured time plus an assumed
        60-second alert poll interval. MTTR is deliberately not reported: human response time was
        never measured here.</p></div></div>`;
      toast(r.mode === 'respond' ? 'Response complete' : 'Triage complete',
        `${r.opened} incident(s), ${r.containment_active} containment action(s) active`, 'good');
      if (r.mode === 'respond') setTimeout(() => go('ir'), 900);
    };
    $('#triage')?.addEventListener('click', () => run('triage'));
    $('#respond')?.addEventListener('click', () => run('respond'));
    document.querySelectorAll('[data-inc]').forEach((b) => b.addEventListener('click', async () => {
      document.querySelectorAll('[data-inc]').forEach((x) => x.setAttribute('aria-current', 'false'));
      b.setAttribute('aria-current', 'true');
      const inc = await act('Loading incident', () => api(`/incidents/${b.dataset.inc}`));
      if (!inc) return;
      const packs = Object.entries(inc.evidence);
      $('#incdetail').innerHTML = `
        <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
          <button class="btn sm" data-tab="tl" aria-current="true">Timeline</button>
          <button class="btn sm" data-tab="pm">Postmortem</button>
          <button class="btn sm" data-tab="ev">Evidence (${packs.length})</button>
        </div>
        <div class="md scroll" id="tab-tl">${md(inc.timeline)}</div>
        <div class="md scroll hide" id="tab-pm">${md(inc.postmortem)}</div>
        <div class="scroll hide" id="tab-ev">${packs.map(([name, p]) => `
          <div class="panel"><header><h3>${esc(name)}</h3><div class="spacer"></div>
            <span class="mono" style="font-size:11px;color:var(--fg-3)">${p.row_count} rows</span></header>
            <div class="body"><p style="color:var(--fg-2);font-size:12px;margin:0 0 10px">${esc(p.description)}</p>
            ${p.rows.length ? table(Object.keys(p.rows[0]).map((k) => ({ label: k })),
              p.rows.slice(0, 40).map((r) => '<tr>' + Object.values(r).map((v) =>
                `<td class="mono">${esc(typeof v === 'object' ? JSON.stringify(v) : v ?? '')}</td>`).join('') + '</tr>'),
              { scroll: true }) : '<div class="empty"><p>No rows.</p></div>'}
            </div></div>`).join('') || '<div class="empty"><p>No evidence packs.</p></div>'}</div>`;
      $('#incdetail').querySelectorAll('[data-tab]').forEach((t) => t.addEventListener('click', () => {
        $('#incdetail').querySelectorAll('[data-tab]').forEach((x) => x.setAttribute('aria-current', 'false'));
        t.setAttribute('aria-current', 'true');
        ['tl', 'pm', 'ev'].forEach((k) => $(`#tab-${k}`).classList.toggle('hide', k !== t.dataset.tab));
      }));
    }));
  },
};

VIEWS.shadow = {
  icon: '◈', label: 'Shadow AI',
  async render() {
    let reg = null, cloud = null;
    try { reg = await api('/discover'); } catch { /* not scanned yet */ }
    try { cloud = await api('/cloud-egress'); } catch { /* not parsed yet */ }
    return `
    <div class="head"><div><h2>Shadow-AI discovery</h2>
      <p>Endpoint and cloud lenses over unsanctioned AI use. All endpoint lenses run without root;
      live SNI capture needs packet-capture privileges and is CLI-only.</p></div>
      <div class="spacer"></div><div class="actions">
        <button class="btn primary" id="scan">Scan this endpoint</button>
        <button class="btn" id="parsecloud">Parse cloud logs</button>
      </div></div>
    <div id="shadowout">${reg ? renderRegister(reg) : '<div class="empty"><p>No endpoint scan yet.</p></div>'}</div>
    <div id="cloudout">${cloud ? renderCloud(cloud) : ''}</div>`;
  },
  bind() {
    $('#scan')?.addEventListener('click', async () => {
      const r = await act('Scanning endpoint', () => api('/discover/scan', { method: 'POST' }));
      if (!r) return;
      $('#shadowout').innerHTML = renderRegister(r);
      toast('Scan complete', `${r.summary.findings_total} finding(s), posture ${r.summary.posture}`,
        r.summary.posture === 'clean' ? 'good' : 'err');
    });
    $('#parsecloud')?.addEventListener('click', async () => {
      const r = await act('Parsing cloud logs', () => api('/cloud-egress/parse', { method: 'POST' }));
      if (!r) return;
      $('#cloudout').innerHTML = renderCloud(r);
      toast('Cloud logs parsed', `${r.summary.flows_total} flow(s), ${r.summary.unsanctioned_flows} unsanctioned`, 'good');
    });
  },
};

function renderRegister(reg) {
  const s = reg.summary;
  const rows = reg.findings.map((f) => `<tr>
    <td class="num">${riskPill(f.risk_score)}</td>
    <td class="mono">${esc(f.lens)}</td>
    <td><strong>${esc(f.asset)}</strong></td>
    <td class="mono">${esc(f.category)}</td>
    <td class="wrap">${esc(f.detail)}</td>
    <td>${f.sanctioned ? pill('sanctioned', 'ok') : pill('unsanctioned', 'high')}</td>
    <td>${sevPill(f.data_egress_risk)}</td></tr>`);
  return `
    <div class="grid cards" style="margin-bottom:14px">
      <div class="card"><h3>Posture</h3><div class="big" style="font-size:20px;color:${
        s.posture === 'critical' ? 'var(--crit)' : s.posture === 'elevated' ? 'var(--high)' : 'var(--ok)'
      }">${esc(s.posture)}</div><div class="sub">${esc(reg.host)}</div></div>
      <div class="card"><h3>Findings</h3><div class="big">${s.findings_total}</div>
        <div class="sub">${s.unsanctioned} unsanctioned</div></div>
      <div class="card"><h3>Top risk</h3><div class="big">${s.highest_risk_score}<span style="font-size:14px;color:var(--fg-3)">/100</span></div>
        <div class="sub">${Object.entries(s.by_lens).map(([k, v]) => `${k} ${v}`).join(' · ')}</div></div>
    </div>
    ${(reg.notes || []).map((n) => `<div class="note warn">${esc(n)}</div>`).join('')}
    <div class="panel"><header><h3>Asset register</h3><div class="spacer"></div>
      <span class="mono" style="font-size:11px;color:var(--fg-3)">${esc(reg.generated)}</span></header>
      <div class="body flush">${table(
        [{label:'Risk'},{label:'Lens'},{label:'Asset'},{label:'Category'},{label:'Detail'},{label:'Status'},{label:'Egress risk'}],
        rows, { empty: 'No AI assets found by any lens. Start a local model runtime to validate the scanner.' })}
      </div></div>`;
}

function renderCloud(c) {
  const s = c.summary;
  const rows = Object.entries(s.providers).map(([name, v]) => `<tr>
    <td><strong>${esc(name)}</strong></td>
    <td>${v.sanctioned ? pill('sanctioned', 'ok') : pill('unsanctioned', 'high')}</td>
    <td>${sevPill(v.risk)}</td>
    <td class="num">${v.flows}</td>
    <td class="num">${v.bytes.toLocaleString()}</td>
    <td class="mono">${v.sources.map((x) => esc(x.split('_')[0])).join(', ')}</td></tr>`);
  return `<div class="panel"><header><h3>Cloud AI egress</h3><div class="spacer"></div>
    ${pill('synthetic samples', 'accent')}</header><div class="body">
    <div class="note warn">${esc(s.note)}</div>
    ${table([{label:'Provider'},{label:'Status'},{label:'Risk'},{label:'Flows'},{label:'Bytes'},{label:'Sources'}], rows)}
    <p style="color:var(--fg-2);font-size:12px;margin:12px 0 0">Byte volume is the signal that
    separates a health check from a repository being uploaded to a coding assistant.</p>
    </div></div>`;
}

VIEWS.query = {
  icon: '▶', label: 'Query',
  async render() {
    const views = await api('/views');
    return `
    <div class="head"><div><h2>Telemetry query</h2>
      <p>Ad-hoc SQL over the DuckDB views. The same SQL runs in Athena against real S3 prefixes —
      that portability is the point of keeping the schemas faithful. Read-only: only
      <span class="mono">SELECT</span> and <span class="mono">WITH</span> are accepted.</p></div></div>
    <div class="split">
      <div class="panel"><header><h3>Views</h3></header><div class="body flush">
        ${views.length ? `<div class="list">${views.map((v) => `<button data-view="${esc(v.view)}">
          <div class="t mono">${esc(v.view)}</div><div class="s">${v.columns} columns</div></button>`).join('')}</div>`
          : '<div class="empty"><p>No telemetry yet. Run attacks first.</p></div>'}
      </div></div>
      <div>
        <div class="panel"><header><h3>SQL</h3><div class="spacer"></div>
          <button class="btn sm primary" id="runq">Run</button></header><div class="body">
          <textarea id="sql" spellcheck="false">SELECT ts, principal_arn, prompt_chars, input_tokens, guardrail_id
FROM bedrock_invocations
ORDER BY ts DESC
LIMIT 20</textarea>
          <p style="color:var(--fg-3);font-size:12px;margin:8px 0 0">Ctrl+Enter to run.</p>
        </div></div>
        <div id="qout"></div>
      </div>
    </div>`;
  },
  bind() {
    const run = async () => {
      const r = await act('Running query', () => api('/query', { method: 'POST', body: { sql: $('#sql').value, limit: 200 } }));
      if (!r) return;
      $('#qout').innerHTML = `<div class="panel"><header><h3>${r.rows.length} row(s)${r.truncated ? ' (truncated)' : ''}</h3></header>
        <div class="body flush">${table(r.columns.map((c) => ({ label: c })),
          r.rows.map((row) => '<tr>' + row.map((c) => `<td class="mono">${esc(c ?? '')}</td>`).join('') + '</tr>'),
          { scroll: true })}</div></div>`;
    };
    $('#runq')?.addEventListener('click', run);
    $('#sql')?.addEventListener('keydown', (e) => { if (e.ctrlKey && e.key === 'Enter') run(); });
    document.querySelectorAll('[data-view]').forEach((b) => b.addEventListener('click', () => {
      $('#sql').value = `SELECT * FROM ${b.dataset.view} LIMIT 25`;
      run();
    }));
  },
};

VIEWS.atlas = {
  icon: '◇', label: 'ATLAS',
  async render() {
    try {
      const a = await api('/atlas');
      return `<div class="head"><div><h2>MITRE ATLAS coverage</h2>
        <p>Generated from the official ATLAS STIX 2.1 bundle, not hand-maintained. An id claimed in
        the repo that does not exist in the bundle fails the generator — which is what makes this
        evidence rather than decoration.</p></div></div>
        <div class="panel"><div class="body md">${md(a.markdown)}</div></div>`;
    } catch (e) {
      return `<div class="head"><div><h2>MITRE ATLAS coverage</h2></div></div>
        <div class="note crit">${esc(e.message)}</div>`;
    }
  },
  bind() {},
};

/* ---------- router ---------- */
async function go(name) {
  state.view = name;
  document.querySelectorAll('#nav button').forEach((b) =>
    b.setAttribute('aria-current', String(b.dataset.v === name)));
  const view = VIEWS[name];
  $('#main').innerHTML = '<div class="empty"><div class="spin"></div></div>';
  try {
    $('#main').innerHTML = await view.render();
    view.bind();
    document.querySelectorAll('[data-go]').forEach((b) =>
      b.addEventListener('click', () => go(b.dataset.go)));
  } catch (e) {
    $('#main').innerHTML = `<div class="note crit"><strong>Could not load this view.</strong> ${esc(e.message)}</div>`;
  }
  window.scrollTo(0, 0);
}

function buildNav() {
  $('#nav').innerHTML = Object.entries(VIEWS).map(([k, v]) =>
    `<button data-v="${k}"><span class="ico">${v.icon}</span>${v.label}</button>`).join('');
  document.querySelectorAll('#nav button').forEach((b) =>
    b.addEventListener('click', () => go(b.dataset.v)));
}

$('#theme').addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('aircap-theme', next); } catch { /* private mode */ }
});

$('#reset').addEventListener('click', async () => {
  if (!confirm('Reset the lab?\n\nThis lifts containment, deletes all telemetry and incidents, and removes planted corpus documents.')) return;
  const r = await act('Resetting lab', () => api('/reset', { method: 'POST' }));
  if (r) {
    toast('Lab reset', `${r.incidents_removed} incident(s) removed, ${r.containment_lifted} containment action(s) lifted`, 'good');
    go(state.view);
  }
});

try {
  const saved = localStorage.getItem('aircap-theme');
  if (saved) document.documentElement.dataset.theme = saved;
} catch { /* private mode */ }

buildNav();
go('overview');
