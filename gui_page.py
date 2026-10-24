"""Inline HTML/CSS/JS for the Commit Guard local control center.

The page is fully self-contained: no CDN, no fonts, no telemetry. The server
injects a per-run token and the initial repository path with plain string
replacement (``__TOKEN__`` / ``__REPO__``).
"""

from __future__ import annotations

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Commit Guard — Control Center</title>
<style>
:root{
  --bg:#0b0f17;--panel:#121826;--panel2:#0f1420;--line:#243044;--line2:#2f3d56;
  --text:#e6edf7;--muted:#93a4bd;--accent:#4da3ff;--accent2:#7c5cff;
  --ok:#2ec27e;--warn:#f5a524;--bad:#ff5d5d;--crit:#ff3b3b;
  --critical:#ff3b3b;--high:#ff7a45;--medium:#f5a524;--low:#4da3ff;--info:#93a4bd;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:radial-gradient(1200px 700px at 15% -10%,#15213a 0%,var(--bg) 55%) no-repeat,var(--bg);
  color:var(--text);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
button,input,select,textarea{font:inherit;color:inherit}
button{cursor:pointer}
a{color:var(--accent)}
.app{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100vh}
.side{background:linear-gradient(180deg,#101827,#0c111b);border-right:1px solid var(--line);padding:18px 14px;display:flex;flex-direction:column;gap:14px}
.brand{display:flex;align-items:center;gap:10px;padding:4px 6px 12px}
.logo{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:grid;place-items:center;font-weight:800;color:#08101c}
.brand h1{font-size:15px;margin:0;letter-spacing:.3px}
.brand small{display:block;color:var(--muted);font-size:11px;font-weight:500}
.nav{display:flex;flex-direction:column;gap:3px}
.nav button{display:flex;align-items:center;gap:10px;background:transparent;border:0;border-radius:9px;padding:9px 10px;color:var(--muted);text-align:left;font-weight:600}
.nav button:hover{background:#162033;color:var(--text)}
.nav button.active{background:linear-gradient(90deg,#1b2a44,#162033);color:#fff;box-shadow:inset 0 0 0 1px var(--line2)}
.nav .ico{width:20px;text-align:center;opacity:.9}
.side .foot{margin-top:auto;color:var(--muted);font-size:11px;padding:8px 6px;border-top:1px solid var(--line)}
.main{min-width:0;padding:20px 24px 60px}
.top{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:16px}
.top .grow{flex:1;min-width:220px}
.field{display:flex;flex-direction:column;gap:5px}
.field label,.lbl{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
input,select,textarea{background:#0d1421;border:1px solid var(--line2);border-radius:8px;padding:8px 10px;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px #4da3ff22}
textarea{width:100%;min-height:420px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;line-height:1.55}
.btn{border:1px solid var(--line2);background:#162033;border-radius:8px;padding:8px 13px;font-weight:700}
.btn:hover{border-color:#3d5275;background:#1a2740}
.btn.primary{background:linear-gradient(135deg,#2f7fe0,#6a4dff);border-color:transparent;color:#fff}
.btn.primary:hover{filter:brightness(1.08)}
.btn.danger{border-color:#5c2430;background:#2a1419;color:#ff9a9a}
.btn.danger:hover{background:#3a1a21}
.btn.small{padding:5px 9px;font-size:12px;border-radius:7px}
.btn:disabled{opacity:.45;cursor:not-allowed}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.chips{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:10px}
.chip{border:1px solid var(--line2);background:#131c2c;border-radius:999px;padding:3px 9px;font-size:11px;color:var(--muted);font-weight:700}
.chip.ok{color:#9ff0c4;border-color:#1f5c40;background:#0f2a1f}
.chip.warn{color:#ffd18c;border-color:#5c4620;background:#2a2112}
.chip.bad{color:#ffb3b3;border-color:#5c2430;background:#2a1419}
.card{background:linear-gradient(180deg,#121a29,#0f1623);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:16px}
.card h2{font-size:14px;margin:0 0 4px;letter-spacing:.2px}
.card p.hint{margin:0 0 12px;color:var(--muted);font-size:12.5px}
.grid{display:grid;gap:12px}
.grid.g2{grid-template-columns:repeat(2,minmax(0,1fr))}
.grid.g3{grid-template-columns:repeat(3,minmax(0,1fr))}
.grid.g4{grid-template-columns:repeat(4,minmax(0,1fr))}
@media(max-width:1100px){.grid.g3,.grid.g4{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:860px){.app{grid-template-columns:1fr}.side{position:sticky;top:0;z-index:5;flex-direction:row;overflow:auto;align-items:center}.nav{flex-direction:row}.side .foot{display:none}.brand small{display:none}.grid.g2{grid-template-columns:1fr}}
.stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin-bottom:12px}
@media(max-width:900px){.stats{grid-template-columns:repeat(3,minmax(0,1fr))}}
.stat{background:#0f1725;border:1px solid var(--line);border-radius:12px;padding:10px 12px}
.stat b{display:block;font-size:20px;line-height:1.2}
.stat span{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;font-weight:700}
.stat.critical b{color:var(--critical)}.stat.high b{color:var(--high)}.stat.medium b{color:var(--medium)}
.stat.low b{color:var(--low)}.stat.info b{color:var(--info)}
.banner{display:flex;gap:14px;align-items:center;justify-content:space-between;flex-wrap:wrap;padding:12px 14px;border-radius:12px;border:1px solid var(--line2);background:#101a2b;margin-bottom:12px}
.banner.fail{border-color:#5c2430;background:linear-gradient(90deg,#241018,#101a2b)}
.banner.pass{border-color:#1f5c40;background:linear-gradient(90deg,#0f241b,#101a2b)}
.banner strong{font-size:14px}
.banner .actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
table{width:100%;border-collapse:collapse}
th,td{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}
tr:hover td{background:#121c2e}
.th-check{width:36px;text-align:center}
.td-check{text-align:center;vertical-align:middle;padding-top:12px}
.td-check input{cursor:pointer}
.applied-row{background:#0b1d16!important}
.applied-row td{border-bottom-color:#163827}
.sev{display:inline-block;border-radius:999px;padding:2px 8px;font-size:10.5px;font-weight:800;text-transform:uppercase;letter-spacing:.05em}
.sev.critical{background:#3a1114;color:#ff9a9a;border:1px solid #6a1f26}
.sev.high{background:#3a2111;color:#ffbd8a;border:1px solid #6a3a1f}
.sev.medium{background:#392c10;color:#ffd88a;border:1px solid #6a5520}
.sev.low{background:#12283a;color:#9ed0ff;border:1px solid #1f4a6a}
.sev.info{background:#1b2230;color:#b7c3d6;border:1px solid #33415a}
.btn.suggest{background:#132338;border-color:#2a4d7c;color:#70b8ff}
.btn.suggest:hover{background:#183050;border-color:#3e6eb0;color:#fff;box-shadow:0 0 12px #4da3ff25}
.btn.apply{background:linear-gradient(135deg,#059669,#10b981);border-color:transparent;color:#fff;font-weight:700}
.btn.apply:hover{filter:brightness(1.12);box-shadow:0 0 14px #10b98144}
.btn.applied{background:#0e2a1d;border:1px solid #1e6b43;color:#86efac;cursor:default;opacity:.9}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
td code{font-size:12px}
.muted{color:var(--muted)}
.small{font-size:12px}
.right{text-align:right}
.pre{white-space:pre-wrap;word-break:break-word;background:#0a101a;border:1px solid var(--line);border-radius:10px;padding:12px;max-height:420px;overflow:auto;font-size:12px}
.diff{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.diff div{background:#0a101a;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;font-size:12px}
.diff .before{border-color:#5c2430;background:#170a0e}.diff .after{border-color:#1f5c40;background:#081810}
.diff-tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;margin-bottom:6px}
.diff-tag.red{background:#3d1015;color:#ff9a9a;border:1px solid #631c25}
.diff-tag.green{background:#0d2f1d;color:#86efac;border:1px solid #195e3a}
.hidden{display:none!important}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.tabs button{background:#101827;border:1px solid var(--line);border-radius:999px;padding:6px 12px;color:var(--muted);font-weight:700;font-size:12px}
.tabs button.active{color:#fff;border-color:var(--accent);background:#16233a}
.details{background:#0d1421;border:1px solid var(--line);border-radius:10px;padding:10px;margin-top:8px}
.details summary{cursor:pointer;color:var(--muted);font-weight:700;font-size:12px}
.spinner{width:14px;height:14px;border:2px solid #ffffff44;border-top-color:#fff;border-radius:50%;display:inline-block;animation:spin .8s linear infinite;vertical-align:-2px}
@keyframes spin{to{transform:rotate(360deg)}}
.toasts{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:8px;z-index:60;max-width:380px}
.toast{background:#151f30;border:1px solid var(--line2);border-left:4px solid var(--accent);border-radius:10px;padding:10px 12px;box-shadow:0 12px 40px #0008;font-size:12.5px}
.toast.ok{border-left-color:var(--ok)}.toast.bad{border-left-color:var(--bad)}.toast.warn{border-left-color:var(--warn)}
.modal{position:fixed;inset:0;background:#0009;display:none;place-items:center;padding:20px;z-index:70}
.modal.show{display:grid}
.modal .box{background:#101827;border:1px solid var(--line2);border-radius:14px;max-width:820px;width:100%;max-height:85vh;overflow:auto;padding:18px}
.modal h3{margin:0 0 10px}
.kbd{background:#0a101a;border:1px solid var(--line2);border-bottom-width:2px;border-radius:5px;padding:1px 5px;font-size:11px}
.notice{border-left:3px solid var(--warn);background:#241d10;border-radius:8px;padding:9px 11px;color:#ffd9a1;font-size:12.5px;margin:10px 0}
.okbox{border-left:3px solid var(--ok);background:#0f241b;border-radius:8px;padding:9px 11px;font-size:12.5px}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand">
      <div class="logo">CG</div>
      <div><h1>Commit Guard</h1><small>Local Control Center</small></div>
    </div>
    <nav class="nav" id="nav">
      <button data-tab="scan" class="active"><span class="ico">▣</span> Scan</button>
      <button data-tab="fixes"><span class="ico">✦</span> Fixes &amp; suggestions</button>
      <button data-tab="pr"><span class="ico">⇅</span> Pull requests</button>
      <button data-tab="baseline"><span class="ico">◈</span> Baseline</button>
      <button data-tab="rules"><span class="ico">▤</span> Rules</button>
      <button data-tab="reports"><span class="ico">▦</span> Reports</button>
      <button data-tab="maintenance"><span class="ico">⚙</span> Maintenance</button>
      <button data-tab="config"><span class="ico">⌘</span> Configuration</button>
      <button data-tab="help"><span class="ico">?</span> Help</button>
    </nav>
    <div class="foot">
      <div>Local only · 127.0.0.1</div>
      <div id="versionLine">Commit Guard</div>
    </div>
  </aside>

  <main class="main">
    <div class="top">
      <div class="field grow">
        <label for="repoPath">Repository</label>
        <input id="repoPath" placeholder="/path/to/git/repository" spellcheck="false">
      </div>
      <button class="btn" id="loadRepoBtn">Load</button>
      <button class="btn" id="refreshInfoBtn">Refresh status</button>
    </div>
    <div class="chips" id="repoChips"></div>

    <section id="tab-scan">
      <div class="card">
        <h2>Scan your changes</h2>
        <p class="hint">Scans staged changes by default. Everything runs locally; secrets are redacted unless you explicitly opt in.</p>
        <div class="grid g3">
          <div class="field"><label for="mode">Scan mode</label>
            <select id="mode">
              <option value="staged">Staged changes (what a commit would include)</option>
              <option value="all">Whole working tree</option>
              <option value="history">Commit history</option>
              <option value="diff">Revision range</option>
            </select>
          </div>
          <div class="field"><label for="threshold">Blocking threshold</label>
            <select id="threshold">
              <option>critical</option><option selected>high</option><option>medium</option><option>low</option><option>info</option>
            </select>
          </div>
          <div class="field hidden" id="historyWrap"><label for="historyN">Commits to audit (0 = all)</label>
            <input id="historyN" type="number" min="0" value="50">
          </div>
          <div class="field hidden" id="diffWrap"><label for="diffRange">Revision range</label>
            <input id="diffRange" placeholder="origin/main...HEAD">
          </div>
        </div>
        <details class="details">
          <summary>Advanced scan options</summary>
          <div class="grid g3" style="margin-top:10px">
            <label class="small"><input type="checkbox" id="optNoBaseline"> Ignore baseline (.commit_guard_ignore)</label>
            <label class="small"><input type="checkbox" id="optNoCache"> Disable rule cache</label>
            <label class="small"><input type="checkbox" id="optPlaceholders"> Report placeholder/example secrets</label>
            <label class="small"><input type="checkbox" id="optDepGraph"> Build dependency graph</label>
            <div class="field"><label for="depGraphFormat">Dependency graph format</label>
              <select id="depGraphFormat"><option>mermaid</option><option>json</option><option>dot</option><option>all</option></select>
            </div>
            <div class="field"><label for="depGraphMax">Graph max nodes</label><input id="depGraphMax" type="number" min="1" value="250"></div>
            <label class="small"><input type="checkbox" id="optSca"> Dependency vulnerability check (SCA)</label>
            <label class="small"><input type="checkbox" id="optScaOnline"> SCA online (OSV.dev network)</label>
            <div class="field"><label for="scaSnapshot">SCA snapshot file</label><input id="scaSnapshot" placeholder="optional local snapshot"></div>
            <div class="field"><label for="scaTimeout">SCA timeout (seconds)</label><input id="scaTimeout" type="number" min="1" value="20"></div>
            <div class="field"><label for="failOn">Baseline failure mode</label>
              <select id="failOn"><option value="">Config default</option><option value="all">Block all findings</option><option value="new">Block only new findings</option></select>
            </div>
            <label class="small" style="color:#ffb3b3"><input type="checkbox" id="optShowSecrets"> Show secret values in results (unsafe)</label>
          </div>
        </details>
        <div class="row" style="margin-top:14px">
          <button class="btn primary" id="scanBtn">Run scan</button>
          <span class="muted small" id="scanStatus">Ready.</span>
        </div>
      </div>

      <div id="results" class="hidden">
        <div class="banner" id="resultBanner"></div>
        <div class="stats" id="stats"></div>
        <div class="card">
          <div class="row" style="justify-content:space-between;margin-bottom:10px">
            <div class="row">
              <div class="field"><label for="filterSeverity">Severity</label>
                <select id="filterSeverity"><option value="">All</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
              </div>
              <div class="field"><label for="filterText">Search</label><input id="filterText" placeholder="file, rule, description..."></div>
              <label class="small" style="margin-bottom:8px"><input type="checkbox" id="filterFixable"> Fixable only</label>
            </div>
            <div class="row">
              <button class="btn small" data-export="html">Open HTML report</button>
              <button class="btn small" data-export="json">JSON</button>
              <button class="btn small" data-export="sarif">SARIF</button>
              <button class="btn small" data-export="markdown">Markdown</button>
            </div>
          </div>
          <div class="row" id="bulkActionsRow" style="margin-bottom:12px;padding:8px 12px;background:#0e1625;border:1px solid var(--line2);border-radius:10px;justify-content:space-between;align-items:center">
            <div class="row" style="align-items:center;gap:8px">
              <button class="btn small suggest" id="suggestAllFixesBtn" title="Preview all available automated fixes and recommendations">💡 Suggest all fixes (<span id="fixableCountBadge">0</span>)</button>
              <button class="btn small apply" id="applySelectedFixesBtn" disabled title="Apply selected fixes and stage modified files">⚡ Apply selected fixes (<span id="selectedFixCount">0</span>)</button>
              <button class="btn small" id="selectAllFixableBtn">Select all fixable</button>
              <button class="btn small" id="deselectAllBtn" style="display:none">Deselect all</button>
            </div>
            <div class="small muted" id="selectedInfoText">Click checkboxes to apply multiple fixes at once</div>
          </div>
          <div style="overflow:auto">
            <table id="findingsTable">
              <thead><tr>
                <th class="th-check"><input type="checkbox" id="checkAllFindings" title="Select / deselect all fixable findings"></th>
                <th>Severity</th><th>Rule</th><th>Location</th><th>Description</th><th>Code</th><th class="right">Actions</th>
              </tr></thead>
              <tbody id="findingsBody"></tbody>
            </table>
          </div>
          <p class="hint" id="findingCount" style="margin:10px 0 0"></p>
        </div>
      </div>
    </section>

    <section id="tab-fixes" class="hidden">
      <div class="card">
        <h2>Safe fixes &amp; suggestions</h2>
        <p class="hint">Preview rule-provided fixes, choose exactly which ones to apply, then Commit Guard writes and stages the files just like <code>scan --fix</code>. Secrets are never auto-fixed.</p>
        <div class="row" style="align-items:center;gap:8px">
          <button class="btn" id="previewFixesBtn">Preview fixes from last scan</button>
          <button class="btn primary apply" id="applyFixesBtn" disabled>⚡ Apply selected fixes</button>
          <button class="btn suggest" id="suggestionsBtn">💡 Preview PR inline suggestions</button>
        </div>
        <div id="fixOutput" style="margin-top:14px"></div>
      </div>
      <div class="card hidden" id="suggestionsCard">
        <h2>Inline PR suggestions</h2>
        <p class="hint">These are the exact suggestions that <code>--review-pr</code> would post on a pull request.</p>
        <div id="suggestionsOut"></div>
      </div>
    </section>

    <section id="tab-pr" class="hidden">
      <div class="card">
        <h2>Create or update a report pull request</h2>
        <p class="hint">Publishes a commit with the report and opens/updates a pull request. Requires a GitHub token with repository access. The token stays in this page's memory and is never written to disk.</p>
        <div class="notice">Use a fine-grained token with <b>Contents: read/write</b> and <b>Pull requests: read/write</b> for the target repository.</div>
        <div class="grid g3">
          <div class="field"><label for="ghRepo">GitHub repository (owner/repo)</label><input id="ghRepo" placeholder="owner/repo"></div>
          <div class="field"><label for="ghToken">GitHub token</label><input id="ghToken" type="password" autocomplete="off" placeholder="ghp_... (session only)"></div>
          <div class="field"><label for="ghBase">Base branch</label><input id="ghBase" placeholder="main"></div>
          <div class="field"><label for="ghBranch">Report branch</label><input id="ghBranch" placeholder="commitguard/security-report"></div>
          <div class="field"><label for="ghTitle">PR title</label><input id="ghTitle" placeholder="CommitGuard security report"></div>
        </div>
        <div class="row" style="margin-top:12px">
          <button class="btn primary" id="createPrBtn">Create / update PR</button>
          <span class="muted small" id="prStatus"></span>
        </div>
        <div id="prResult" style="margin-top:12px"></div>
      </div>
      <div class="card">
        <h2>Post inline suggestions to an existing PR</h2>
        <p class="hint">Adds click-to-commit suggestions for auto-fixable findings to the PR diff. The PR must be open and the token needs Pull requests write access.</p>
        <div class="grid g3">
          <div class="field"><label for="prNumber">Pull request number</label><input id="prNumber" type="number" min="1" placeholder="123"></div>
        </div>
        <div class="row" style="margin-top:12px">
          <button class="btn" id="reviewPrBtn">Post inline suggestions</button>
          <span class="muted small" id="reviewStatus"></span>
        </div>
        <div id="reviewResult" style="margin-top:12px"></div>
      </div>
    </section>

    <section id="tab-baseline" class="hidden">
      <div class="card">
        <h2>Baseline &amp; suppressions</h2>
        <p class="hint">Accept current findings into <code>.commit_guard_ignore</code>, audit stale entries, or suppress one finding at a time from the Scan tab.</p>
        <div class="grid g3">
          <div class="field"><label for="baselineOwner">Owner (optional)</label><input id="baselineOwner" placeholder="security-team"></div>
          <div class="field"><label for="baselineExpiry">Expiry (YYYY-MM-DD, optional)</label><input id="baselineExpiry" placeholder="2026-12-31"></div>
          <div class="field"><label>&nbsp;</label><button class="btn" id="updateBaselineBtn">Add current findings to baseline</button></div>
        </div>
        <div class="row" style="margin-top:12px">
          <button class="btn" id="auditBtn">Audit suppressions</button>
          <button class="btn" id="reloadBaselineBtn">Reload entries</button>
        </div>
        <div id="auditOut" style="margin-top:12px"></div>
      </div>
      <div class="card">
        <h2>Entries</h2>
        <div style="overflow:auto"><table>
          <thead><tr><th>Line</th><th>Kind</th><th>Value</th><th>Owner</th><th>Expiry</th></tr></thead>
          <tbody id="baselineBody"></tbody>
        </table></div>
        <p class="hint" id="baselinePath"></p>
      </div>
    </section>

    <section id="tab-rules" class="hidden">
      <div class="card">
        <h2>Rule explorer</h2>
        <div class="row" style="justify-content:space-between;margin-bottom:10px">
          <div class="row">
            <div class="field"><label for="ruleSearch">Search</label><input id="ruleSearch" placeholder="id, description, tag..."></div>
            <div class="field"><label for="ruleSource">Source</label><select id="ruleSource"><option value="">All</option></select></div>
            <label class="small" style="margin-bottom:8px"><input type="checkbox" id="ruleFixable"> Fixable only</label>
          </div>
          <div class="row">
            <button class="btn" id="loadRulesBtn">Load rules</button>
            <button class="btn" id="checkRulesBtn">Validate rules</button>
          </div>
        </div>
        <div style="overflow:auto"><table>
          <thead><tr><th>Rule</th><th>Severity</th><th>Source</th><th>Tags</th><th>Flags</th><th></th></tr></thead>
          <tbody id="rulesBody"></tbody>
        </table></div>
        <p class="hint" id="rulesCount"></p>
      </div>
    </section>

    <section id="tab-reports" class="hidden">
      <div class="card">
        <h2>Generate &amp; download reports</h2>
        <p class="hint">Built from the last scan in memory — no rescanning. “Save to repo” writes into the configured report directory.</p>
        <div class="row">
          <div class="field"><label for="exportFormat">Format</label>
            <select id="exportFormat">
              <option value="html">HTML dashboard</option><option value="json">JSON</option>
              <option value="markdown">Markdown</option><option value="sarif">SARIF</option>
              <option value="junit">JUnit XML</option><option value="gitlab">GitLab Code Quality</option>
              <option value="checkstyle">Checkstyle XML</option>
            </select>
          </div>
          <button class="btn primary" id="downloadReportBtn">Download</button>
          <button class="btn" id="saveReportBtn">Save to repo</button>
          <button class="btn" id="openReportBtn">Open in browser</button>
        </div>
        <div id="exportOut" style="margin-top:12px"></div>
      </div>
      <div class="card">
        <h2>Report directory</h2>
        <div class="row" style="margin-bottom:10px"><button class="btn small" id="reloadReportsBtn">Refresh</button><span class="muted small" id="reportDir"></span></div>
        <div style="overflow:auto"><table>
          <thead><tr><th>File</th><th>Size</th><th>Modified</th><th class="right"></th></tr></thead>
          <tbody id="reportsBody"></tbody>
        </table></div>
      </div>
    </section>

    <section id="tab-maintenance" class="hidden">
      <div class="card">
        <h2>Install &amp; health</h2>
        <p class="hint">These actions run the same manager as <code>./commit-guard</code>. Destructive actions require confirmation.</p>
        <div class="grid g3">
          <div class="field"><label for="installProfile">Install profile</label>
            <select id="installProfile"><option value="">default</option><option>balanced</option><option>strict</option><option>audit</option></select>
          </div>
          <label class="small" style="margin-bottom:8px"><input type="checkbox" id="installForce"> Force overwrite rules</label>
          <label class="small" style="margin-bottom:8px"><input type="checkbox" id="installPrePush"> Install pre-push hook</label>
        </div>
        <div class="row" style="margin-top:12px">
          <button class="btn" data-maint="status">Status</button>
          <button class="btn" data-maint="doctor">Doctor</button>
          <button class="btn" data-maint="install">Install / repair</button>
          <button class="btn" data-maint="update">Update engine</button>
          <button class="btn" data-maint="enable">Enable hook</button>
          <button class="btn" data-maint="disable">Disable hook</button>
          <button class="btn" data-maint="init">Write default config</button>
          <button class="btn danger" data-maint="uninstall">Uninstall</button>
        </div>
      </div>
      <div class="card"><h2>Output</h2><pre class="pre" id="maintOut">No action run yet.</pre></div>
    </section>

    <section id="tab-config" class="hidden">
      <div class="card">
        <h2>Configuration (.commit_guard.toml)</h2>
        <p class="hint">Validated with the same loader as scans. Saving keeps one backup (<code>.commit_guard.toml.bak</code>).</p>
        <div class="row" style="margin-bottom:10px">
          <button class="btn" id="reloadConfigBtn">Reload</button>
          <button class="btn primary" id="saveConfigBtn">Save</button>
          <button class="btn" id="restoreConfigBtn">Restore backup</button>
          <button class="btn" id="defaultConfigBtn">Insert template</button>
          <span class="muted small" id="configStatus"></span>
        </div>
        <textarea id="configText" spellcheck="false"></textarea>
        <div id="configOut" style="margin-top:12px"></div>
      </div>
    </section>

    <section id="tab-help" class="hidden">
      <div class="card">
        <h2>What can I do here?</h2>
        <table>
          <tr><td><b>Scan</b></td><td>Run the same checks as <code>git commit</code>, CI, and <code>./commit-guard scan</code>.</td></tr>
          <tr><td><b>Fixes</b></td><td>Preview rule-provided fixes, apply only what you select, and stage the result.</td></tr>
          <tr><td><b>Pull requests</b></td><td>Publish a report PR or post inline fix suggestions to an existing PR.</td></tr>
          <tr><td><b>Baseline</b></td><td>Accept findings, add owner/expiry metadata, audit stale suppressions.</td></tr>
          <tr><td><b>Rules</b></td><td>Browse active rules, inspect patterns, validate the rule pack.</td></tr>
          <tr><td><b>Reports</b></td><td>Download HTML, JSON, SARIF, JUnit, GitLab, Checkstyle, or Markdown.</td></tr>
          <tr><td><b>Maintenance</b></td><td>Install, update, enable/disable the hook, run doctor, uninstall.</td></tr>
          <tr><td><b>Configuration</b></td><td>Edit <code>.commit_guard.toml</code> with validation and backup.</td></tr>
        </table>
        <h3 style="margin-top:18px">Privacy &amp; safety</h3>
        <ul class="small muted">
          <li>The server binds to <code>127.0.0.1</code> and requires a per-run token.</li>
          <li>Secret values are redacted unless you tick “Show secret values”.</li>
          <li>GitHub tokens live only in this page's memory and are sent to the local server per action.</li>
          <li>No telemetry, no CDN, no external requests except an opt-in SCA/PR action.</li>
        </ul>
        <h3>Keyboard</h3>
        <p class="small muted">Use <span class="kbd">Tab</span> to move between controls and <span class="kbd">Enter</span> to activate buttons. Press <span class="kbd">Esc</span> to close dialogs.</p>
      </div>
    </section>
  </main>
</div>

<div class="toasts" id="toasts"></div>
<div class="modal" id="modal"><div class="box"><h3 id="modalTitle"></h3><div id="modalBody"></div><div class="row" style="margin-top:14px;justify-content:flex-end"><button class="btn" id="modalClose">Close</button></div></div></div>

<script>
"use strict";
const TOKEN = "__TOKEN__";
const INITIAL_REPO = "__REPO__";
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const state = { repo: INITIAL_REPO, info: null, report: null, options: null, rules: [], lastFixes: [] };
let ghToken = "";

function esc(value){
  return String(value === undefined || value === null ? "" : value)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
function fmtBytes(n){ if(n<1024) return n+" B"; if(n<1048576) return (n/1024).toFixed(1)+" KB"; return (n/1048576).toFixed(1)+" MB"; }
function fmtTime(ts){ try { return new Date(ts*1000).toLocaleString(); } catch(e){ return ts; } }
function notify(msg, kind){
  const el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), 6000);
}
function modal(title, html){
  $("#modalTitle").textContent = title;
  $("#modalBody").innerHTML = html;
  $("#modal").classList.add("show");
}
$("#modalClose").addEventListener("click", () => $("#modal").classList.remove("show"));
$("#modal").addEventListener("click", (e) => { if(e.target === $("#modal")) $("#modal").classList.remove("show"); });
document.addEventListener("keydown", (e) => { if(e.key === "Escape") $("#modal").classList.remove("show"); });

async function api(path, options){
  const opts = Object.assign({method:"GET"}, options || {});
  opts.headers = Object.assign({"X-CG-Token": TOKEN}, opts.headers || {});
  if(opts.body !== undefined && typeof opts.body !== "string"){
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  const response = await fetch(path, opts);
  const type = response.headers.get("content-type") || "";
  let data;
  if(type.includes("application/json")) data = await response.json();
  else data = await response.text();
  if(!response.ok){
    const message = (data && data.error) ? data.error : (typeof data === "string" ? data : response.statusText);
    const err = new Error(message);
    err.detail = data && data.detail ? data.detail : null;
    throw err;
  }
  return data;
}
function showTab(name){
  $$("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  $$("main > section").forEach((s) => s.classList.toggle("hidden", s.id !== "tab-" + name));
  if(name === "reports") loadReports().catch(()=>{});
  if(name === "baseline") loadBaseline().catch(()=>{});
  if(name === "config") loadConfig().catch(()=>{});
  if(name === "rules" && !state.rules.length) loadRules().catch(()=>{});
}
$$("#nav button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));

function setChips(){
  const info = state.info;
  const chips = [];
  if(!info){ $("#repoChips").innerHTML = ""; return; }
  chips.push('<span class="chip">' + esc(info.branch || "no branch") + '</span>');
  chips.push('<span class="chip ' + (info.installed ? "ok" : "warn") + '">' + (info.installed ? "installed" : "not installed") + '</span>');
  if(info.hook === "active") chips.push('<span class="chip ok">hook active</span>');
  else if(info.hook === "disabled") chips.push('<span class="chip warn">hook disabled</span>');
  else if(info.hook === "missing") chips.push('<span class="chip bad">no hook</span>');
  else chips.push('<span class="chip">external hook</span>');
  if(info.config_exists) chips.push('<span class="chip ok">config</span>');
  if(info.baseline_exists) chips.push('<span class="chip">baseline</span>');
  if(info.github) chips.push('<span class="chip">' + esc(info.github) + '</span>');
  if(info.config_error) chips.push('<span class="chip bad">config error</span>');
  $("#repoChips").innerHTML = chips.join("");
  $("#versionLine").textContent = "Commit Guard v" + (info.version || "");
  if(info.github && !$("#ghRepo").value) $("#ghRepo").value = info.github;
}

async function loadRepo(repo){
  const target = (repo || $("#repoPath").value || state.repo || INITIAL_REPO || "").trim();
  if(!target){ notify("Enter a repository path.", "warn"); return; }
  $("#loadRepoBtn").disabled = true;
  try{
    const info = await api("/api/repo/info?repo=" + encodeURIComponent(target));
    state.repo = info.root;
    state.info = info;
    $("#repoPath").value = info.root;
    try { localStorage.setItem("commitguard.repo", info.root); } catch(e){}
    setChips();
    const snap = await api("/api/state?repo=" + encodeURIComponent(info.root));
    if(snap && snap.repo === info.root && snap.report){
      state.report = snap.report;
      state.options = snap.options || null;
      renderResults();
      notify("Loaded previous scan for this repository.", "ok");
    }
    notify("Repository loaded.", "ok");
  }catch(err){
    notify(err.message, "bad");
  }finally{
    $("#loadRepoBtn").disabled = false;
  }
}
$("#loadRepoBtn").addEventListener("click", () => loadRepo());
$("#refreshInfoBtn").addEventListener("click", () => loadRepo(state.repo));
$("#repoPath").addEventListener("keydown", (e) => { if(e.key === "Enter") loadRepo(); });

function syncMode(){
  const mode = $("#mode").value;
  $("#historyWrap").classList.toggle("hidden", mode !== "history");
  $("#diffWrap").classList.toggle("hidden", mode !== "diff");
}
$("#mode").addEventListener("change", syncMode);
syncMode();

function gatherOptions(){
  const options = {
    mode: $("#mode").value,
    threshold: $("#threshold").value,
    history: $("#historyN").value,
    diff: $("#diffRange").value.trim(),
    no_baseline: $("#optNoBaseline").checked,
    no_cache: $("#optNoCache").checked,
    no_placeholder_filter: $("#optPlaceholders").checked,
    show_secrets: $("#optShowSecrets").checked,
    dep_graph: $("#optDepGraph").checked,
    dep_graph_format: $("#depGraphFormat").value,
    dep_graph_max_nodes: $("#depGraphMax").value,
    sca: $("#optSca").checked,
    sca_online: $("#optScaOnline").checked,
    sca_snapshot: $("#scaSnapshot").value.trim(),
    sca_timeout: $("#scaTimeout").value,
    fail_on: $("#failOn").value
  };
  return options;
}

async function runScan(){
  const button = $("#scanBtn");
  const status = $("#scanStatus");
  button.disabled = true;
  status.innerHTML = '<span class="spinner"></span> Scanning...';
  if($("#optShowSecrets").checked && !confirm("Show raw secret values in this page and exported reports?")) {
    button.disabled = false; status.textContent = "Cancelled."; return;
  }
  try{
    const options = gatherOptions();
    const data = await api("/api/scan", {method:"POST", body:{repo:state.repo, options}});
    state.report = data.report;
    state.options = options;
    renderResults();
    const total = data.report.total || 0;
    status.textContent = "Scanned in " + (data.duration_ms/1000).toFixed(2) + "s · exit " + data.exit_code;
    notify(total ? total + " finding(s) — " + (data.report.summary.high||0) + " high, " + (data.report.summary.critical||0) + " critical." : "No findings.", total ? "warn" : "ok");
  }catch(err){
    status.textContent = "Scan failed.";
    notify(err.message, "bad");
    if(err.detail && err.detail.stderr) modal("Scan failed", "<pre class='pre'>" + esc(err.detail.stderr || err.detail.stdout) + "</pre>");
  }finally{
    button.disabled = false;
  }
}
$("#scanBtn").addEventListener("click", runScan);

function summarize(){
  const report = state.report;
  if(!report) return;
  const summary = report.summary || {};
  const order = ["critical","high","medium","low","info"];
  $("#stats").innerHTML = order.map((sev) =>
    '<div class="stat ' + sev + '"><b>' + (summary[sev] || 0) + '</b><span>' + sev + '</span></div>'
  ).join("") + '<div class="stat"><b>' + (report.fixable || 0) + '</b><span>fix candidates</span></div>';
  const blocking = report.blocked;
  const banner = $("#resultBanner");
  banner.className = "banner " + (blocking ? "fail" : "pass");
  banner.innerHTML =
    '<div><strong>' + (blocking ? "Blocked" : "Passed") + '</strong> · ' +
    (report.total || 0) + ' finding(s) · threshold ' + esc(report.block_threshold || "high") +
    (report.truncated ? ' · results truncated' : '') +
    (report.redacted === false ? ' · <span style="color:#ff9ab0">secrets visible</span>' : '') +
    '<div class="muted small">Generated ' + esc(report.generated || "") + '</div></div>' +
    '<div class="actions">' +
      (report.fixable ? '<button class="btn suggest" data-banner="suggest-all">💡 Suggest fixes (' + report.fixable + ')</button>' : '') +
      (report.fixable ? '<button class="btn apply" data-banner="apply-all">⚡ Quick apply all (' + report.fixable + ')</button>' : '') +
      '<button class="btn" data-banner="pr">Create PR</button>' +
      '<button class="btn" data-banner="rescan">Rescan</button>' +
    '</div>';
  banner.querySelectorAll("[data-banner]").forEach((b) => b.addEventListener("click", () => {
    const action = b.dataset.banner;
    if(action === "suggest-all"){ showTab("fixes"); previewFixes().catch((e)=>notify(e.message,"bad")); }
    else if(action === "apply-all"){ applyAllFixable(); }
    else if(action === "pr") showTab("pr");
    else runScan();
  }));
  updateFixSelectionUI();
}

function updateFixSelectionUI(){
  const fixableRows = (state.report && state.report.findings ? state.report.findings : []).filter((f) => f.fixable && !f._applied);
  const badge = $("#fixableCountBadge");
  if(badge) badge.textContent = fixableRows.length;
  const checkedBoxes = $$(".finding-check:checked");
  const countSpan = $("#selectedFixCount");
  if(countSpan) countSpan.textContent = checkedBoxes.length;
  const applyBtn = $("#applySelectedFixesBtn");
  if(applyBtn) applyBtn.disabled = checkedBoxes.length === 0;
  const infoText = $("#selectedInfoText");
  if(infoText){
    infoText.textContent = checkedBoxes.length
      ? checkedBoxes.length + " finding(s) selected for bulk fix"
      : fixableRows.length + " automated fix(es) available";
  }
}

function filteredFindings(){
  const report = state.report;
  if(!report) return [];
  const sev = $("#filterSeverity").value;
  const text = $("#filterText").value.trim().toLowerCase();
  const fixableOnly = $("#filterFixable").checked;
  return (report.findings || []).filter((f) => {
    if(sev && f.severity !== sev) return false;
    if(fixableOnly && !f.fixable) return false;
    if(text){
      const hay = [f.file,f.rule_id,f.description,f.source,f.cwe,(f.tags||[]).join(" ")].join(" ").toLowerCase();
      if(!hay.includes(text)) return false;
    }
    return true;
  });
}

function renderFindings(){
  const rows = filteredFindings();
  const body = $("#findingsBody");
  if(!rows.length){
    body.innerHTML = '<tr><td colspan="7" class="muted">No findings match the current filters.</td></tr>';
  } else {
    body.innerHTML = rows.map((f, idx) => {
      const fp = esc(f.fingerprint || "");
      const tags = (f.tags || []).map((t) => '<span class="chip">' + esc(t) + '</span>').join(" ");
      const isApplied = !!f._applied;
      const canCheck = f.fixable && !isApplied;
      return '<tr data-idx="' + idx + '" class="' + (isApplied ? 'applied-row' : '') + '">' +
        '<td class="td-check"><input type="checkbox" class="finding-check" data-idx="' + idx + '" data-fp="' + fp + '" ' + (canCheck ? '' : 'disabled') + ' ' + (f._selected ? 'checked' : '') + '></td>' +
        '<td><span class="sev ' + esc(f.severity) + '">' + esc(f.severity) + '</span></td>' +
        '<td><code>' + esc(f.rule_id) + '</code>' +
          (f.fixable ? ' <span class="chip ok" title="Automated fix available">⚡ fixable</span>' : '') +
          (isApplied ? ' <span class="chip ok" style="background:#0d2f1d;color:#86efac">applied</span>' : '') +
        '</td>' +
        '<td><code>' + esc(f.file) + ':' + esc(f.line) + '</code></td>' +
        '<td>' + esc(f.description) + '<div class="details hidden" id="detail-' + idx + '">' +
          '<div class="small muted">source: ' + esc(f.source || "") + (f.cwe ? ' · ' + esc(f.cwe) : '') + (f.baseline_state ? ' · baseline: ' + esc(f.baseline_state) : '') + '</div>' +
          (tags ? '<div class="chips" style="margin-top:6px">' + tags + '</div>' : '') +
          (f.fixed_versions && f.fixed_versions.length ? '<div class="small">fixed versions: ' + esc(f.fixed_versions.join(", ")) + '</div>' : '') +
          (f.advisory_url ? '<div class="small"><a href="' + esc(f.advisory_url) + '" target="_blank" rel="noreferrer">advisory</a></div>' : '') +
          '<div class="small muted">fingerprint: <code>' + fp + '</code></div>' +
        '</div></td>' +
        '<td><code>' + esc(f.flagged_code || "") + '</code></td>' +
        '<td class="right" style="white-space:nowrap">' +
          '<button class="btn small suggest" data-act="suggest-fix" data-idx="' + idx + '" title="View suggested remediation or automated fix diff">💡 Suggest fix</button> ' +
          (f.fixable ? (isApplied ? '<span class="btn small applied">✅ Applied</span> ' : '<button class="btn small apply" data-act="apply-fix" data-idx="' + idx + '" title="Apply this fix to disk and git stage">⚡ Apply</button> ') : '') +
          '<button class="btn small" data-act="detail" data-idx="' + idx + '">Details</button> ' +
          '<button class="btn small" data-act="suppress" data-idx="' + idx + '">Suppress</button>' +
        '</td></tr>';
    }).join("");

    body.querySelectorAll(".finding-check").forEach((cb) => {
      cb.addEventListener("change", (e) => {
        const idx = Number(cb.dataset.idx);
        if(rows[idx]) rows[idx]._selected = cb.checked;
        updateFixSelectionUI();
      });
    });

    body.querySelectorAll("[data-act]").forEach((btn) => btn.addEventListener("click", (event) => {
      event.stopPropagation();
      const f = rows[Number(btn.dataset.idx)];
      const act = btn.dataset.act;
      if(act === "detail"){
        const detail = $("#detail-" + btn.dataset.idx);
        if(detail) detail.classList.toggle("hidden");
      } else if(act === "suggest-fix"){
        suggestFixForFinding(f);
      } else if(act === "apply-fix"){
        applyFixDirect(f, btn);
      } else if(act === "suppress"){
        suppressOne(f).catch((e) => notify(e.message, "bad"));
      }
    }));
  }
  $("#findingCount").textContent = rows.length + " of " + ((state.report && state.report.total) || 0) + " finding(s) shown.";
  updateFixSelectionUI();
}

function renderResults(){
  if(!state.report){ $("#results").classList.add("hidden"); return; }
  $("#results").classList.remove("hidden");
  summarize();
  renderFindings();
}
["filterSeverity","filterText","filterFixable"].forEach((id) => {
  const el = document.getElementById(id);
  el.addEventListener(id === "filterText" ? "input" : "change", renderFindings);
});

async function suggestFixForFinding(f){
  if(!f) return;
  const isFixable = !!f.fixable;
  modal(
    (isFixable ? "💡 Suggested Fix · " : "💡 Remediation Guidance · ") + esc(f.rule_id),
    '<div style="text-align:center;padding:24px"><span class="spinner"></span> Loading suggested fix...</div>'
  );

  if(isFixable && f.fingerprint){
    try{
      const data = await api("/api/fixes/preview", {
        method: "POST",
        body: {repo: state.repo, report: state.report, fingerprints: [f.fingerprint]}
      });
      const outcome = (data.outcomes || [])[0];
      if(outcome){
        let html = '<div style="margin-bottom:12px">' +
          '<div class="row" style="gap:8px;margin-bottom:6px">' +
            '<span class="sev ' + esc(f.severity) + '">' + esc(f.severity) + '</span> ' +
            '<code>' + esc(f.file) + ':' + esc(f.line) + '</code> ' +
            (f._applied ? '<span class="chip ok">Already applied</span>' : '<span class="chip ok">⚡ Auto-fix available</span>') +
          '</div>' +
          '<p style="margin:6px 0;font-size:13px">' + esc(f.description) + '</p>' +
        '</div>' +
        '<div class="diff" style="margin-top:10px">' +
          '<div class="before">' +
            '<span class="diff-tag red">Current Code (Line ' + esc(outcome.line) + ')</span>' +
            '<pre class="pre" style="margin:6px 0 0;max-height:160px"><code>' + esc(outcome.before) + '</code></pre>' +
          '</div>' +
          '<div class="after">' +
            '<span class="diff-tag green">Suggested Fix</span>' +
            '<pre class="pre" style="margin:6px 0 0;max-height:160px"><code>' + esc(outcome.after) + '</code></pre>' +
          '</div>' +
        '</div>' +
        '<div id="modalFixActionRow" style="margin-top:16px;display:flex;gap:10px;align-items:center">' +
          (!f._applied
            ? '<button class="btn primary apply" id="modalApplyBtn">⚡ Apply this fix &amp; stage file</button>'
            : '<span class="btn small applied">✅ Fix has been applied and staged</span>') +
          '<button class="btn" id="modalCloseInner">Dismiss</button>' +
        '</div>';
        $("#modalBody").innerHTML = html;
        const applyBtn = $("#modalApplyBtn");
        if(applyBtn){
          applyBtn.addEventListener("click", async () => {
            applyBtn.disabled = true;
            applyBtn.innerHTML = '<span class="spinner"></span> Applying...';
            try{
              const res = await api("/api/fixes/apply", {
                method: "POST",
                body: {repo: state.repo, report: state.report, fingerprints: [f.fingerprint]}
              });
              f._applied = true;
              renderFindings();
              summarize();
              $("#modalFixActionRow").innerHTML = '<div class="okbox" style="flex:1">✅ Fix applied to <code>' + esc(f.file) + '</code> and staged with git!</div>' +
                '<button class="btn primary small" id="modalRescanBtn">Rescan now</button>';
              const rescan = $("#modalRescanBtn");
              if(rescan) rescan.addEventListener("click", () => { $("#modal").classList.remove("show"); runScan(); });
              notify("Applied and staged fix for " + f.file + ":" + f.line, "ok");
            }catch(err){
              applyBtn.disabled = false;
              applyBtn.textContent = "⚡ Apply this fix & stage file";
              notify(err.message, "bad");
            }
          });
        }
        const dismiss = $("#modalCloseInner");
        if(dismiss) dismiss.addEventListener("click", () => $("#modal").classList.remove("show"));
        return;
      }
    }catch(e){}
  }

  // Fallback / Guidance for non-regex-fixable items (Secrets, SCA, Taint)
  let guide = '<div style="margin-bottom:12px">' +
    '<div class="row" style="gap:8px;margin-bottom:8px">' +
      '<span class="sev ' + esc(f.severity) + '">' + esc(f.severity) + '</span> ' +
      '<code>' + esc(f.file) + ':' + esc(f.line) + '</code> ' +
      '<code>' + esc(f.rule_id) + '</code>' +
    '</div>' +
    '<p style="margin:4px 0 12px;font-size:13px">' + esc(f.description) + '</p>' +
  '</div>';

  if((f.tags || []).includes("secret") || f.rule_id.includes("secret") || f.rule_id.includes("key") || f.rule_id.includes("token")){
    guide += '<div class="notice" style="margin-top:10px">' +
      '<b>🔒 Hardcoded Credential Detected:</b><br>' +
      'Secrets cannot be auto-fixed by code substitution because the credential must be rotated and kept out of git history.' +
      '<ol style="margin:8px 0 4px;padding-left:20px;line-height:1.6">' +
        '<li>Remove the credential from <code>' + esc(f.file) + '</code>.</li>' +
        '<li>Load it dynamically from an environment variable (e.g. <code>os.environ.get(...)</code>) or secret manager.</li>' +
        '<li>Revoke / rotate the exposed key in your provider dashboard immediately.</li>' +
        '<li>If this is an intentional dummy test value, suppress it with <code># commit-guard-ignore: ' + esc(f.rule_id) + '</code> or add to <code>.commit_guard_ignore</code>.</li>' +
      '</ol>' +
    '</div>';
  } else if(f.fixed_versions && f.fixed_versions.length){
    guide += '<div class="okbox" style="margin-top:10px">' +
      '<b>📦 Dependency Upgrade Recommendation:</b><br>' +
      'Upgrade package to fixed version: <b><code>' + esc(f.fixed_versions.join(", ")) + '</code></b> in your manifest file.<br>' +
      (f.advisory_url ? '<div style="margin-top:6px"><a href="' + esc(f.advisory_url) + '" target="_blank" rel="noreferrer">Open official security advisory &rarr;</a></div>' : '') +
    '</div>';
  } else {
    guide += '<div class="card" style="background:#0a101a;margin-top:10px">' +
      '<b>🛡️ Security Remediation Steps:</b><br>' +
      '<p class="small muted" style="margin:6px 0 10px">Avoid unsafe patterns and dynamic user-controlled strings in sensitive execution sinks.</p>' +
      '<pre class="pre" style="margin:0"><code>' + esc(f.flagged_code || "") + '</code></pre>' +
    '</div>';
  }

  guide += '<div class="row" style="margin-top:16px;justify-content:flex-end">' +
    '<button class="btn small" id="modalExplainBtn">View Full Rule Details</button>' +
    '<button class="btn small" id="modalSuppressBtn">Suppress Finding</button>' +
  '</div>';

  $("#modalBody").innerHTML = guide;
  const expBtn = $("#modalExplainBtn");
  if(expBtn) expBtn.addEventListener("click", () => explainRule(f.rule_id));
  const supBtn = $("#modalSuppressBtn");
  if(supBtn) supBtn.addEventListener("click", () => { $("#modal").classList.remove("show"); suppressOne(f); });
}

async function applyFixDirect(f, btn){
  if(!f || !f.fingerprint) return;
  const originalHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';
  try{
    const data = await api("/api/fixes/apply", {
      method: "POST",
      body: {repo: state.repo, report: state.report, fingerprints: [f.fingerprint]}
    });
    f._applied = true;
    f._selected = false;
    btn.outerHTML = '<span class="btn small applied">✅ Applied</span>';
    const row = document.querySelector('tr[data-idx="' + (state.report.findings.indexOf(f)) + '"]');
    if(row) row.classList.add("applied-row");
    updateFixSelectionUI();
    notify("Applied and staged fix for " + f.file + ":" + f.line + " (" + f.rule_id + ")", "ok");
  }catch(err){
    btn.disabled = false;
    btn.innerHTML = originalHtml;
    notify("Could not apply fix: " + err.message, "bad");
  }
}

async function applyAllFixable(){
  if(!state.report || !state.report.findings){ notify("Run a scan first.", "warn"); return; }
  const fixable = state.report.findings.filter((f) => f.fixable && !f._applied);
  if(!fixable.length){ notify("No unapplied fixable findings.", "ok"); return; }
  const fps = [...new Set(fixable.map((f) => f.fingerprint).filter(Boolean))];
  if(!confirm("Apply all " + fps.length + " safe automated fix(es)? Modified files will be staged.")) return;
  try{
    const data = await api("/api/fixes/apply", {
      method: "POST",
      body: {repo: state.repo, report: state.report, fingerprints: fps}
    });
    fixable.forEach((f) => { f._applied = true; f._selected = false; });
    renderFindings();
    summarize();
    notify("Applied and staged " + data.count + " fix(es) across " + data.files_modified.length + " file(s).", "ok");
  }catch(err){ notify(err.message, "bad"); }
}

$("#suggestAllFixesBtn").addEventListener("click", () => {
  showTab("fixes");
  previewFixes().catch((e) => notify(e.message, "bad"));
});

$("#applySelectedFixesBtn").addEventListener("click", async () => {
  const selectedCbs = $$(".finding-check:checked");
  const fps = [...new Set(selectedCbs.map((cb) => cb.dataset.fp).filter(Boolean))];
  if(!fps.length){ notify("No fixable findings selected.", "warn"); return; }
  if(!confirm("Apply " + fps.length + " selected fix(es)? Modified files will be staged.")) return;
  const btn = $("#applySelectedFixesBtn");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Applying...';
  try{
    const data = await api("/api/fixes/apply", {
      method: "POST",
      body: {repo: state.repo, report: state.report, fingerprints: fps}
    });
    (state.report.findings || []).forEach((f) => {
      if(fps.includes(f.fingerprint)){ f._applied = true; f._selected = false; }
    });
    renderFindings();
    summarize();
    notify("Applied and staged " + data.count + " selected fix(es).", "ok");
  }catch(err){
    notify(err.message, "bad");
  }finally{
    btn.disabled = false;
    btn.innerHTML = '⚡ Apply selected fixes (<span id="selectedFixCount">0</span>)';
    updateFixSelectionUI();
  }
});

$("#selectAllFixableBtn").addEventListener("click", () => {
  const rows = filteredFindings();
  rows.forEach((f) => { if(f.fixable && !f._applied) f._selected = true; });
  renderFindings();
  $("#selectAllFixableBtn").style.display = "none";
  $("#deselectAllBtn").style.display = "inline-block";
});

$("#deselectAllBtn").addEventListener("click", () => {
  const rows = filteredFindings();
  rows.forEach((f) => { f._selected = false; });
  renderFindings();
  $("#deselectAllBtn").style.display = "none";
  $("#selectAllFixableBtn").style.display = "inline-block";
});

const chkAll = $("#checkAllFindings");
if(chkAll){
  chkAll.addEventListener("change", () => {
    const rows = filteredFindings();
    rows.forEach((f) => { if(f.fixable && !f._applied) f._selected = chkAll.checked; });
    renderFindings();
  });
}

async function explainRule(ruleId){
  const data = await api("/api/rules/explain?repo=" + encodeURIComponent(state.repo) + "&id=" + encodeURIComponent(ruleId));
  const rows = [
    ["Rule", data.rule_id], ["Severity", data.severity], ["Source", data.source],
    ["Description", data.description], ["CWE", data.cwe], ["Tags", (data.tags||[]).join(", ")],
    ["Languages", (data.languages||[]).join(", ")], ["Paths", (data.paths||[]).join(", ")],
    ["Entropy", data.entropy], ["Keywords", (data.keywords||[]).join(", ")],
    ["Fixable", data.fixable ? "yes" : "no"]
  ].filter((r) => r[1] !== null && r[1] !== undefined && r[1] !== "");
  let html = "<table>" + rows.map((r) => "<tr><th>" + esc(r[0]) + "</th><td>" + esc(r[1]) + "</td></tr>").join("") + "</table>";
  if(data.pattern) html += "<h3 style='margin-top:14px'>Pattern</h3><pre class='pre'>" + esc(data.pattern) + "</pre>";
  if(data.fix_pattern) html += "<h3>Fix</h3><pre class='pre'>" + esc(data.fix_pattern) + "  →  " + esc(data.fix_replacement) + "</pre>";
  modal("Rule " + ruleId, html);
}

async function suppressOne(finding){
  if(!finding || !finding.fingerprint){ notify("This finding has no fingerprint.", "warn"); return; }
  if(!confirm("Suppress this finding in .commit_guard_ignore?\n\n" + finding.file + ":" + finding.line + "  " + finding.rule_id)) return;
  const result = await api("/api/baseline/suppress", {method:"POST", body:{repo:state.repo, fingerprints:[finding.fingerprint]}});
  notify(result.added ? "Finding added to the baseline." : "Already present in the baseline.", result.added ? "ok" : "warn");
}

async function previewFixes(fingerprints){
  if(!state.report){ notify("Run a scan first.", "warn"); return; }
  const data = await api("/api/fixes/preview", {method:"POST", body:{repo:state.repo, report:state.report, fingerprints:fingerprints || null}});
  state.lastFixes = data.outcomes || [];
  const out = $("#fixOutput");
  if(!data.count){
    out.innerHTML = '<div class="okbox">No safe fixes are available for the current findings.</div>';
    $("#applyFixesBtn").disabled = true;
    return;
  }
  out.innerHTML = '<div class="row" style="justify-content:space-between;align-items:center;margin-bottom:10px">' +
    '<p class="hint" style="margin:0">' + data.count + ' fix(es) across ' + data.files.length + ' file(s). Select which ones to apply.</p>' +
    '<div class="row">' +
      '<button class="btn small" id="toggleAllFixChecks">Toggle all</button>' +
    '</div></div>' +
    '<div style="overflow:auto"><table><thead><tr><th style="width:36px"><input type="checkbox" id="checkAllFixes" checked></th><th>Location</th><th>Rule</th><th>Change Preview</th><th class="right">Action</th></tr></thead><tbody>' +
    data.outcomes.map((o, i) =>
      '<tr><td><input type="checkbox" class="fix-check" data-i="' + i + '" checked></td>' +
      '<td><code>' + esc(o.file) + ':' + esc(o.line) + '</code></td>' +
      '<td><code>' + esc(o.rule_id) + '</code></td>' +
      '<td><div class="diff"><div class="before"><span class="diff-tag red">before</span><br><code>' + esc(o.before) + '</code></div>' +
      '<div class="after"><span class="diff-tag green">after</span><br><code>' + esc(o.after) + '</code></div></div></td>' +
      '<td class="right" style="vertical-align:middle"><button class="btn small apply" data-apply-fp="' + esc(o.fingerprint || "") + '" data-i="' + i + '">⚡ Apply</button></td></tr>'
    ).join("") + '</tbody></table></div>';
  $("#applyFixesBtn").disabled = false;

  const chkFixAll = $("#checkAllFixes");
  if(chkFixAll){
    chkFixAll.addEventListener("change", () => {
      $$(".fix-check").forEach((cb) => { cb.checked = chkFixAll.checked; });
    });
  }
  const toggleBtn = $("#toggleAllFixChecks");
  if(toggleBtn){
    toggleBtn.addEventListener("click", () => {
      const anyUnchecked = $$(".fix-check").some((cb) => !cb.checked);
      $$(".fix-check").forEach((cb) => { cb.checked = anyUnchecked; });
      if(chkFixAll) chkFixAll.checked = anyUnchecked;
    });
  }
  out.querySelectorAll("[data-apply-fp]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const fp = btn.dataset.applyFp;
      if(!fp) return;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span>';
      try{
        const res = await api("/api/fixes/apply", {method:"POST", body:{repo:state.repo, report:state.report, fingerprints:[fp]}});
        btn.outerHTML = '<span class="btn small applied">✅ Applied</span>';
        notify("Applied and staged fix.", "ok");
        if(state.report && state.report.findings){
          state.report.findings.forEach((f) => { if(f.fingerprint === fp) f._applied = true; });
        }
      }catch(err){
        btn.disabled = false;
        btn.textContent = "⚡ Apply";
        notify(err.message, "bad");
      }
    });
  });
}
$("#previewFixesBtn").addEventListener("click", () => previewFixes().catch((e) => notify(e.message, "bad")));
$("#applyFixesBtn").addEventListener("click", async () => {
  const selected = $$(".fix-check:checked").map((el) => state.lastFixes[Number(el.dataset.i)]);
  const fingerprints = [...new Set(selected.map((o) => o.fingerprint).filter(Boolean))];
  if(!fingerprints.length){ notify("Select at least one fix.", "warn"); return; }
  if(!confirm("Apply " + fingerprints.length + " fix(es)? Modified files will be staged.")) return;
  $("#applyFixesBtn").disabled = true;
  try{
    const data = await api("/api/fixes/apply", {method:"POST", body:{repo:state.repo, report:state.report, fingerprints}});
    if(state.report && state.report.findings){
      state.report.findings.forEach((f) => {
        if(fingerprints.includes(f.fingerprint)) f._applied = true;
      });
    }
    $("#fixOutput").innerHTML = '<div class="okbox">Applied ' + data.count + ' fix(es). Modified: ' +
      (data.files_modified.length ? '<code>' + esc(data.files_modified.join(", ")) + '</code>' : 'none') +
      '</div><div class="row" style="margin-top:10px"><button class="btn primary" id="rescanAfterFix">Rescan now</button></div>';
    const btn = $("#rescanAfterFix");
    if(btn) btn.addEventListener("click", runScan);
    notify("Applied and staged " + data.count + " fix(es).", "ok");
  }catch(err){ notify(err.message, "bad"); }
  finally{ $("#applyFixesBtn").disabled = false; }
});

async function previewSuggestions(){
  if(!state.report){ notify("Run a scan first.", "warn"); return; }
  const data = await api("/api/github/suggestions", {method:"POST", body:{repo:state.repo, report:state.report}});
  $("#suggestionsCard").classList.remove("hidden");
  if(!data.count){
    $("#suggestionsOut").innerHTML = '<div class="okbox">No inline suggestions are available.</div>';
    return;
  }
  $("#suggestionsOut").innerHTML = data.suggestions.map((s) =>
    '<div class="card" style="background:#0d1421"><div class="small"><code>' + esc(s.path) + ':' + esc(s.line) +
    '</code> · <code>' + esc(s.rule_id) + '</code></div><pre class="pre" style="margin-top:8px">' + esc(s.body) + '</pre></div>'
  ).join("");
}
$("#suggestionsBtn").addEventListener("click", () => previewSuggestions().catch((e) => notify(e.message, "bad")));

function ghCommon(){
  ghToken = $("#ghToken").value.trim() || ghToken;
  return {
    repo: state.repo,
    options: state.options || gatherOptions(),
    token: ghToken,
    repository: $("#ghRepo").value.trim()
  };
}
$("#ghToken").addEventListener("input", () => { ghToken = $("#ghToken").value.trim(); });

$("#createPrBtn").addEventListener("click", async () => {
  const base = ghCommon();
  if(!base.token){ notify("Enter a GitHub token.", "warn"); return; }
  if(!confirm("Create or update the report pull request in " + (base.repository || "the detected repository") + "?")) return;
  $("#createPrBtn").disabled = true; $("#prStatus").textContent = "Working...";
  try{
    const data = await api("/api/github/pr", {method:"POST", body:Object.assign({}, base, {
      base: $("#ghBase").value.trim(), branch: $("#ghBranch").value.trim(), title: $("#ghTitle").value.trim()
    })});
    $("#prResult").innerHTML = '<div class="okbox">Pull request #' + esc(data.number || "?") + ' ready. ' +
      (data.url ? '<a href="' + esc(data.url) + '" target="_blank" rel="noreferrer">Open on GitHub</a>' : '') + '</div>';
    $("#prStatus").textContent = "Done.";
    notify("Report PR published.", "ok");
  }catch(err){
    $("#prStatus").textContent = "Failed.";
    $("#prResult").innerHTML = '<div class="notice">' + esc(err.message) + '</div>';
    notify(err.message, "bad");
  }finally{ $("#createPrBtn").disabled = false; }
});

$("#reviewPrBtn").addEventListener("click", async () => {
  const base = ghCommon();
  if(!base.token){ notify("Enter a GitHub token.", "warn"); return; }
  const number = $("#prNumber").value.trim();
  if(!number){ notify("Enter the pull request number.", "warn"); return; }
  if(!confirm("Post inline suggestions on PR #" + number + "?")) return;
  $("#reviewPrBtn").disabled = true; $("#reviewStatus").textContent = "Working...";
  try{
    const data = await api("/api/github/review", {method:"POST", body:Object.assign({}, base, {pr_number:number})});
    $("#reviewResult").innerHTML = '<div class="okbox">Posted ' + esc(data.posted) + ' suggestion(s) on PR #' + esc(data.pr) +
      (data.skipped ? ' · ' + esc(data.skipped) + ' already up to date' : '') + '.</div>';
    $("#reviewStatus").textContent = "Done.";
    notify("Inline review posted.", "ok");
  }catch(err){
    $("#reviewStatus").textContent = "Failed.";
    $("#reviewResult").innerHTML = '<div class="notice">' + esc(err.message) + '</div>';
    notify(err.message, "bad");
  }finally{ $("#reviewPrBtn").disabled = false; }
});

async function loadBaseline(){
  const data = await api("/api/baseline/entries?repo=" + encodeURIComponent(state.repo));
  $("#baselinePath").textContent = data.path + (data.exists ? "" : " (does not exist yet)");
  $("#baselineBody").innerHTML = data.entries.length ? data.entries.map((e) =>
    '<tr><td>' + esc(e.line) + '</td><td>' + esc(e.kind) + '</td><td><code>' + esc(e.value) + '</code></td><td>' + esc(e.owner || "") + '</td><td>' + esc(e.expiry || "") + '</td></tr>'
  ).join("") : '<tr><td colspan="5" class="muted">No baseline entries.</td></tr>';
}
$("#reloadBaselineBtn").addEventListener("click", () => loadBaseline().catch((e) => notify(e.message, "bad")));
$("#updateBaselineBtn").addEventListener("click", async () => {
  if(!state.report){ notify("Run a scan first.", "warn"); return; }
  if(!confirm("Add all current findings to the baseline?")) return;
  const data = await api("/api/baseline/update", {method:"POST", body:{repo:state.repo, report:state.report,
    owner:$("#baselineOwner").value.trim(), expiry:$("#baselineExpiry").value.trim()}}).catch((e) => { notify(e.message, "bad"); return null; });
  if(!data) return;
  notify(data.added + " fingerprint(s) added.", data.added ? "ok" : "warn");
  loadBaseline().catch(()=>{});
});
$("#auditBtn").addEventListener("click", async () => {
  const data = await api("/api/baseline/audit", {method:"POST", body:{repo:state.repo, report:state.report || null}});
  $("#auditOut").innerHTML = data.clean
    ? '<div class="okbox">Baseline looks clean (' + data.entries + ' entries).</div>'
    : '<div class="notice"><b>' + data.issues.length + ' issue(s):</b><ul>' + data.issues.map((i) => '<li>' + esc(i) + '</li>').join("") + '</ul></div>';
});

async function loadRules(){
  const data = await api("/api/rules?repo=" + encodeURIComponent(state.repo));
  state.rules = data.rules;
  const sources = [...new Set(data.rules.map((r) => r.source))].sort();
  $("#ruleSource").innerHTML = '<option value="">All</option>' + sources.map((s) => '<option>' + esc(s) + '</option>').join("");
  renderRules();
  $("#rulesCount").textContent = data.total + " active rule(s) · " + data.skipped + " skipped · " + data.rules_dir;
}
function renderRules(){
  const q = $("#ruleSearch").value.trim().toLowerCase();
  const src = $("#ruleSource").value;
  const fixableOnly = $("#ruleFixable").checked;
  const rows = state.rules.filter((r) => {
    if(src && r.source !== src) return false;
    if(fixableOnly && !r.fixable) return false;
    if(q){
      const hay = [r.rule_id,r.description,r.source,(r.tags||[]).join(" "),r.cwe].join(" ").toLowerCase();
      if(!hay.includes(q)) return false;
    }
    return true;
  });
  $("#rulesBody").innerHTML = rows.map((r) =>
    '<tr><td><code>' + esc(r.rule_id) + '</code><div class="small muted">' + esc(r.description) + '</div></td>' +
    '<td><span class="sev ' + esc(r.severity) + '">' + esc(r.severity) + '</span></td>' +
    '<td>' + esc(r.source) + '</td><td>' + (r.tags||[]).map((t) => '<span class="chip">' + esc(t) + '</span>').join(" ") + '</td>' +
    '<td>' + (r.is_secret ? '<span class="chip warn">secret</span> ' : '') + (r.fixable ? '<span class="chip ok">fixable</span>' : '') + '</td>' +
    '<td class="right"><button class="btn small" data-rule="' + esc(r.rule_id) + '">Explain</button></td></tr>'
  ).join("");
  $("#rulesBody").querySelectorAll("[data-rule]").forEach((b) => b.addEventListener("click", () => explainRule(b.dataset.rule).catch((e) => notify(e.message, "bad"))));
  $("#rulesCount").textContent = rows.length + " rule(s) shown.";
}
$("#loadRulesBtn").addEventListener("click", () => loadRules().catch((e) => notify(e.message, "bad")));
["ruleSearch","ruleSource","ruleFixable"].forEach((id) => document.getElementById(id).addEventListener(id === "ruleSearch" ? "input" : "change", renderRules));
$("#checkRulesBtn").addEventListener("click", async () => {
  try{
    const data = await api("/api/rules/check", {method:"POST", body:{repo:state.repo}});
    modal("Rule validation", "<pre class='pre'>" + esc(data.output) + "</pre>");
  }catch(err){ notify(err.message, "bad"); }
});

$$("[data-maint]").forEach((btn) => btn.addEventListener("click", () => runMaintenance(btn.dataset.maint)));
async function runMaintenance(action){
  if(!confirm("Run maintenance action: " + action + "?")) return;
  let options = {profile:$("#installProfile").value, force:$("#installForce").checked, pre_push:$("#installPrePush").checked};
  if(action === "uninstall"){
    const typed = prompt("This removes Commit Guard from this repository.\nType the repository folder name to confirm: " + state.info.name);
    if(typed !== state.info.name){ notify("Uninstall cancelled.", "warn"); return; }
    options.confirm = typed;
  }
  $("#maintOut").textContent = "Running " + action + "...";
  try{
    const data = await api("/api/maintenance/" + action, {method:"POST", body:{repo:state.repo, options}});
    $("#maintOut").textContent = data.output || "(no output)";
    notify(action + " finished (exit " + data.exit_code + ").", data.exit_code === 0 ? "ok" : "bad");
    loadRepo(state.repo).catch(()=>{});
  }catch(err){ $("#maintOut").textContent = err.message; notify(err.message, "bad"); }
}

async function loadConfig(){
  const data = await api("/api/config?repo=" + encodeURIComponent(state.repo));
  $("#configText").value = data.text || data.default_text || "";
  $("#configStatus").textContent = data.exists ? data.path : "not created yet";
  $("#configOut").innerHTML = data.error ? '<div class="notice">' + esc(data.error) + '</div>' :
    (data.summary ? '<div class="okbox">Valid configuration · threshold ' + esc(data.summary.threshold) + ' · report dir ' + esc(data.summary.report_dir) + '</div>' : '');
  $("#configText").dataset.default = data.default_text || "";
}
$("#reloadConfigBtn").addEventListener("click", () => loadConfig().catch((e) => notify(e.message, "bad")));
$("#defaultConfigBtn").addEventListener("click", () => {
  if(!confirm("Replace the editor contents with the default template? (Not saved until you click Save.)")) return;
  $("#configText").value = $("#configText").dataset.default || "";
});
$("#saveConfigBtn").addEventListener("click", async () => {
  try{
    const data = await api("/api/config", {method:"PUT", body:{repo:state.repo, text:$("#configText").value}});
    $("#configStatus").textContent = "Saved · " + data.path;
    $("#configOut").innerHTML = '<div class="okbox">Configuration saved and validated. A backup is kept as .commit_guard.toml.bak.</div>';
    notify("Configuration saved.", "ok");
    loadRepo(state.repo).catch(()=>{});
  }catch(err){ $("#configOut").innerHTML = '<div class="notice">' + esc(err.message) + '</div>'; notify(err.message, "bad"); }
});
$("#restoreConfigBtn").addEventListener("click", async () => {
  if(!confirm("Restore the last configuration backup?")) return;
  try{
    await api("/api/config/restore", {method:"POST", body:{repo:state.repo}});
    notify("Backup restored.", "ok");
    loadConfig().catch(()=>{});
  }catch(err){ notify(err.message, "bad"); }
});

function downloadBlob(content, name, type){
  const blob = new Blob([content], {type: type || "text/plain"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}
async function exportReport(save, open){
  if(!state.report){ notify("Run a scan first.", "warn"); return; }
  const format = $("#exportFormat").value;
  const data = await api("/api/export", {method:"POST", body:{repo:state.repo, format, save:!!save}});
  if(save){
    $("#exportOut").innerHTML = '<div class="okbox">Saved to <code>' + esc(data.saved_path) + '</code></div>';
    notify("Report saved.", "ok");
    loadReports().catch(()=>{});
  } else if(open){
    const blob = new Blob([data.content], {type:data.mimetype});
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } else {
    downloadBlob(data.content, data.filename, data.mimetype);
    notify("Downloaded " + data.filename, "ok");
  }
}
$("#downloadReportBtn").addEventListener("click", () => exportReport(false, false).catch((e) => notify(e.message, "bad")));
$("#saveReportBtn").addEventListener("click", () => exportReport(true, false).catch((e) => notify(e.message, "bad")));
$("#openReportBtn").addEventListener("click", () => exportReport(false, true).catch((e) => notify(e.message, "bad")));
$$("[data-export]").forEach((b) => b.addEventListener("click", () => {
  if(!state.report){ notify("Run a scan first.", "warn"); return; }
  const fmt = b.dataset.export;
  api("/api/export", {method:"POST", body:{repo:state.repo, format:fmt, save:false}}).then((data) => {
    if(fmt === "html"){
      const url = URL.createObjectURL(new Blob([data.content], {type:data.mimetype}));
      window.open(url, "_blank");
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } else {
      downloadBlob(data.content, data.filename, data.mimetype);
    }
  }).catch((e) => notify(e.message, "bad"));
}));

async function loadReports(){
  const data = await api("/api/reports?repo=" + encodeURIComponent(state.repo));
  $("#reportDir").textContent = data.dir;
  $("#reportsBody").innerHTML = data.files.length ? data.files.map((f) =>
    '<tr><td><code>' + esc(f.name) + '</code></td><td>' + esc(fmtBytes(f.size)) + '</td><td>' + esc(fmtTime(f.modified)) + '</td>' +
    '<td class="right"><button class="btn small" data-open="' + esc(f.name) + '">Open</button></td></tr>'
  ).join("") : '<tr><td colspan="4" class="muted">No report files yet.</td></tr>';
  $("#reportsBody").querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", async () => {
    try{
      const response = await fetch("/api/reports/download?repo=" + encodeURIComponent(state.repo) + "&name=" + encodeURIComponent(b.dataset.open), {headers:{"X-CG-Token":TOKEN}});
      if(!response.ok) throw new Error((await response.text()) || "Could not open report");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      if(b.dataset.open.endsWith(".html")) window.open(url, "_blank");
      else { const a=document.createElement("a"); a.href=url; a.download=b.dataset.open; a.click(); }
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    }catch(err){ notify(err.message, "bad"); }
  }));
}
$("#reloadReportsBtn").addEventListener("click", () => loadReports().catch((e) => notify(e.message, "bad")));

(function init(){
  let saved = null;
  try { saved = localStorage.getItem("commitguard.repo"); } catch(e){}
  const target = saved || INITIAL_REPO;
  if(target){ $("#repoPath").value = target; loadRepo(target).catch(() => {}); }
  else { $("#repoPath").focus(); }
})();
</script>
</body>
</html>
"""
