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
  color-scheme:dark;
  --bg:#070b12;--bg-soft:#0b111c;--panel:#0f1624;--panel2:#0b1220;--panel3:#141d2e;
  --line:rgba(148,163,184,.13);--line2:rgba(148,163,184,.23);
  --text:#e8eef8;--muted:#92a3ba;--faint:#64748b;
  --accent:#5ba7ff;--accent2:#8b5cf6;--accent-soft:rgba(91,167,255,.14);
  --ok:#34d399;--warn:#fbbf24;--bad:#fb7185;--crit:#fb7185;
  --critical:#fb7185;--high:#fb923c;--medium:#facc15;--low:#38bdf8;--info:#94a3b8;
  --shadow:0 22px 60px rgba(0,0,0,.38);--shadow-sm:0 8px 24px rgba(0,0,0,.2);
  --radius:16px;--radius-sm:11px;
}
html[data-theme="light"]{
  color-scheme:light;
  --bg:#f3f6fb;--bg-soft:#eef2f9;--panel:#fff;--panel2:#f8fafc;--panel3:#f1f5fb;
  --line:rgba(15,23,42,.09);--line2:rgba(15,23,42,.17);
  --text:#142033;--muted:#5b6b82;--faint:#8492a6;
  --accent:#2563eb;--accent2:#7c3aed;--accent-soft:rgba(37,99,235,.1);
  --ok:#059669;--warn:#b45309;--bad:#dc2626;--crit:#dc2626;
  --critical:#dc2626;--high:#ea580c;--medium:#ca8a04;--low:#0284c7;--info:#64748b;
  --shadow:0 22px 60px rgba(15,23,42,.1);--shadow-sm:0 8px 24px rgba(15,23,42,.06);
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
html{scroll-behavior:smooth}
body{background:
  radial-gradient(900px 520px at 8% -12%,rgba(91,167,255,.18),transparent 64%),
  radial-gradient(760px 480px at 96% 0%,rgba(139,92,246,.14),transparent 60%),
  var(--bg);
  color:var(--text);font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;opacity:.16;
  background-image:linear-gradient(var(--line) 1px,transparent 1px),linear-gradient(90deg,var(--line) 1px,transparent 1px);
  background-size:48px 48px;
  -webkit-mask-image:radial-gradient(circle at 50% 0,#000 0%,transparent 72%);
  mask-image:radial-gradient(circle at 50% 0,#000 0%,transparent 72%)}
::selection{background:var(--accent-soft);color:var(--text)}
*{scrollbar-width:thin;scrollbar-color:var(--line2) transparent}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:var(--line2);border-radius:99px;border:2px solid transparent;background-clip:content-box}
::-webkit-scrollbar-track{background:transparent}
button,input,select,textarea{font:inherit;color:inherit}
button{cursor:pointer}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.skip-link{position:absolute;left:12px;top:-60px;z-index:100;background:var(--accent);color:#fff;padding:9px 13px;border-radius:9px;font-weight:700}
.skip-link:focus{top:12px}
.app{display:grid;grid-template-columns:264px minmax(0,1fr);min-height:100vh}
.side{position:sticky;top:0;height:100vh;overflow:auto;background:
  linear-gradient(180deg,rgba(15,22,36,.96),rgba(8,13,22,.98));
  border-right:1px solid var(--line);padding:22px 15px 16px;display:flex;flex-direction:column;gap:16px;
  backdrop-filter:blur(18px)}
html[data-theme="light"] .side{background:linear-gradient(180deg,rgba(255,255,255,.94),rgba(247,250,255,.97))}
.brand{display:flex;align-items:center;gap:12px;padding:2px 7px 16px;border-bottom:1px solid var(--line)}
.logo{width:42px;height:42px;flex:0 0 42px;border-radius:13px;background:linear-gradient(145deg,var(--accent),var(--accent2));
  display:grid;place-items:center;color:#fff;box-shadow:0 10px 26px rgba(91,140,255,.3),inset 0 1px 0 rgba(255,255,255,.3)}
.logo svg{width:24px;height:24px}
.brand h1{font-size:15px;margin:0;letter-spacing:-.01em;font-weight:800}
.brand small{display:block;color:var(--muted);font-size:11px;font-weight:600;letter-spacing:.02em}
.nav{display:flex;flex-direction:column;gap:15px;overflow:auto;padding-right:2px}
.nav-group{display:flex;flex-direction:column;gap:3px}
.nav-label{font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);font-weight:800;padding:0 10px 5px}
.nav button{position:relative;display:flex;align-items:center;gap:10px;width:100%;background:transparent;border:0;border-radius:10px;
  padding:9px 10px;color:var(--muted);text-align:left;font-weight:650;font-size:13px;transition:background .15s ease,color .15s ease,box-shadow .15s ease}
.nav button svg{width:18px;height:18px;flex:0 0 18px;opacity:.72;transition:opacity .15s ease,color .15s ease}
.nav button:hover{background:var(--panel3);color:var(--text)}
.nav button:hover svg{opacity:1}
.nav button.active{background:linear-gradient(90deg,var(--accent-soft),transparent 82%);color:var(--text);box-shadow:inset 0 0 0 1px var(--line2)}
.nav button.active::before{content:"";position:absolute;left:0;top:50%;width:3px;height:17px;transform:translateY(-50%);
  border-radius:0 4px 4px 0;background:linear-gradient(180deg,var(--accent),var(--accent2))}
.nav button.active svg{opacity:1;color:var(--accent)}
.side .foot{margin-top:auto;color:var(--muted);font-size:11px;padding:14px 7px 2px;border-top:1px solid var(--line);display:flex;flex-direction:column;gap:6px}
.local-status{display:flex;align-items:center;gap:7px;font-weight:700;color:var(--text)}
.local-status .status-dot{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 4px color-mix(in srgb,var(--ok) 14%,transparent)}
.version-line{font-size:10.5px;color:var(--faint);letter-spacing:.02em}
.main{min-width:0;width:100%;max-width:1640px;margin:0 auto;padding:30px clamp(18px,3vw,44px) 76px}
.page-head{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:20px}
.eyebrow{display:inline-block;font-size:10.5px;text-transform:uppercase;letter-spacing:.17em;color:var(--accent);font-weight:850}
.page-head h2{font-size:clamp(25px,3vw,36px);line-height:1.08;letter-spacing:-.035em;margin:5px 0 6px;font-weight:850}
.page-head p{margin:0;color:var(--muted);font-size:13.5px;max-width:700px}
.page-actions{display:flex;gap:8px;align-items:center;flex:0 0 auto;padding-top:2px}
.icon-btn{width:40px;height:40px;min-height:40px;padding:0;display:inline-grid;place-items:center;border-radius:11px;border:1px solid var(--line2);
  background:var(--panel);color:var(--muted);box-shadow:var(--shadow-sm);transition:transform .15s ease,color .15s ease,border-color .15s ease}
.icon-btn:hover{color:var(--text);border-color:var(--accent);transform:translateY(-1px)}
.icon-btn svg{width:18px;height:18px}
.icon-sun{display:block}.icon-moon{display:none}
html[data-theme="light"] .icon-sun{display:none}html[data-theme="light"] .icon-moon{display:block}
.repo-bar{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;background:linear-gradient(180deg,var(--panel),var(--panel2));
  border:1px solid var(--line);border-radius:var(--radius);padding:14px;margin-bottom:11px;box-shadow:var(--shadow-sm)}
.repo-bar .field{flex:1;min-width:250px}
.field{display:flex;flex-direction:column;gap:6px;min-width:0}
.field label,.lbl{font-size:10.5px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);font-weight:800}
input,select,textarea{width:100%;background:var(--bg-soft);border:1px solid var(--line2);border-radius:10px;padding:9px 11px;
  min-height:40px;outline:none;transition:border-color .15s ease,box-shadow .15s ease,background .15s ease}
input:hover,select:hover,textarea:hover{border-color:color-mix(in srgb,var(--accent) 45%,var(--line2))}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);background:var(--panel)}
input::placeholder,textarea::placeholder{color:var(--faint)}
select{cursor:pointer}
input[type="checkbox"],input[type="radio"]{width:auto;min-height:0;accent-color:var(--accent);cursor:pointer;vertical-align:-2px}
input[type="number"]{font-variant-numeric:tabular-nums}
textarea{min-height:420px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;line-height:1.6}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:39px;border:1px solid var(--line2);background:var(--panel3);
  border-radius:10px;padding:9px 14px;font-weight:700;letter-spacing:.01em;white-space:nowrap;
  transition:transform .15s ease,background .15s ease,border-color .15s ease,box-shadow .15s ease}
.btn:hover{background:color-mix(in srgb,var(--panel3) 72%,var(--accent));border-color:color-mix(in srgb,var(--accent) 45%,var(--line2));transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn.primary{background:linear-gradient(135deg,var(--accent),var(--accent2));border-color:transparent;color:#fff;box-shadow:0 9px 24px rgba(80,120,255,.28)}
.btn.primary:hover{filter:brightness(1.08);box-shadow:0 12px 28px rgba(80,120,255,.36)}
.btn.danger{border-color:color-mix(in srgb,var(--bad) 40%,var(--line2));background:color-mix(in srgb,var(--bad) 10%,var(--panel));color:var(--bad)}
.btn.danger:hover{background:color-mix(in srgb,var(--bad) 18%,var(--panel))}
.btn.small{min-height:30px;padding:5px 10px;font-size:12px;border-radius:8px}
.btn:disabled{opacity:.42;cursor:not-allowed;transform:none;box-shadow:none}
.btn svg{width:15px;height:15px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.chips{display:flex;gap:7px;flex-wrap:wrap;margin:0 0 14px;min-height:23px}
.chip{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--line2);background:var(--panel);border-radius:999px;
  padding:3px 9px;font-size:10.5px;color:var(--muted);font-weight:750;letter-spacing:.01em}
.chip.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 35%,var(--line2));background:color-mix(in srgb,var(--ok) 10%,var(--panel))}
.chip.warn{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 35%,var(--line2));background:color-mix(in srgb,var(--warn) 10%,var(--panel))}
.chip.bad{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 35%,var(--line2));background:color-mix(in srgb,var(--bad) 10%,var(--panel))}
.card{position:relative;background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:var(--radius);
  padding:20px;margin-bottom:18px;box-shadow:var(--shadow-sm)}
.card h2{display:flex;align-items:center;gap:9px;font-size:15px;margin:0 0 5px;letter-spacing:-.01em;font-weight:800}
.card h2::before{content:"";width:3px;height:16px;border-radius:3px;background:linear-gradient(180deg,var(--accent),var(--accent2));flex:0 0 3px}
.card p.hint{margin:0 0 14px;color:var(--muted);font-size:12.5px}
.card h3{font-size:14px;letter-spacing:-.01em}
.grid{display:grid;gap:14px}
.grid.g2{grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
.grid.g3{grid-template-columns:repeat(auto-fit,minmax(215px,1fr))}
.grid.g4{grid-template-columns:repeat(auto-fit,minmax(165px,1fr))}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:11px;margin:14px 0 16px}
.stat{position:relative;overflow:hidden;background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);
  border-radius:13px;padding:12px 14px;box-shadow:var(--shadow-sm)}
.stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--stat,var(--line2))}
.stat b{display:block;font-size:26px;line-height:1.15;letter-spacing:-.03em;font-variant-numeric:tabular-nums;color:var(--stat,var(--text))}
.stat span{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;font-weight:800}
.stat.critical{--stat:var(--critical)}.stat.high{--stat:var(--high)}.stat.medium{--stat:var(--medium)}
.stat.low{--stat:var(--low)}.stat.info{--stat:var(--info)}
.banner{display:flex;gap:14px;align-items:center;justify-content:space-between;flex-wrap:wrap;padding:14px 16px;border-radius:13px;
  border:1px solid var(--line2);background:linear-gradient(180deg,var(--panel),var(--panel2));margin-bottom:14px;box-shadow:var(--shadow-sm)}
.banner.fail{border-color:color-mix(in srgb,var(--bad) 45%,var(--line2));background:linear-gradient(90deg,color-mix(in srgb,var(--bad) 11%,var(--panel)),var(--panel2))}
.banner.pass{border-color:color-mix(in srgb,var(--ok) 45%,var(--line2));background:linear-gradient(90deg,color-mix(in srgb,var(--ok) 11%,var(--panel)),var(--panel2))}
.banner strong{font-size:14px}
.banner .actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel2)}
table{width:100%;border-collapse:separate;border-spacing:0}
th,td{padding:10px 11px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{position:sticky;top:0;z-index:2;background:var(--panel3);font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);font-weight:800}
td{font-size:12.5px}
tbody tr{transition:background .12s ease}
tbody tr:hover td{background:color-mix(in srgb,var(--accent) 5%,transparent)}
tbody tr:last-child td{border-bottom:0}
.th-check{width:38px;text-align:center}
.td-check{text-align:center;vertical-align:middle;padding-top:13px}
.td-check input{cursor:pointer}
.applied-row{background:color-mix(in srgb,var(--ok) 7%,transparent)!important}
.applied-row td{border-bottom-color:color-mix(in srgb,var(--ok) 22%,var(--line))}
.sev{display:inline-block;border-radius:999px;padding:2px 8px;font-size:10px;font-weight:850;text-transform:uppercase;letter-spacing:.06em;border:1px solid transparent}
.sev.critical{color:var(--critical);background:color-mix(in srgb,var(--critical) 13%,transparent);border-color:color-mix(in srgb,var(--critical) 34%,transparent)}
.sev.high{color:var(--high);background:color-mix(in srgb,var(--high) 13%,transparent);border-color:color-mix(in srgb,var(--high) 34%,transparent)}
.sev.medium{color:var(--medium);background:color-mix(in srgb,var(--medium) 13%,transparent);border-color:color-mix(in srgb,var(--medium) 34%,transparent)}
.sev.low{color:var(--low);background:color-mix(in srgb,var(--low) 13%,transparent);border-color:color-mix(in srgb,var(--low) 34%,transparent)}
.sev.info{color:var(--info);background:color-mix(in srgb,var(--info) 13%,transparent);border-color:color-mix(in srgb,var(--info) 34%,transparent)}
.btn.suggest{background:color-mix(in srgb,var(--accent) 11%,var(--panel));border-color:color-mix(in srgb,var(--accent) 40%,var(--line2));color:var(--accent)}
.btn.suggest:hover{background:color-mix(in srgb,var(--accent) 18%,var(--panel));box-shadow:0 0 18px var(--accent-soft)}
.btn.apply{background:linear-gradient(135deg,#059669,#10b981);border-color:transparent;color:#fff;font-weight:800}
.btn.apply:hover{filter:brightness(1.1);box-shadow:0 0 18px rgba(16,185,129,.35)}
.btn.applied{background:color-mix(in srgb,var(--ok) 13%,var(--panel));border:1px solid color-mix(in srgb,var(--ok) 38%,var(--line));color:var(--ok);cursor:default;opacity:.9}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
td code{font-size:11.5px;color:color-mix(in srgb,var(--text) 86%,var(--accent))}
.muted{color:var(--muted)}
.small{font-size:12px}
.right{text-align:right}
.pre{white-space:pre-wrap;word-break:break-word;background:var(--bg-soft);border:1px solid var(--line);border-radius:11px;padding:13px;max-height:430px;overflow:auto;font-size:12px;line-height:1.6}
.diff{display:grid;grid-template-columns:1fr 1fr;gap:9px}
.diff div{background:var(--bg-soft);border:1px solid var(--line);border-radius:9px;padding:11px;overflow:auto;font-size:12px}
.diff .before{border-color:color-mix(in srgb,var(--bad) 40%,var(--line));background:color-mix(in srgb,var(--bad) 7%,var(--bg-soft))}
.diff .after{border-color:color-mix(in srgb,var(--ok) 40%,var(--line));background:color-mix(in srgb,var(--ok) 7%,var(--bg-soft))}
.diff-tag{display:inline-block;padding:2px 7px;border-radius:5px;font-size:9.5px;font-weight:850;letter-spacing:.06em;text-transform:uppercase;margin-bottom:7px}
.diff-tag.red{background:color-mix(in srgb,var(--bad) 14%,transparent);color:var(--bad);border:1px solid color-mix(in srgb,var(--bad) 34%,transparent)}
.diff-tag.green{background:color-mix(in srgb,var(--ok) 14%,transparent);color:var(--ok);border:1px solid color-mix(in srgb,var(--ok) 34%,transparent)}
.hidden{display:none!important}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:13px}
.tabs button{background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:6px 12px;color:var(--muted);font-weight:750;font-size:12px}
.tabs button.active{color:var(--text);border-color:var(--accent);background:var(--accent-soft)}
.details{background:var(--bg-soft);border:1px solid var(--line);border-radius:11px;padding:11px;margin-top:9px}
.details summary{cursor:pointer;color:var(--muted);font-weight:750;font-size:12px;transition:color .15s ease}
.details summary:hover{color:var(--text)}
.details[open] summary{color:var(--text);margin-bottom:3px}
.spinner{width:14px;height:14px;border:2px solid color-mix(in srgb,var(--text) 20%,transparent);border-top-color:var(--accent);
  border-radius:50%;display:inline-block;animation:spin .8s linear infinite;vertical-align:-2px}
@keyframes spin{to{transform:rotate(360deg)}}
.toasts{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:9px;z-index:60;max-width:390px}
.toast{background:color-mix(in srgb,var(--panel) 92%,transparent);border:1px solid var(--line2);border-left:4px solid var(--accent);
  border-radius:11px;padding:11px 13px;box-shadow:var(--shadow);font-size:12.5px;backdrop-filter:blur(14px);animation:toast-in .2s ease-out}
.toast.ok{border-left-color:var(--ok)}.toast.bad{border-left-color:var(--bad)}.toast.warn{border-left-color:var(--warn)}
@keyframes toast-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.modal{position:fixed;inset:0;background:rgba(2,6,15,.72);display:none;place-items:center;padding:20px;z-index:70;backdrop-filter:blur(8px)}
html[data-theme="light"] .modal{background:rgba(15,23,42,.42)}
.modal.show{display:grid}
.modal .box{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line2);border-radius:16px;
  max-width:820px;width:100%;max-height:86vh;overflow:auto;padding:20px;box-shadow:var(--shadow)}
.modal h3{margin:0 0 12px;font-size:17px;letter-spacing:-.02em}
.kbd{background:var(--bg-soft);border:1px solid var(--line2);border-bottom-width:2px;border-radius:5px;padding:1px 5px;font-size:11px;color:var(--text)}
.notice{border-left:3px solid var(--warn);background:color-mix(in srgb,var(--warn) 10%,var(--panel));border-radius:9px;padding:10px 12px;
  color:color-mix(in srgb,var(--warn) 72%,var(--text));font-size:12.5px;margin:10px 0}
.okbox{border-left:3px solid var(--ok);background:color-mix(in srgb,var(--ok) 9%,var(--panel));border-radius:9px;padding:10px 12px;font-size:12.5px}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
input:focus-visible,select:focus-visible,textarea:focus-visible{outline:none}
@media(max-width:1180px){.app{grid-template-columns:236px minmax(0,1fr)}.main{padding-inline:22px}}
@media(max-width:900px){
  .app{grid-template-columns:1fr}
  .side{position:sticky;top:0;height:auto;z-index:50;flex-direction:row;align-items:center;gap:12px;padding:10px 14px;
    border-right:0;border-bottom:1px solid var(--line);backdrop-filter:blur(20px)}
  .brand{padding:0;border:0;flex:0 0 auto}
  .brand-copy small{display:none}
  .logo{width:36px;height:36px;flex-basis:36px;border-radius:11px}
  .logo svg{width:21px;height:21px}
  .nav{flex-direction:row;gap:4px;overflow-x:auto;padding:0 2px 2px}
  .nav-group{display:contents}
  .nav-label{display:none}
  .nav button{width:auto;white-space:nowrap;padding:8px 10px}
  .side .foot{display:none}
  .main{padding:22px 18px 60px}
}
@media(max-width:760px){
  .stats{grid-template-columns:repeat(2,minmax(0,1fr))}
  .page-head{flex-direction:column;gap:12px}
  .page-actions{width:100%;justify-content:flex-end}
  .repo-bar{align-items:stretch;flex-direction:column}
  .repo-bar .field{min-width:0;width:100%;flex:auto}
  .repo-bar .btn{width:100%}
  .grid.g2,.grid.g3,.grid.g4{grid-template-columns:1fr}
  .nav-label-text{display:none}
  .nav button{padding:9px}
  .card{padding:16px}
  .diff{grid-template-columns:1fr}
  .toasts{left:12px;right:12px;bottom:12px;max-width:none}
}
@media(prefers-reduced-motion:reduce){
  html{scroll-behavior:auto}
  *,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}
}
</style>
</head>
<body>
<a class="skip-link" href="#mainContent">Skip to content</a>
<div class="app">
  <aside class="side">
    <div class="brand">
      <div class="logo" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 4.5 6v5.2c0 4.6 3.2 8.8 7.5 9.8 4.3-1 7.5-5.2 7.5-9.8V6L12 3Z"/><path d="m8.7 12.2 2.1 2.1 4.6-4.6"/></svg>
      </div>
      <div class="brand-copy"><h1>Commit Guard</h1><small>Local Control Center</small></div>
    </div>
    <nav class="nav" id="nav" aria-label="Main navigation">
      <div class="nav-group">
        <span class="nav-label">Workspace</span>
        <button type="button" data-tab="scan" class="active" title="Scan">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4"/></svg>
          <span class="nav-label-text">Scan</span>
        </button>
        <button type="button" data-tab="git" title="Git workspace">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="2.2"/><circle cx="6" cy="18" r="2.2"/><circle cx="18" cy="8" r="2.2"/><path d="M6 8.2v7.6M8.2 6H14a4 4 0 0 1 4 4"/></svg>
          <span class="nav-label-text">Git</span>
        </button>
        <button type="button" data-tab="fixes" title="Fixes and suggestions">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3 1.6 4.4L18 9l-4.4 1.6L12 15l-1.6-4.4L6 9l4.4-1.6L12 3Z"/><path d="m5 15 .8 2.2L8 18l-2.2.8L5 21l-.8-2.2L2 18l2.2-.8L5 15Z"/></svg>
          <span class="nav-label-text">Fixes &amp; suggestions</span>
        </button>
        <button type="button" data-tab="pr" title="Pull requests">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 7h10M7 7l3-3M7 7l3 3M17 17H7m10 0-3-3m3 3-3 3"/></svg>
          <span class="nav-label-text">Pull requests</span>
        </button>
        <button type="button" data-tab="baseline" title="Baseline and suppressions">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5M3 16l9 5 9-5"/></svg>
          <span class="nav-label-text">Baseline</span>
        </button>
      </div>
      <div class="nav-group">
        <span class="nav-label">Quality</span>
        <button type="button" data-tab="rules" title="Rules">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M8 6h12M8 12h12M8 18h12"/><circle cx="4" cy="6" r="1"/><circle cx="4" cy="12" r="1"/><circle cx="4" cy="18" r="1"/></svg>
          <span class="nav-label-text">Rules</span>
        </button>
        <button type="button" data-tab="reports" title="Reports">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h8l4 4v14H6V3Z"/><path d="M14 3v4h4M9 12h6M9 16h6"/></svg>
          <span class="nav-label-text">Reports</span>
        </button>
      </div>
      <div class="nav-group">
        <span class="nav-label">System</span>
        <button type="button" data-tab="maintenance" title="Maintenance">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 6.5a4 4 0 0 0-5.2 5.2L4 17l3 3 5.3-5.3a4 4 0 0 0 5.2-5.2l-2.1 2.1-2.1-2.1 2.2-2.2Z"/></svg>
          <span class="nav-label-text">Maintenance</span>
        </button>
        <button type="button" data-tab="config" title="Configuration">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/></svg>
          <span class="nav-label-text">Configuration</span>
        </button>
        <button type="button" data-tab="help" title="Help">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M9.6 9a2.5 2.5 0 1 1 3.6 2.2c-.8.4-1.2 1-1.2 1.8v.5"/><circle cx="12" cy="17" r=".7" fill="currentColor" stroke="none"/></svg>
          <span class="nav-label-text">Help</span>
        </button>
      </div>
    </nav>
    <div class="foot">
      <div class="local-status"><span class="status-dot"></span> Local only · 127.0.0.1</div>
      <div class="version-line" id="versionLine">Commit Guard</div>
    </div>
  </aside>

  <main class="main" id="mainContent">
    <header class="page-head">
      <div>
        <span class="eyebrow">Commit Guard workspace</span>
        <h2 id="pageTitle">Scan</h2>
        <p id="pageSubtitle">Run the same security checks as hooks and CI, then review findings in one place.</p>
      </div>
      <div class="page-actions">
        <button type="button" class="icon-btn" id="themeToggle" title="Toggle light/dark theme" aria-label="Toggle light/dark theme">
          <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
          <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5a8.5 8.5 0 1 0 11 11Z"/></svg>
        </button>
      </div>
    </header>
    <div class="repo-bar">
      <div class="field">
        <label for="repoPath">Repository</label>
        <input id="repoPath" placeholder="/path/to/git/repository" spellcheck="false">
      </div>
      <button class="btn primary" id="loadRepoBtn">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 5l7 7-7 7"/></svg>
        Load
      </button>
      <button class="btn" id="refreshInfoBtn">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 9a7 7 0 0 1 11.4-2L20 9M4 15l2.5 2a7 7 0 0 0 11.4-2"/></svg>
        Refresh status
      </button>
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
            <label class="small"><input type="checkbox" id="optNoConfig"> Ignore .commit_guard.toml</label>
            <label class="small"><input type="checkbox" id="optStrict"> Strict mode (suppression issues fail)</label>
            <label class="small"><input type="checkbox" id="optSoftFail"> Soft-fail (always exit 0)</label>
            <label class="small"><input type="checkbox" id="optGithubAnnotations"> GitHub Actions annotations</label>
            <label class="small"><input type="checkbox" id="optVerboseRules"> Verbose skipped-rule diagnostics</label>
            <div class="field"><label for="configPath">Custom config file</label><input id="configPath" placeholder="optional path"></div>
            <div class="field"><label for="rulesDir">Custom rules directory</label><input id="rulesDir" placeholder="optional path"></div>
            <div class="field"><label for="baselinePath">Custom baseline file</label><input id="baselinePath" placeholder="optional path"></div>
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
            <label class="small"><input type="checkbox" id="optFixDryRun"> Preview fixes only (dry run)</label>
            <label class="small"><input type="checkbox" id="optFixApply"> Apply and stage safe fixes</label>
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
              <button class="btn small suggest" id="suggestAllFixesBtn" title="Preview all available automated fixes and recommendations">Suggest all fixes (<span id="fixableCountBadge">0</span>)</button>
              <button class="btn small apply" id="applySelectedFixesBtn" disabled title="Apply selected fixes and stage modified files">Apply selected fixes (<span id="selectedFixCount">0</span>)</button>
              <button class="btn small" id="selectAllFixableBtn">Select all fixable</button>
              <button class="btn small" id="deselectAllBtn" style="display:none">Deselect all</button>
            </div>
            <div class="small muted" id="selectedInfoText">Click checkboxes to apply multiple fixes at once</div>
          </div>
          <div class="table-wrap">
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

      <div class="card">
        <h2>Dependency graph</h2>
        <p class="hint">Build a local import graph and blast-radius view from Python, JavaScript/TypeScript, Java, and similar source files. Output can be saved into the repository.</p>
        <div class="grid g3">
          <div class="field"><label for="graphFormat">Format</label>
            <select id="graphFormat"><option>mermaid</option><option>json</option><option>dot</option><option>all</option></select>
          </div>
          <div class="field"><label for="graphMax">Maximum nodes</label><input id="graphMax" type="number" min="1" value="250"></div>
          <div class="field"><label>&nbsp;</label>
            <div class="row">
              <button class="btn primary" id="buildGraphBtn">Build graph</button>
              <button class="btn" id="saveGraphBtn">Build &amp; save</button>
            </div>
          </div>
        </div>
        <div class="row" style="margin-top:12px">
          <button class="btn" id="downloadGraphBtn" disabled>Download graph</button>
          <span class="small muted" id="graphFiles"></span>
        </div>
        <div class="stats" id="graphStats"></div>
        <pre class="pre hidden" id="graphOut"></pre>
      </div>
    </section>

    <section id="tab-git" class="hidden">
      <div class="card">
        <h2>Repository state</h2>
        <p class="hint" id="gitSummary">Load a repository to inspect its working tree.</p>
        <div id="gitOperation"></div>
        <div class="stats" id="gitStats"></div>
        <div class="row" style="margin:12px 0">
          <button class="btn" id="gitRefreshBtn">Refresh</button>
          <button class="btn" id="gitStageAllBtn">Stage all</button>
          <button class="btn" id="gitUnstageAllBtn">Unstage all</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Path</th><th>Index</th><th>Worktree</th><th class="right">Actions</th></tr></thead>
            <tbody id="gitFilesBody"></tbody>
          </table>
        </div>
        <p class="hint" id="gitFilesHint" style="margin:10px 0 0"></p>
      </div>

      <div class="card hidden" id="gitDiffCard">
        <div class="row" style="justify-content:space-between;align-items:center;margin-bottom:8px">
          <h2 id="gitDiffTitle" style="margin:0">Diff</h2>
          <button class="btn small" id="gitDiffClose">Close</button>
        </div>
        <pre class="pre" id="gitDiffOut"></pre>
      </div>

      <div class="card">
        <h2>Commit</h2>
        <p class="hint">Commits staged changes with your configured Git identity. Enable “include tracked changes” to stage all modified tracked files first.</p>
        <div class="field"><label for="gitCommitMsg">Commit message</label><input id="gitCommitMsg" placeholder="Describe the change..."></div>
        <div class="row" style="margin-top:12px">
          <label class="small"><input type="checkbox" id="gitCommitAll"> Include tracked changes (-a)</label>
          <button class="btn primary" id="gitCommitBtn">Commit staged changes</button>
        </div>
        <pre class="pre hidden" id="gitCommitOut" style="margin-top:12px"></pre>
      </div>

      <div class="card">
        <h2>Sync with remote</h2>
        <p class="hint">Fetch updates, pull with fast-forward only, or push the current branch. Destructive operations require confirmation.</p>
        <div class="grid g3">
          <div class="field"><label for="gitRemote">Remote</label><select id="gitRemote"><option value="origin">origin</option></select></div>
          <div class="field"><label>&nbsp;</label><button class="btn" id="gitFetchBtn">Fetch</button></div>
          <div class="field"><label>&nbsp;</label><button class="btn" id="gitPullBtn">Pull (fast-forward)</button></div>
          <div class="field"><label>&nbsp;</label><button class="btn primary" id="gitPushBtn">Push current branch</button></div>
        </div>
      </div>

      <div class="card">
        <h2>Branches</h2>
        <p class="hint">Create, switch, or delete local branches. The current branch and remote branches are shown below.</p>
        <div class="grid g3">
          <div class="field"><label for="gitNewBranch">New branch name</label><input id="gitNewBranch" placeholder="feature/my-change"></div>
          <div class="field"><label for="gitStartPoint">Start point (optional)</label><input id="gitStartPoint" placeholder="main"></div>
          <div class="field"><label>&nbsp;</label>
            <div class="row">
              <button class="btn primary" id="gitCreateBranchBtn">Create &amp; switch</button>
              <button class="btn" id="gitCreateOnlyBtn">Create only</button>
            </div>
          </div>
        </div>
        <div id="gitBranchesOut" style="margin-top:14px"></div>
      </div>

      <div class="card">
        <h2>Recent commits</h2>
        <div class="row" style="margin-bottom:12px">
          <div class="field"><label for="gitLogLimit">Commit limit</label><input id="gitLogLimit" type="number" min="1" max="200" value="20"></div>
          <button class="btn" id="gitLogBtn">Reload</button>
        </div>
        <div id="gitLogOut"></div>
      </div>

      <div class="card">
        <h2>History doctor</h2>
        <p class="hint">Scan recent commit history and inspect the commits that introduced findings. Leave the limit at 0 to audit all history.</p>
        <div class="row">
          <div class="field"><label for="gitDoctorLimit">Commits to audit</label><input id="gitDoctorLimit" type="number" min="0" value="50"></div>
          <button class="btn primary" id="gitDoctorBtn">Scan history</button>
        </div>
        <div id="gitDoctorOut" style="margin-top:12px"></div>
      </div>
    </section>

    <section id="tab-fixes" class="hidden">
      <div class="card">
        <h2>Safe fixes &amp; suggestions</h2>
        <p class="hint">Preview rule-provided fixes, choose exactly which ones to apply, then Commit Guard writes and stages the files just like <code>scan --fix</code>. Secrets are never auto-fixed.</p>
        <div class="row" style="align-items:center;gap:8px">
          <button class="btn" id="previewFixesBtn">Preview fixes from last scan</button>
          <button class="btn primary apply" id="applyFixesBtn" disabled>Apply selected fixes</button>
          <button class="btn suggest" id="suggestionsBtn">Preview PR inline suggestions</button>
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
        <div class="table-wrap"><table>
          <thead><tr><th>Line</th><th>Kind</th><th>Value</th><th>Owner</th><th>Expiry</th></tr></thead>
          <tbody id="baselineBody"></tbody>
        </table></div>
        <p class="hint" id="baselinePathInfo"></p>
      </div>
    </section>

    <section id="tab-rules" class="hidden">
      <div class="card">
        <h2>Download &amp; enable rule packs</h2>
        <p class="hint">Opt-in network access: rules are fetched only when you click the button. Official gitleaks rules update <code>rules/gitleaks.toml</code>; YAML packs are validated, installed under <code>rules/custom/</code> or <code>rules/semgrep_rules/</code>, and enabled immediately.</p>
        <div class="notice">Rule patterns are code-execution inputs for the scanner's regex engine. Only download packs from sources you trust.</div>
        <div class="grid g3">
          <div class="field"><label for="rulePackSource">Pack source</label>
            <select id="rulePackSource">
              <option value="gitleaks">Gitleaks upstream (TOML)</option>
              <option value="semgrep">Semgrep YAML (regex-compatible)</option>
              <option value="custom">Commit Guard native YAML</option>
            </select>
          </div>
          <div class="field"><label for="rulePackUrl">URL</label><input id="rulePackUrl" spellcheck="false"></div>
          <div class="field"><label for="rulePackName">Pack name (YAML only)</label><input id="rulePackName" placeholder="team-rules"></div>
        </div>
        <div class="row" style="margin-top:10px">
          <button class="btn primary" id="downloadRulesBtn">Download &amp; enable</button>
          <span class="muted small" id="downloadRulesStatus"></span>
        </div>
        <div id="downloadRulesOut" style="margin-top:10px"></div>
      </div>
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
        <div class="table-wrap"><table>
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
        <div class="table-wrap"><table>
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
          <tr><td><b>Rules</b></td><td>Browse active rules, inspect patterns, validate the rule pack, and download/update opt-in packs.</td></tr>
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
const TAB_META = {
  scan: ["Scan", "Run the same security checks as hooks and CI, then review findings in one place."],
  git: ["Git workspace", "Inspect changes, stage files, commit, sync remotes, and manage branches without leaving the page."],
  fixes: ["Fixes & suggestions", "Preview rule-provided fixes, apply only what you select, and inspect PR-ready suggestions."],
  pr: ["Pull requests", "Publish security reports and inline fix suggestions to GitHub with a session-only token."],
  baseline: ["Baseline & suppressions", "Accept known findings, attach ownership and expiry, and audit stale suppressions."],
  rules: ["Rule library", "Search active rules, validate coverage, and download trusted rule packs on demand."],
  reports: ["Reports", "Export the last scan as HTML, JSON, SARIF, JUnit, GitLab, Checkstyle, or Markdown."],
  maintenance: ["Maintenance", "Install, update, and repair Commit Guard, or control the repository hook."],
  config: ["Configuration", "Edit the validated .commit_guard.toml configuration with automatic backups."],
  help: ["Help & safety", "How this control center maps to the CLI, plus the local-only safety model."]
};
function applyTheme(theme){
  const next = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("commitguard.theme", next); } catch(e){}
  const button = $("#themeToggle");
  if(button){
    const label = next === "light" ? "Switch to dark theme" : "Switch to light theme";
    button.title = label;
    button.setAttribute("aria-label", label);
  }
}
function showTab(name){
  $$("#nav button").forEach((b) => {
    const active = b.dataset.tab === name;
    b.classList.toggle("active", active);
    b.setAttribute("aria-current", active ? "page" : "false");
  });
  $$("main > section").forEach((s) => s.classList.toggle("hidden", s.id !== "tab-" + name));
  const meta = TAB_META[name] || TAB_META.scan;
  $("#pageTitle").textContent = meta[0];
  $("#pageSubtitle").textContent = meta[1];
  document.title = meta[0] + " · Commit Guard";
  try { history.replaceState(null, "", "#" + name); } catch(e){}
  if(name === "reports") loadReports().catch(()=>{});
  if(name === "baseline") loadBaseline().catch(()=>{});
  if(name === "config") loadConfig().catch(()=>{});
  if(name === "rules" && !state.rules.length) loadRules().catch(()=>{});
  if(name === "git" && state.repo) loadGit().catch((e) => notify(e.message, "bad"));
}
$$("#nav button").forEach((b) => {
  if(!b.getAttribute("aria-label")) b.setAttribute("aria-label", b.title || b.textContent.trim());
  b.addEventListener("click", () => showTab(b.dataset.tab));
});
window.addEventListener("hashchange", () => {
  const name = location.hash.slice(1);
  if(TAB_META[name]) showTab(name);
});
$("#themeToggle").addEventListener("click", () => {
  applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
});

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
    no_config: $("#optNoConfig").checked,
    strict: $("#optStrict").checked,
    soft_fail: $("#optSoftFail").checked,
    github_annotations: $("#optGithubAnnotations").checked,
    verbose_rules: $("#optVerboseRules").checked,
    config_path: $("#configPath").value.trim(),
    rules_dir: $("#rulesDir").value.trim(),
    baseline_path: $("#baselinePath").value.trim(),
    fix: $("#optFixApply").checked,
    fix_dry_run: $("#optFixDryRun").checked,
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
      (report.fixable ? '<button class="btn suggest" data-banner="suggest-all">Suggest fixes (' + report.fixable + ')</button>' : '') +
      (report.fixable ? '<button class="btn apply" data-banner="apply-all">Quick apply all (' + report.fixable + ')</button>' : '') +
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
          (f.fixable ? ' <span class="chip ok" title="Automated fix available">fixable</span>' : '') +
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
          '<button class="btn small suggest" data-act="suggest-fix" data-idx="' + idx + '" title="View suggested remediation or automated fix diff">Suggest fix</button> ' +
          (f.fixable ? (isApplied ? '<span class="btn small applied">Applied</span> ' : '<button class="btn small apply" data-act="apply-fix" data-idx="' + idx + '" title="Apply this fix to disk and git stage">Apply</button> ') : '') +
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
    (isFixable ? "Suggested fix · " : "Remediation guidance · ") + esc(f.rule_id),
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
            (f._applied ? '<span class="chip ok">Already applied</span>' : '<span class="chip ok">Auto-fix available</span>') +
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
            ? '<button class="btn primary apply" id="modalApplyBtn">Apply this fix &amp; stage file</button>'
            : '<span class="btn small applied">Fix already applied and staged</span>') +
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
              $("#modalFixActionRow").innerHTML = '<div class="okbox" style="flex:1">Fix applied to <code>' + esc(f.file) + '</code> and staged with git.</div>' +
                '<button class="btn primary small" id="modalRescanBtn">Rescan now</button>';
              const rescan = $("#modalRescanBtn");
              if(rescan) rescan.addEventListener("click", () => { $("#modal").classList.remove("show"); runScan(); });
              notify("Applied and staged fix for " + f.file + ":" + f.line, "ok");
            }catch(err){
              applyBtn.disabled = false;
              applyBtn.textContent = "Apply this fix & stage file";
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
      '<b>Hardcoded credential detected:</b><br>' +
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
      '<b>Dependency upgrade recommendation:</b><br>' +
      'Upgrade package to fixed version: <b><code>' + esc(f.fixed_versions.join(", ")) + '</code></b> in your manifest file.<br>' +
      (f.advisory_url ? '<div style="margin-top:6px"><a href="' + esc(f.advisory_url) + '" target="_blank" rel="noreferrer">Open official security advisory &rarr;</a></div>' : '') +
    '</div>';
  } else {
    guide += '<div class="card" style="background:#0a101a;margin-top:10px">' +
      '<b>Security remediation steps:</b><br>' +
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
    btn.outerHTML = '<span class="btn small applied">Applied</span>';
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
    btn.innerHTML = 'Apply selected fixes (<span id="selectedFixCount">0</span>)';
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
    '<div class="table-wrap"><table><thead><tr><th style="width:36px"><input type="checkbox" id="checkAllFixes" checked></th><th>Location</th><th>Rule</th><th>Change Preview</th><th class="right">Action</th></tr></thead><tbody>' +
    data.outcomes.map((o, i) =>
      '<tr><td><input type="checkbox" class="fix-check" data-i="' + i + '" checked></td>' +
      '<td><code>' + esc(o.file) + ':' + esc(o.line) + '</code></td>' +
      '<td><code>' + esc(o.rule_id) + '</code></td>' +
      '<td><div class="diff"><div class="before"><span class="diff-tag red">before</span><br><code>' + esc(o.before) + '</code></div>' +
      '<div class="after"><span class="diff-tag green">after</span><br><code>' + esc(o.after) + '</code></div></div></td>' +
      '<td class="right" style="vertical-align:middle"><button class="btn small apply" data-apply-fp="' + esc(o.fingerprint || "") + '" data-i="' + i + '">Apply</button></td></tr>'
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
        btn.outerHTML = '<span class="btn small applied">Applied</span>';
        notify("Applied and staged fix.", "ok");
        if(state.report && state.report.findings){
          state.report.findings.forEach((f) => { if(f.fingerprint === fp) f._applied = true; });
        }
      }catch(err){
        btn.disabled = false;
        btn.textContent = "Apply";
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
  $("#baselinePathInfo").textContent = data.path + (data.exists ? "" : " (does not exist yet)");
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

const DEFAULT_GITLEAKS_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml";
function syncRulePackFields(){
  const source = $("#rulePackSource").value;
  const url = $("#rulePackUrl");
  if(source === "gitleaks"){
    if(!url.value || url.dataset.official === "1"){ url.value = DEFAULT_GITLEAKS_URL; url.dataset.official = "1"; }
    $("#rulePackName").disabled = true;
    $("#rulePackName").placeholder = "not used for gitleaks";
  } else {
    if(url.dataset.official === "1"){ url.value = ""; url.dataset.official = "0"; }
    $("#rulePackName").disabled = false;
    $("#rulePackName").placeholder = source === "semgrep" ? "semgrep-pack" : "team-rules";
  }
}
$("#rulePackSource").addEventListener("change", syncRulePackFields);
syncRulePackFields();
$("#downloadRulesBtn").addEventListener("click", async () => {
  if(!state.repo){ notify("Load a repository first.", "warn"); return; }
  const source = $("#rulePackSource").value;
  const url = $("#rulePackUrl").value.trim();
  if(!url){ notify("Enter a rule pack URL.", "warn"); return; }
  const name = $("#rulePackName").value.trim();
  if(!confirm("Download rules from this URL?\n\n" + url + "\n\nThe pack will be validated and enabled immediately. A backup is kept for updates.")) return;
  const button = $("#downloadRulesBtn");
  button.disabled = true;
  $("#downloadRulesStatus").innerHTML = '<span class="spinner"></span> Downloading...';
  $("#downloadRulesOut").innerHTML = "";
  try{
    const data = await api("/api/rules/download", {method:"POST", body:{
      repo:state.repo, options:{source, url, name}
    }});
    $("#downloadRulesStatus").textContent = "Enabled.";
    const added = source === "gitleaks"
      ? "Updated the gitleaks pack."
      : esc(data.rules_added) + " new regex rule(s) added.";
    $("#downloadRulesOut").innerHTML = '<div class="okbox">Downloaded <b>' + esc(fmtBytes(data.bytes)) +
      '</b> into <code>' + esc(data.path) + '</code>. ' + added + ' ' +
      esc(data.rules_total) + ' active total, ' + esc(data.skipped) + ' unsupported entries skipped.' +
      (data.backup ? '<div class="small muted">Previous file backed up to <code>' + esc(data.backup) + '</code>.</div>' : '') +
      '</div>';
    notify("Rule pack downloaded and enabled.", "ok");
    await loadRules();
  }catch(err){
    $("#downloadRulesStatus").textContent = "Failed.";
    $("#downloadRulesOut").innerHTML = '<div class="notice">' + esc(err.message) + '</div>';
    notify(err.message, "bad");
  }finally{ button.disabled = false; }
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

/* -------------------------------------------------------------------------
   Dependency graph
   ------------------------------------------------------------------------- */
function graphExtension(format){
  return format === "json" ? "json" : (format === "dot" ? "dot" : "mmd");
}
function graphMime(format){
  if(format === "json") return "application/json";
  if(format === "dot") return "text/vnd.graphviz";
  return "text/plain";
}
async function buildGraph(save){
  if(!state.repo){ notify("Load a repository first.", "warn"); return; }
  const format = $("#graphFormat").value;
  const button = save ? $("#saveGraphBtn") : $("#buildGraphBtn");
  const original = button.textContent;
  button.disabled = true;
  button.innerHTML = '<span class="spinner"></span> Building...';
  try{
    const data = await api("/api/graph", {method:"POST", body:{repo:state.repo, options:{
      format, max_nodes:$("#graphMax").value, save:!!save
    }}});
    graphContent = data.content || "";
    graphFilename = "dependency-graph." + graphExtension(format);
    $("#graphStats").innerHTML =
      '<div class="stat"><b>' + esc(data.nodes) + '</b><span>files</span></div>' +
      '<div class="stat"><b>' + esc(data.edges) + '</b><span>import edges</span></div>' +
      '<div class="stat"><b>' + esc(data.external) + '</b><span>external imports</span></div>' +
      '<div class="stat"><b>' + esc(data.blast_radius) + '</b><span>exposed files</span></div>';
    const out = $("#graphOut");
    out.textContent = graphContent;
    out.classList.remove("hidden");
    $("#downloadGraphBtn").disabled = !graphContent;
    $("#graphFiles").innerHTML = data.saved && data.saved.length
      ? "Saved: " + data.saved.map((p) => '<code>' + esc(p) + '</code>').join(", ")
      : "";
    notify("Dependency graph built (" + data.nodes + " files).", "ok");
  }catch(err){ notify(err.message, "bad"); }
  finally{ button.disabled = false; button.textContent = original; }
}
$("#buildGraphBtn").addEventListener("click", () => buildGraph(false));
$("#saveGraphBtn").addEventListener("click", () => buildGraph(true));
$("#downloadGraphBtn").addEventListener("click", () => {
  if(!graphContent) return;
  downloadBlob(graphContent, graphFilename, graphMime($("#graphFormat").value));
});

/* -------------------------------------------------------------------------
   Git workspace
   ------------------------------------------------------------------------- */
function gitTrack(branch){
  const parts = [];
  if(branch.upstream) parts.push("tracking " + branch.upstream);
  if(branch.ahead) parts.push("ahead " + branch.ahead);
  if(branch.behind) parts.push("behind " + branch.behind);
  if(branch.gone) parts.push("upstream gone");
  return parts.join(" · ");
}
function setGitRemoteOptions(remotes){
  const select = $("#gitRemote");
  const previous = select.value;
  select.innerHTML = (remotes || []).map((r) => '<option value="' + esc(r.name) + '">' + esc(r.name) + '</option>').join("") ||
    '<option value="origin">origin</option>';
  if(previous && Array.from(select.options).some((o) => o.value === previous)) select.value = previous;
}
function renderGitStatus(){
  const status = state.git && state.git.status;
  if(!status) return;
  const branchLabel = status.detached ? "detached HEAD" : (status.branch || "no commits yet");
  $("#gitSummary").innerHTML = '<code>' + esc(status.repo) + '</code> · ' +
    '<b>' + esc(branchLabel) + '</b>' +
    (status.upstream ? ' · <span class="muted">' + esc(status.upstream) + '</span>' : ' · <span class="muted">no upstream</span>') +
    (status.ahead ? ' · <span class="chip ok">ahead ' + esc(status.ahead) + '</span>' : '') +
    (status.behind ? ' · <span class="chip warn">behind ' + esc(status.behind) + '</span>' : '') +
    (status.clean ? ' · <span class="chip ok">clean</span>' : ' · <span class="chip warn">changes</span>');
  $("#gitStats").innerHTML =
    '<div class="stat"><b>' + esc(status.staged_count) + '</b><span>staged</span></div>' +
    '<div class="stat"><b>' + esc(status.unstaged_count) + '</b><span>unstaged</span></div>' +
    '<div class="stat"><b>' + esc(status.untracked_count) + '</b><span>untracked</span></div>' +
    '<div class="stat"><b>' + esc(status.ahead) + '</b><span>ahead</span></div>' +
    '<div class="stat"><b>' + esc(status.behind) + '</b><span>behind</span></div>';
  $("#gitOperation").innerHTML = status.operation
    ? '<div class="notice">Git operation in progress: <b>' + esc(status.operation) + '</b>. Resolve it before committing or switching branches.</div>'
    : "";
  const body = $("#gitFilesBody");
  if(!status.files.length){
    body.innerHTML = '<tr><td colspan="4" class="muted">Working tree is clean.</td></tr>';
  } else {
    body.innerHTML = status.files.map((f, index) => {
      const actions = [];
      if(f.unstaged || f.untracked) actions.push('<button class="btn small" data-git-stage="' + index + '">Stage</button>');
      if(f.staged) actions.push('<button class="btn small" data-git-unstage="' + index + '">Unstage</button>');
      if(f.staged) actions.push('<button class="btn small" data-git-diff="' + index + '" data-staged="1">Staged diff</button>');
      if(f.unstaged) actions.push('<button class="btn small" data-git-diff="' + index + '" data-staged="0">Diff</button>');
      return '<tr><td><code>' + esc(f.path) + '</code>' + (f.original_path ? '<div class="small muted">from ' + esc(f.original_path) + '</div>' : '') + '</td>' +
        '<td>' + esc(f.index) + '</td><td>' + esc(f.worktree) + '</td>' +
        '<td class="right" style="white-space:nowrap">' + actions.join(" ") + '</td></tr>';
    }).join("");
  }
  $("#gitFilesHint").textContent = status.files.length + " changed path(s). Remote operations use the selected remote.";
  setGitRemoteOptions(state.git.remotes);
}
function renderGitBranches(){
  const branches = state.git && state.git.branches;
  if(!branches) return;
  const local = branches.local || [];
  const rows = local.map((b) => {
    const track = gitTrack(b);
    return '<tr><td>' + (b.current ? '<span class="chip ok">current</span> ' : '') + '<code>' + esc(b.name) + '</code></td>' +
      '<td class="small muted">' + esc(track || b.commit) + '</td><td class="small">' + esc(b.subject) + '</td>' +
      '<td class="right" style="white-space:nowrap">' +
        (!b.current ? '<button class="btn small" data-branch-switch="' + esc(b.name) + '">Switch</button> ' : '') +
        (!b.current ? '<button class="btn small danger" data-branch-delete="' + esc(b.name) + '">Delete</button>' : '') +
      '</td></tr>';
  }).join("") || '<tr><td colspan="4" class="muted">No local branches yet.</td></tr>';
  const remote = (branches.remote || []).map((b) => '<span class="chip">' + esc(b.name) + '</span>').join(" ") || '<span class="muted small">none</span>';
  $("#gitBranchesOut").innerHTML = '<div class="table-wrap"><table><thead><tr><th>Local branch</th><th>Tracking</th><th>Last commit</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
    '<div class="small muted" style="margin-top:10px">Remote branches: ' + remote + '</div>';
}
function commitRows(commits){
  if(!commits || !commits.length) return '<tr><td colspan="5" class="muted">No commits found.</td></tr>';
  return commits.map((c) =>
    '<tr><td><code>' + esc(c.short) + '</code></td><td>' + esc(c.author) + '</td><td class="small muted">' + esc(c.date) + '</td>' +
    '<td>' + esc(c.subject) + '</td><td>' + (c.refs||[]).map((r) => '<span class="chip">' + esc(r) + '</span>').join(" ") + '</td></tr>'
  ).join("");
}
function renderGitLog(commits){
  $("#gitLogOut").innerHTML = '<div class="table-wrap"><table><thead><tr><th>Commit</th><th>Author</th><th>Date</th><th>Subject</th><th>Refs</th></tr></thead><tbody>' +
    commitRows(commits) + '</tbody></table></div>';
}
async function loadGit(){
  if(!state.repo){ notify("Load a repository first.", "warn"); return; }
  const repo = encodeURIComponent(state.repo);
  const limit = $("#gitLogLimit").value || 20;
  const [status, branches, log, remotes] = await Promise.all([
    api("/api/git/status?repo=" + repo),
    api("/api/git/branches?repo=" + repo),
    api("/api/git/log?repo=" + repo + "&limit=" + encodeURIComponent(limit)),
    api("/api/git/remotes?repo=" + repo)
  ]);
  state.git = {status, branches, remotes:remotes.remotes || [], commits:log.commits || []};
  renderGitStatus();
  renderGitBranches();
  renderGitLog(state.git.commits);
}
async function reloadGitAfter(data, message){
  if(data && data.status) state.git.status = data.status;
  await loadGit();
  if(message) notify(message, "ok");
}
async function gitDiff(path, staged, title){
  $("#gitDiffCard").classList.remove("hidden");
  $("#gitDiffTitle").textContent = title || ("Diff · " + (path || "working tree"));
  $("#gitDiffOut").textContent = "Loading...";
  try{
    const data = await api("/api/git/diff?repo=" + encodeURIComponent(state.repo) +
      "&staged=" + (staged ? "1" : "0") + "&path=" + encodeURIComponent(path || ""));
    $("#gitDiffOut").textContent = data.empty ? "No differences." : data.diff;
    $("#gitDiffCard").scrollIntoView({behavior:"smooth", block:"start"});
  }catch(err){
    $("#gitDiffOut").textContent = err.message;
    notify(err.message, "bad");
  }
}
$("#gitDiffClose").addEventListener("click", () => $("#gitDiffCard").classList.add("hidden"));
$("#gitRefreshBtn").addEventListener("click", () => loadGit().catch((e) => notify(e.message, "bad")));
$("#gitStageAllBtn").addEventListener("click", async () => {
  try{
    const data = await api("/api/git/add", {method:"POST", body:{repo:state.repo, all:true}});
    await reloadGitAfter(data, "Staged all changes.");
  }catch(err){ notify(err.message, "bad"); }
});
$("#gitUnstageAllBtn").addEventListener("click", async () => {
  try{
    const data = await api("/api/git/unstage", {method:"POST", body:{repo:state.repo, all:true}});
    await reloadGitAfter(data, "Unstaged all changes.");
  }catch(err){ notify(err.message, "bad"); }
});
$("#gitFilesBody").addEventListener("click", async (event) => {
  const stage = event.target.closest("[data-git-stage]");
  const unstage = event.target.closest("[data-git-unstage]");
  const diff = event.target.closest("[data-git-diff]");
  if(stage){
    const f = state.git.status.files[Number(stage.dataset.gitStage)];
    if(!f) return;
    try{
      const data = await api("/api/git/add", {method:"POST", body:{repo:state.repo, paths:[f.path]}});
      await reloadGitAfter(data, "Staged " + f.path);
    }catch(err){ notify(err.message, "bad"); }
  } else if(unstage){
    const f = state.git.status.files[Number(unstage.dataset.gitUnstage)];
    if(!f) return;
    try{
      const data = await api("/api/git/unstage", {method:"POST", body:{repo:state.repo, paths:[f.path]}});
      await reloadGitAfter(data, "Unstaged " + f.path);
    }catch(err){ notify(err.message, "bad"); }
  } else if(diff){
    const f = state.git.status.files[Number(diff.dataset.gitDiff)];
    if(f) gitDiff(f.path, diff.dataset.staged === "1", (diff.dataset.staged === "1" ? "Staged diff · " : "Diff · ") + f.path);
  }
});
$("#gitCommitBtn").addEventListener("click", async () => {
  const message = $("#gitCommitMsg").value.trim();
  if(!message){ notify("Enter a commit message.", "warn"); return; }
  if(!confirm("Commit staged changes?\n\n" + message)) return;
  $("#gitCommitBtn").disabled = true;
  try{
    const data = await api("/api/git/commit", {method:"POST", body:{
      repo:state.repo, message, all_tracked:$("#gitCommitAll").checked
    }});
    $("#gitCommitOut").textContent = data.output || ("Committed " + data.commit);
    $("#gitCommitOut").classList.remove("hidden");
    $("#gitCommitMsg").value = "";
    await reloadGitAfter(data, "Committed changes.");
  }catch(err){ notify(err.message, "bad"); }
  finally{ $("#gitCommitBtn").disabled = false; }
});
$("#gitFetchBtn").addEventListener("click", async () => {
  const remote = $("#gitRemote").value || "origin";
  const button = $("#gitFetchBtn");
  button.disabled = true;
  try{
    const data = await api("/api/git/fetch", {method:"POST", body:{repo:state.repo, remote}});
    await reloadGitAfter(data, "Fetched " + remote + ".");
    if(data.output) modal("Fetch output", "<pre class='pre'>" + esc(data.output) + "</pre>");
  }catch(err){ notify(err.message, "bad"); }
  finally{ button.disabled = false; }
});
$("#gitPullBtn").addEventListener("click", async () => {
  const remote = $("#gitRemote").value || "origin";
  if(!confirm("Pull from " + remote + " using fast-forward only?")) return;
  const button = $("#gitPullBtn");
  button.disabled = true;
  try{
    const data = await api("/api/git/pull", {method:"POST", body:{repo:state.repo, remote}});
    await reloadGitAfter(data, "Pulled " + remote + ".");
    if(data.output) modal("Pull output", "<pre class='pre'>" + esc(data.output) + "</pre>");
  }catch(err){ notify(err.message, "bad"); }
  finally{ button.disabled = false; }
});
$("#gitPushBtn").addEventListener("click", async () => {
  const status = state.git && state.git.status;
  if(!status || !status.branch){ notify("Cannot push from a detached HEAD.", "warn"); return; }
  const remote = $("#gitRemote").value || "origin";
  const target = remote + "/" + status.branch;
  if(!confirm("Push " + status.branch + " to " + target + "?")) return;
  const button = $("#gitPushBtn");
  button.disabled = true;
  try{
    const data = await api("/api/git/push", {method:"POST", body:{
      repo:state.repo, remote, branch:status.branch, set_upstream:!status.upstream
    }});
    await reloadGitAfter(data, "Pushed to " + target + ".");
    if(data.output) modal("Push output", "<pre class='pre'>" + esc(data.output) + "</pre>");
  }catch(err){ notify(err.message, "bad"); }
  finally{ button.disabled = false; }
});
async function createGitBranch(checkout){
  const name = $("#gitNewBranch").value.trim();
  if(!name){ notify("Enter a branch name.", "warn"); return; }
  try{
    const data = await api("/api/git/branches/create", {method:"POST", body:{
      repo:state.repo, name, start_point:$("#gitStartPoint").value.trim(), checkout:!!checkout
    }});
    $("#gitNewBranch").value = "";
    await reloadGitAfter(data, (checkout ? "Created and switched to " : "Created ") + name + ".");
  }catch(err){ notify(err.message, "bad"); }
}
$("#gitCreateBranchBtn").addEventListener("click", () => createGitBranch(true));
$("#gitCreateOnlyBtn").addEventListener("click", () => createGitBranch(false));
$("#gitBranchesOut").addEventListener("click", async (event) => {
  const switchBtn = event.target.closest("[data-branch-switch]");
  const deleteBtn = event.target.closest("[data-branch-delete]");
  if(switchBtn){
    const name = switchBtn.dataset.branchSwitch;
    if(state.git.status.clean === false && !confirm("The working tree has changes. Switch to " + name + " anyway?")) return;
    try{
      const data = await api("/api/git/branches/switch", {method:"POST", body:{repo:state.repo, name}});
      await reloadGitAfter(data, "Switched to " + name + ".");
    }catch(err){ notify(err.message, "bad"); }
  } else if(deleteBtn){
    const name = deleteBtn.dataset.branchDelete;
    if(!confirm("Delete merged local branch " + name + "?")) return;
    try{
      const data = await api("/api/git/branches/delete", {method:"POST", body:{repo:state.repo, name}});
      await reloadGitAfter(data, "Deleted branch " + name + ".");
    }catch(err){
      if(!/not fully merged/i.test(err.message)){ notify(err.message, "bad"); return; }
      const typed = prompt("Branch " + name + " is not fully merged. Type the branch name to force-delete it:");
      if(typed !== name){ notify("Delete cancelled.", "warn"); return; }
      try{
        const data = await api("/api/git/branches/delete", {method:"POST", body:{repo:state.repo, name, force:true, confirm:name}});
        await reloadGitAfter(data, "Force-deleted branch " + name + ".");
      }catch(forceErr){ notify(forceErr.message, "bad"); }
    }
  }
});
$("#gitLogBtn").addEventListener("click", async () => {
  try{
    const data = await api("/api/git/log?repo=" + encodeURIComponent(state.repo) + "&limit=" + encodeURIComponent($("#gitLogLimit").value || 20));
    renderGitLog(data.commits || []);
    if(state.git) state.git.commits = data.commits || [];
  }catch(err){ notify(err.message, "bad"); }
});
$("#gitDoctorBtn").addEventListener("click", async () => {
  const limit = Number($("#gitDoctorLimit").value || 0);
  if(limit < 0){ notify("History limit must be zero or positive.", "warn"); return; }
  const button = $("#gitDoctorBtn");
  button.disabled = true;
  $("#gitDoctorOut").innerHTML = '<div class="small muted"><span class="spinner"></span> Scanning the last ' + (limit || "all") + ' commit(s)...</div>';
  try{
    const data = await api("/api/history/doctor", {method:"POST", body:{
      repo:state.repo, limit, options:gatherOptions()
    }});
    state.report = data.report;
    state.options = data.options || Object.assign(gatherOptions(), {mode:"history", history:limit});
    renderResults();
    const summary = data.report.summary || {};
    const commits = (data.history && data.history.commits) || [];
    $("#gitDoctorOut").innerHTML =
      '<div class="okbox">Scanned <b>' + esc(limit || "all") + '</b> commit(s) of <b>' + esc(data.history.total_commits) + '</b> total · ' +
      esc(data.report.total || 0) + ' finding(s) · ' + esc(summary.critical || 0) + ' critical · ' + esc(summary.high || 0) + ' high · exit ' + esc(data.exit_code) +
      ' <button class="btn small" id="gitDoctorOpenFindings" style="margin-left:8px">Open findings</button></div>' +
      '<div class="table-wrap" style="margin-top:10px"><table><thead><tr><th>Commit</th><th>Author</th><th>Date</th><th>Subject</th><th>Refs</th></tr></thead><tbody>' +
      commitRows(commits) + '</tbody></table></div>';
    const openBtn = $("#gitDoctorOpenFindings");
    if(openBtn) openBtn.addEventListener("click", () => showTab("scan"));
    notify("History doctor finished: " + (data.report.total || 0) + " finding(s).", data.report.total ? "warn" : "ok");
  }catch(err){
    $("#gitDoctorOut").innerHTML = '<div class="notice">' + esc(err.message) + '</div>';
    notify(err.message, "bad");
  }finally{ button.disabled = false; }
});
$("#optFixApply").addEventListener("change", () => { if($("#optFixApply").checked) $("#optFixDryRun").checked = false; });
$("#optFixDryRun").addEventListener("change", () => { if($("#optFixDryRun").checked) $("#optFixApply").checked = false; });

(function init(){
  let savedTheme = null;
  try { savedTheme = localStorage.getItem("commitguard.theme"); } catch(e){}
  const prefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
  applyTheme(savedTheme || (prefersLight ? "light" : "dark"));
  let saved = null;
  try { saved = localStorage.getItem("commitguard.repo"); } catch(e){}
  const target = saved || INITIAL_REPO;
  if(target){ $("#repoPath").value = target; loadRepo(target).catch(() => {}); }
  else { $("#repoPath").focus(); }
  const initialTab = location.hash.slice(1);
  if(TAB_META[initialTab]) showTab(initialTab);
})();
</script>
</body>
</html>
"""
