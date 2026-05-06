// Hosted-by footer injected into uploaded HTML at view time, gated on the
// `footerHidden` flag in tiers.js. Anonymous and Free pages get the footer;
// Pro pages don't. Lives in a closed shadow DOM attached to a single host
// element so the user's CSS can't reach in (no class collisions, no global
// resets bleeding through) and ours can't leak back into their content.
//
// Injection is appended to the decrypted HTML string returned by /api/verify.
// The receiving iframe (view.html `#contentFrame`) has `sandbox="allow-scripts"`
// already, so the IIFE runs and Shadow DOM attaches normally — null-origin
// sandboxes still expose `Element.attachShadow`.
//
// Why server-side at view time, not bake-in at upload:
//   - existing pages get the footer immediately on next view
//   - Pro upgrade/downgrade is reflected without re-encrypting the blob
//     (footerHidden keys off tier_at_creation, which itself is fixed)

const HOST_FOOTER_HTML = `
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" data-pg-fonts>
<div id="pg-footer-host" data-pagegate-footer></div>
<script>
(function () {
  var host = document.getElementById('pg-footer-host');
  if (!host || !host.attachShadow) return;
  // \`all: initial\` resets every inheritable property so a hostile
  // \`* { all: unset !important }\` on the user side can't neutralize our
  // positioning. Max signed 32-bit z-index keeps us above their overlays.
  host.style.cssText = 'all: initial; position: fixed; left: 0; right: 0; bottom: 0; z-index: 2147483647; pointer-events: auto; display: block;';
  var shadow = host.attachShadow({ mode: 'closed' });
  shadow.innerHTML = [
    '<style>',
    ':host { all: initial; display: block; }',
    '* { box-sizing: border-box; }',
    '.wrap { background:#EFEBF4; border-top:1px solid rgba(21,21,26,0.12); box-shadow:0 -6px 24px rgba(20,20,30,0.05); min-height:76px; display:flex; align-items:center; gap:20px; padding:12px 28px; font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; color:#15151A; }',
    '.mark { display:inline-flex; align-items:baseline; gap:12px; color:#15151A; text-decoration:none; flex-shrink:0; line-height:1; }',
    '.hosted { font-family:"JetBrains Mono",ui-monospace,"SF Mono",Menlo,monospace; font-size:13px; color:rgba(21,21,26,0.55); letter-spacing:0.04em; text-transform:uppercase; align-self:center; flex-shrink:0; }',
    '.brand { font-family:"Instrument Serif","Times New Roman",serif; font-weight:400; font-size:38px; line-height:0.92; letter-spacing:-0.02em; color:#15151A; }',
    '.brand em { font-style:italic; color:#6C5CE7; font-weight:400; }',
    '.spacer { flex:1; }',
    '.cta { display:inline-flex; align-items:center; gap:10px; background:#15151A; color:#EFEBF4; text-decoration:none; padding:12px 20px; border-radius:999px; font-family:"JetBrains Mono",ui-monospace,monospace; font-size:13px; font-weight:600; letter-spacing:0.02em; white-space:nowrap; transition:background 0.15s ease, transform 0.15s ease; flex-shrink:0; }',
    '.cta:hover { background:#6C5CE7; transform:translateX(2px); }',
    '.cta svg { width:12px; height:10px; }',
    '@media (max-width:720px){.wrap{min-height:64px;padding:10px 14px;gap:10px}.mark{gap:8px}.hosted{font-size:11px}.brand{font-size:28px}.cta{padding:9px 14px;font-size:12px}}',
    '@media (max-width:480px){.hosted{font-size:10px;letter-spacing:0.03em}.brand{font-size:24px}.cta{padding:8px 12px}}',
    '</style>',
    '<footer class="wrap" aria-label="PageGate">',
    '  <a class="mark" href="https://pagegate.app/" target="_blank" rel="noopener">',
    '    <span class="hosted">Hosted by</span>',
    '    <span class="brand">Page<em>Gate</em>.</span>',
    '  </a>',
    '  <span class="spacer"></span>',
    '  <a class="cta" href="https://pagegate.app/" target="_blank" rel="noopener">',
    '    Make your own',
    '    <svg viewBox="0 0 14 12" fill="none" aria-hidden="true">',
    '      <path d="M1 6h12M9 2l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
    '    </svg>',
    '  </a>',
    '</footer>'
  ].join('');
  // Sibling spacer reserves bottom-of-viewport space for the user's content,
  // so they can scroll past the footer. Sibling rather than \`body{padding-bottom}\`
  // because users sometimes hard-pin \`body{padding:0!important}\` and we want
  // adaptable behaviour.
  var spacer = document.createElement('div');
  spacer.setAttribute('aria-hidden', 'true');
  spacer.style.cssText = 'all: initial; display: block; height: 76px; width: 100%;';
  document.body.appendChild(spacer);
})();
</script>
`.trim();

module.exports = { HOST_FOOTER_HTML };
