

/* ==========================================================================
   XAREX LANDING PAGE — lp-* (redesigned)
   Dark glass · purple #7c6af7 · cyan #06b6d4 · green #3dd68c
   ========================================================================== */

/* ── Tokens & reset ─────────────────────────────────────────────────────── */
#landingPage {
  --c-bg:        #03040a;
  --c-bg-soft:   #06080f;
  --c-surface:   rgba(255,255,255,.04);
  --c-surface-2: rgba(255,255,255,.06);
  --c-border:    rgba(255,255,255,.08);
  --c-border-2:  rgba(255,255,255,.12);
  --c-accent:    #7c6af7;
  --c-violet:    #a78bfa;
  --c-cyan:      #06b6d4;
  --c-green:     #3dd68c;
  --c-red:       #f04f59;
  --c-orange:    #f0853a;
  --c-text:      #e2e8f0;
  --c-text-2:    #f8fafc;
  --c-muted:     #94a3b8;

  --grad-primary: linear-gradient(135deg, #7c6af7 0%, #a78bfa 100%);
  --grad-text:    linear-gradient(135deg, #a78bfa 0%, #06b6d4 100%);
  --grad-button:  linear-gradient(135deg, #7c6af7 0%, #5239d4 100%);

  --glass-blur:   blur(20px) saturate(160%);
  --shadow-card:  0 12px 48px rgba(0,0,0,.5);
  --shadow-glow:  0 8px 32px rgba(124,106,247,.45);

  --radius-sm:  10px;
  --radius:     14px;
  --radius-lg:  20px;
  --radius-xl:  24px;

  --ease:       cubic-bezier(.4,0,.2,1);

  display: block;
  background: var(--c-bg);
  color: var(--c-text);
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  font-size: 16px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  overflow-x: hidden;
}

#landingPage *,
#landingPage *::before,
#landingPage *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}
#landingPage a       { color: inherit; text-decoration: none; }
#landingPage ul      { list-style: none; }
#landingPage button  { font-family: inherit; cursor: pointer; }
#landingPage img     { display: block; max-width: 100%; }
#landingPage strong  { font-weight: 700; color: var(--c-text-2); }
#landingPage h1,
#landingPage h2,
#landingPage h3,
#landingPage h4 {
  font-weight: 800;
  line-height: 1.15;
  color: var(--c-text-2);
}

/* ── Scroll-reveal — GSAP owns the from-state, no opacity:0 here ────────── */
.lp-fade-up { transition: opacity .7s var(--ease), transform .7s var(--ease); }
.lp-reveal  { transition: opacity .65s var(--ease), transform .65s var(--ease); }
.lp-delay-1 { transition-delay: .12s; }
.lp-delay-2 { transition-delay: .24s; }
.lp-delay-3 { transition-delay: .36s; }
.lp-delay-4 { transition-delay: .48s; }

/* ── Alert bar ──────────────────────────────────────────────────────────── */
.lp-alert-bar {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  height: 44px;
  padding: 0 24px;
  background: linear-gradient(90deg, #4f46e5 0%, #0891b2 100%);
  font-size: .82rem;
  font-weight: 500;
  color: #fff;
  flex-wrap: wrap;
  position: relative;
  z-index: 150;
  letter-spacing: .01em;
}

.lp-alert-pulse {
  width: 8px; height: 8px;
  border-radius: 50%;
  background: #fde68a;
  flex-shrink: 0;
  animation: lpPulse 2s ease-out infinite;
}

@keyframes lpPulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(253,230,138,.7); }
  50%      { box-shadow: 0 0 0 8px rgba(253,230,138,0); }
}

.lp-alert-link {
  color: #fde68a;
  font-weight: 700;
  text-decoration: underline;
  text-underline-offset: 2px;
  white-space: nowrap;
  transition: color .2s;
}
.lp-alert-link:hover { color: #fff; }

/* ── Navigation ─────────────────────────────────────────────────────────── */
.lp-nav {
  position: sticky;
  top: 0;
  z-index: 100;
  background: rgba(3,4,10,.85);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  border-bottom: 1px solid var(--c-border);
  transition: box-shadow .3s, background .3s;
}
.lp-nav.scrolled {
  background: rgba(3,4,10,.92);
  box-shadow: 0 4px 40px rgba(0,0,0,.6);
}

.lp-nav-inner {
  display: flex;
  align-items: center;
  max-width: 1280px;
  margin: 0 auto;
  padding: 0 40px;
  height: 68px;
  gap: 32px;
}

.lp-logo {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}

.lp-logo-mark {
  font-size: 1.7rem;
  line-height: 1;
  background: var(--grad-text);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.lp-logo-name {
  font-size: 1.1rem;
  font-weight: 900;
  letter-spacing: .14em;
  background: var(--grad-text);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.lp-links {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 32px;
  flex: 1;
}

.lp-links li a {
  font-size: .88rem;
  font-weight: 500;
  color: var(--c-muted);
  transition: color .2s;
}
.lp-links li a:hover { color: var(--c-text-2); }

.lp-nav-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}

.lp-mobile-menu {
  display: none;
  flex-direction: column;
  justify-content: center;
  gap: 5px;
  background: none;
  border: none;
  padding: 6px;
  margin-left: auto;
}
.lp-mobile-menu span {
  display: block;
  width: 22px; height: 2px;
  background: var(--c-text-2);
  border-radius: 2px;
  transition: transform .3s, opacity .3s;
}
.lp-mobile-menu.open span:nth-child(1) { transform: translateY(7px) rotate(45deg); }
.lp-mobile-menu.open span:nth-child(2) { opacity: 0; }
.lp-mobile-menu.open span:nth-child(3) { transform: translateY(-7px) rotate(-45deg); }

.lp-mobile-nav {
  display: none;
  flex-direction: column;
  border-top: 1px solid var(--c-border);
  padding: 8px 0 16px;
  background: rgba(3,4,10,.97);
}
.lp-mobile-nav.open { display: flex; }
.lp-mobile-nav a {
  padding: 14px 32px;
  font-size: .9rem;
  color: var(--c-muted);
  border-bottom: 1px solid rgba(255,255,255,.04);
  transition: background .2s, color .2s;
}
.lp-mobile-nav a:hover {
  background: rgba(255,255,255,.04);
  color: var(--c-text-2);
}
.lp-mobile-nav button { margin: 14px 32px 0; }

/* ── Buttons ────────────────────────────────────────────────────────────── */
.lp-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 11px 22px;
  border-radius: 50px;
  font-size: .88rem;
  font-weight: 600;
  border: 1px solid transparent;
  line-height: 1.2;
  white-space: nowrap;
  transition: transform .22s var(--ease),
              box-shadow .22s,
              background .22s,
              border-color .22s;
}

.lp-primary {
  background: var(--grad-button);
  color: #fff;
  box-shadow: 0 4px 24px rgba(124,106,247,.4);
}
.lp-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 10px 36px rgba(124,106,247,.6);
}

.lp-ghost {
  background: rgba(255,255,255,.05);
  border-color: rgba(255,255,255,.12);
  color: var(--c-text-2);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
}
.lp-ghost:hover {
  background: rgba(255,255,255,.1);
  border-color: rgba(255,255,255,.22);
  transform: translateY(-2px);
}

.lp-btn-xl {
  padding: 16px 32px;
  font-size: 1rem;
  border-radius: 60px;
}
.lp-btn-full { width: 100%; }

/* ── Gradient text ──────────────────────────────────────────────────────── */
.lp-grad {
  background: var(--grad-text);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

/* ── Chips ──────────────────────────────────────────────────────────────── */
.lp-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 14px;
  border-radius: 50px;
  font-size: .76rem;
  font-weight: 600;
  background: rgba(124,106,247,.14);
  border: 1px solid rgba(124,106,247,.3);
  color: var(--c-violet);
  white-space: nowrap;
}
.lp-chip-green {
  background: rgba(61,214,140,.1);
  border-color: rgba(61,214,140,.3);
  color: var(--c-green);
}

/* ── Section layout ─────────────────────────────────────────────────────── */
.lp-section {
  padding: 100px 0;
  position: relative;
  scroll-margin-top: 80px;
}
.lp-dark-section {
  background:
    linear-gradient(180deg, rgba(255,255,255,.015) 0%, rgba(255,255,255,.025) 100%);
  border-top: 1px solid rgba(255,255,255,.04);
  border-bottom: 1px solid rgba(255,255,255,.04);
}

.lp-container {
  width: 100%;
  max-width: 1200px;
  margin-left: auto;
  margin-right: auto;
  padding: 0 48px;
}
.lp-faq-container { max-width: 780px; }

.lp-section-head {
  text-align: center;
  margin: 0 auto 64px;
  max-width: 700px;
}

/* Kill doubled top-margin where children carry their own margins */
.lp-section-head + .lp-pain-grid,
.lp-section-head + .lp-feat-tabs,
.lp-section-head + .lp-feat-grid,
.lp-section-head + .lp-steps,
.lp-section-head + .lp-roi-wrap,
.lp-section-head + .lp-table-wrap,
.lp-section-head + .lp-pricing-grid,
.lp-section-head + .lp-testimonials,
.lp-section-head + .lp-faq-list { margin-top: 0; }

.lp-eyebrow {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: rgba(124,106,247,.12);
  border: 1px solid rgba(124,106,247,.28);
  color: var(--c-violet);
  font-size: .72rem;
  font-weight: 700;
  letter-spacing: .12em;
  text-transform: uppercase;
  padding: 6px 14px;
  border-radius: 50px;
  margin-bottom: 20px;
}

.lp-h2 {
  font-size: clamp(2rem, 3.6vw, 2.9rem);
  font-weight: 800;
  letter-spacing: -.03em;
  line-height: 1.15;
  margin-bottom: 16px;
  color: var(--c-text-2);
}

.lp-h2-sub {
  font-size: 1.05rem;
  color: var(--c-muted);
  max-width: 600px;
  margin: 0 auto;
  line-height: 1.7;
}

/* ── Hero ───────────────────────────────────────────────────────────────── */
.lp-hero {
  position: relative;
  width: 100%;
  min-height: calc(100vh - 108px);
  display: flex;
  flex-direction: row;
  align-items: center;
  justify-content: center;
  gap: 72px;
  padding: 100px clamp(40px, 8vw, 120px) 90px;
  overflow: hidden;
  scroll-margin-top: 80px;
}

#lp3dCanvas {
  position: absolute;
  inset: 0;
  width: 100%; height: 100%;
  z-index: 0;
  pointer-events: none;
  opacity: .55;
}

.lp-hero::before {
  content: '';
  position: absolute;
  top: -120px; left: 50%;
  transform: translateX(-50%);
  width: min(1000px, 100%);
  height: 740px;
  background: radial-gradient(ellipse at 50% 30%,
    rgba(124,106,247,.22) 0%,
    rgba(6,182,212,.08) 45%,
    transparent 72%);
  pointer-events: none;
  z-index: 1;
}

.lp-hero-inner {
  position: relative;
  z-index: 2;
  flex: 0 1 640px;
  min-width: 0;
  text-align: left;
}

.lp-hero-eyebrow {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 28px;
}

.lp-hero-h1 {
  font-size: clamp(2.8rem, 4.5vw, 4.8rem);
  font-weight: 900;
  letter-spacing: -.04em;
  line-height: 1.05;
  margin-bottom: 24px;
  color: var(--c-text-2);
}

.lp-hero-sub {
  font-size: 1.15rem;
  color: var(--c-muted);
  line-height: 1.75;
  margin-bottom: 40px;
  max-width: 580px;
}
.lp-break { display: none; }

.lp-hero-ctas {
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
  margin-bottom: 44px;
}

.lp-hero-trust {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  font-size: .82rem;
  color: var(--c-muted);
}

.lp-trust-item { display: inline-flex; align-items: center; gap: 6px; }
.lp-trust-sep  { opacity: .35; }

.lp-dot-green {
  width: 8px; height: 8px;
  border-radius: 50%;
  background: var(--c-green);
  display: inline-block;
  flex-shrink: 0;
  box-shadow: 0 0 8px rgba(61,214,140,.6);
  animation: lpPulse 2.5s infinite;
}

/* ── Hero mockup ────────────────────────────────────────────────────────── */
.lp-hero-mockup {
  position: relative;
  z-index: 2;
  flex: 0 0 480px;
  max-width: 480px;
}

.lp-mockup-frame {
  background: rgba(10,11,22,.94);
  border: 1px solid rgba(255,255,255,.1);
  border-radius: 18px;
  overflow: hidden;
  box-shadow:
    0 32px 80px rgba(0,0,0,.75),
    0 0 0 1px rgba(124,106,247,.18),
    0 0 80px rgba(124,106,247,.18);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
}

.lp-mockup-bar {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 12px 16px;
  background: rgba(255,255,255,.04);
  border-bottom: 1px solid rgba(255,255,255,.06);
}

.lp-tb-dot {
  width: 12px; height: 12px;
  border-radius: 50%;
  display: inline-block;
  flex-shrink: 0;
}

.lp-mockup-body {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  padding: 16px;
}

.lp-mockup-stat {
  background: rgba(255,255,255,.04);
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 10px;
  padding: 14px 10px;
  text-align: center;
}
.lp-mockup-stat-red    { border-color: rgba(240,79,89,.3);  background: rgba(240,79,89,.06); }
.lp-mockup-stat-orange { border-color: rgba(240,133,58,.3); background: rgba(240,133,58,.06); }
.lp-mockup-stat-green  { border-color: rgba(61,214,140,.3); background: rgba(61,214,140,.06); }
.lp-mockup-stat-blue   { border-color: rgba(79,201,240,.3); background: rgba(79,201,240,.06); }

.lp-ms-val {
  font-size: 1.7rem;
  font-weight: 800;
  line-height: 1;
  margin-bottom: 4px;
}
.lp-mockup-stat-red    .lp-ms-val { color: #f04f59; }
.lp-mockup-stat-orange .lp-ms-val { color: #f0853a; }
.lp-mockup-stat-green  .lp-ms-val { color: #3dd68c; }
.lp-mockup-stat-blue   .lp-ms-val { color: #4fc9f0; }

.lp-ms-lbl {
  font-size: .62rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: rgba(255,255,255,.42);
  font-weight: 600;
}

.lp-mockup-scan-line {
  grid-column: 1 / -1;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  background: rgba(61,214,140,.06);
  border: 1px solid rgba(61,214,140,.22);
  border-radius: 8px;
}

.lp-scan-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  background: var(--c-green);
  flex-shrink: 0;
  box-shadow: 0 0 8px rgba(61,214,140,.7);
  animation: lpPulse 1.4s infinite;
}

.lp-scan-badge {
  margin-left: auto;
  font-size: .62rem;
  font-weight: 800;
  letter-spacing: .1em;
  color: var(--c-green);
  background: rgba(61,214,140,.14);
  border: 1px solid rgba(61,214,140,.32);
  padding: 2px 8px;
  border-radius: 4px;
}

/* ── Stats strip ────────────────────────────────────────────────────────── */
.lp-stats-strip {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0;
  padding: 56px 48px;
  border-top: 1px solid rgba(255,255,255,.06);
  border-bottom: 1px solid rgba(255,255,255,.06);
  background: rgba(255,255,255,.02);
  flex-wrap: wrap;
  max-width: 1280px;
  margin: 0 auto;
}

.lp-stat-item {
  text-align: center;
  padding: 8px 48px;
  flex: 0 1 auto;
  min-width: 180px;
}

.lp-stat-val {
  display: block;
  font-size: clamp(2.4rem, 4vw, 3.2rem);
  font-weight: 900;
  letter-spacing: -.04em;
  line-height: 1;
  background: var(--grad-text);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.lp-stat-lbl {
  font-size: .82rem;
  color: var(--c-muted);
  margin-top: 8px;
  font-weight: 500;
  letter-spacing: .01em;
}

.lp-stat-div {
  width: 1px;
  height: 56px;
  background: linear-gradient(180deg,
    transparent 0%,
    rgba(255,255,255,.12) 50%,
    transparent 100%);
  flex-shrink: 0;
}

/* ── Pain cards ─────────────────────────────────────────────────────────── */
.lp-pain-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 24px;
}

.lp-pain-card {
  background: rgba(255,255,255,.04);
  border: 1px solid rgba(255,255,255,.08);
  border-radius: 16px;
  padding: 36px 30px;
  position: relative;
  overflow: hidden;
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  transition: transform .3s var(--ease),
              border-color .3s,
              box-shadow .3s;
  transform-style: preserve-3d;
}
.lp-pain-card::before {
  content: '';
  position: absolute;
  left: 0; top: 0;
  width: 4px;
  height: 100%;
  background: var(--c-accent);
  opacity: 0;
  transition: opacity .3s;
}
.lp-pain-card::after {
  content: '';
  position: absolute;
  inset: 0;
  background: radial-gradient(ellipse at 0 0, rgba(124,106,247,.1), transparent 65%);
  opacity: 0;
  transition: opacity .3s;
  pointer-events: none;
}
.lp-pain-card:hover {
  transform: translateY(-4px);
  border-color: rgba(124,106,247,.45);
  box-shadow: 0 16px 48px rgba(124,106,247,.18);
}
.lp-pain-card:hover::before,
.lp-pain-card:hover::after { opacity: 1; }

.lp-pain-icon {
  font-size: 2.5rem;
  margin-bottom: 18px;
  display: block;
  line-height: 1;
}

.lp-pain-card h3 {
  font-size: 1.15rem;
  font-weight: 700;
  color: var(--c-text-2);
  margin-bottom: 12px;
}

.lp-pain-card p {
  font-size: .9rem;
  color: var(--c-muted);
  line-height: 1.7;
  margin-bottom: 20px;
}

.lp-pain-callout {
  font-size: .82rem;
  font-weight: 600;
  color: var(--c-violet);
  background: rgba(124,106,247,.1);
  border: 1px solid rgba(124,106,247,.24);
  border-radius: 10px;
  padding: 10px 14px;
  line-height: 1.4;
}

/* ── Feature tabs ───────────────────────────────────────────────────────── */
.lp-feat-tabs {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 48px;
}

.lp-feat-tab {
  padding: 11px 22px;
  border-radius: 50px;
  font-size: .85rem;
  font-weight: 600;
  border: 1px solid var(--c-border);
  background: rgba(255,255,255,.03);
  color: var(--c-muted);
  transition: border-color .2s, color .2s, background .2s, box-shadow .2s, transform .2s;
}
.lp-feat-tab:hover {
  border-color: rgba(124,106,247,.4);
  color: var(--c-text-2);
  transform: translateY(-1px);
}
.lp-feat-tab.active {
  background: var(--grad-button);
  border-color: transparent;
  color: #fff;
  box-shadow: 0 6px 24px rgba(124,106,247,.45);
}

/* ── Feature grid ───────────────────────────────────────────────────────── */
.lp-feat-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 20px;
}

.lp-feat-card {
  background: rgba(255,255,255,.04);
  border: 1px solid rgba(255,255,255,.08);
  border-radius: 16px;
  padding: 28px 24px;
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  transition: border-color .25s, box-shadow .25s, transform .25s;
  transform-style: preserve-3d;
  display: flex;
  flex-direction: column;
}
.lp-feat-card:hover {
  border-color: rgba(124,106,247,.4);
  box-shadow: 0 16px 48px rgba(0,0,0,.55), 0 0 0 1px rgba(124,106,247,.2);
  transform: translateY(-4px);
}

.lp-feat-icon {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.4rem;
  margin-bottom: 18px;
  flex-shrink: 0;
  border: 1px solid rgba(255,255,255,.06);
}

.lp-feat-card h4 {
  font-size: 1.05rem;
  font-weight: 700;
  color: var(--c-text-2);
  margin-bottom: 10px;
}

.lp-feat-card p {
  font-size: .88rem;
  color: var(--c-muted);
  line-height: 1.65;
  margin-bottom: 18px;
  flex: 1;
}

.lp-feat-tag {
  display: inline-block;
  font-size: .72rem;
  font-weight: 600;
  color: var(--c-cyan);
  background: rgba(6,182,212,.08);
  border: 1px solid rgba(6,182,212,.22);
  border-radius: 6px;
  padding: 5px 10px;
  margin-top: auto;
  align-self: flex-start;
  line-height: 1.4;
}

.lp-tilt { transform-style: preserve-3d; }

/* ── Steps ──────────────────────────────────────────────────────────────── */
.lp-steps {
  display: grid;
  grid-template-columns: 1fr auto 1fr auto 1fr;
  align-items: stretch;
  gap: 16px;
}

.lp-step {
  background: rgba(255,255,255,.04);
  border: 1px solid rgba(255,255,255,.08);
  border-radius: 16px;
  padding: 36px 28px;
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  transition: border-color .3s, transform .3s, box-shadow .3s;
  display: flex;
  flex-direction: column;
}
.lp-step:hover {
  border-color: rgba(124,106,247,.45);
  transform: translateY(-4px);
  box-shadow: 0 16px 40px rgba(124,106,247,.15);
}

.lp-step-num {
  width: 52px; height: 52px;
  border-radius: 50%;
  background: var(--grad-button);
  color: #fff;
  font-size: 1.05rem;
  font-weight: 800;
  letter-spacing: .04em;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 22px;
  box-shadow: 0 6px 24px rgba(124,106,247,.5);
}

.lp-step-content h3 {
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--c-text-2);
  margin-bottom: 10px;
}

.lp-step-content p {
  font-size: .9rem;
  color: var(--c-muted);
  line-height: 1.7;
  margin-bottom: 16px;
}

.lp-step-time {
  font-size: .78rem;
  font-weight: 600;
  color: var(--c-cyan);
  background: rgba(6,182,212,.08);
  border: 1px solid rgba(6,182,212,.22);
  border-radius: 50px;
  padding: 5px 12px;
  display: inline-block;
  align-self: flex-start;
  margin-top: auto;
}

.lp-step-arrow {
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.5rem;
  color: rgba(124,106,247,.5);
  text-align: center;
  font-weight: 300;
  min-width: 28px;
}

/* ── ROI Calculator ─────────────────────────────────────────────────────── */
.lp-roi-wrap {
  background: rgba(255,255,255,.04);
  border: 1px solid rgba(255,255,255,.08);
  border-radius: 20px;
  padding: 48px 44px;
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  box-shadow: var(--shadow-card);
}

.lp-roi-controls {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 36px;
  margin-bottom: 40px;
}

.lp-roi-slider-group { display: flex; flex-direction: column; }

.lp-roi-slider-label {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  font-size: .82rem;
  color: var(--c-muted);
  margin-bottom: 14px;
}
.lp-roi-slider-label strong {
  color: var(--c-text-2);
  font-weight: 700;
  font-size: .9rem;
}

.lp-slider {
  -webkit-appearance: none;
  appearance: none;
  width: 100%;
  height: 4px;
  border-radius: 4px;
  background: rgba(255,255,255,.12);
  outline: none;
  cursor: pointer;
}
.lp-slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  width: 20px; height: 20px;
  border-radius: 50%;
  background: var(--c-accent);
  box-shadow: 0 0 0 4px rgba(124,106,247,.25);
  cursor: pointer;
  transition: box-shadow .2s, transform .2s;
}
.lp-slider::-webkit-slider-thumb:hover {
  box-shadow: 0 0 0 8px rgba(124,106,247,.32);
  transform: scale(1.1);
}
.lp-slider::-moz-range-thumb {
  width: 20px; height: 20px;
  border: none; border-radius: 50%;
  background: var(--c-accent);
  cursor: pointer;
  box-shadow: 0 0 0 4px rgba(124,106,247,.25);
}

.lp-slider-ticks {
  display: flex;
  justify-content: space-between;
  font-size: .68rem;
  color: var(--c-muted);
  margin-top: 8px;
  opacity: .55;
}

.lp-roi-result {
  display: grid;
  grid-template-columns: 1fr 60px 1fr;
  margin-bottom: 28px;
  border: 1px solid var(--c-border);
  border-radius: 14px;
  overflow: hidden;
}

.lp-roi-col { padding: 28px 26px; }
.lp-roi-traditional {
  background: rgba(240,79,89,.04);
  border-right: 1px solid var(--c-border);
}
.lp-roi-xarex {
  background: rgba(61,214,140,.04);
}

.lp-roi-col-head {
  font-size: .75rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .12em;
  color: var(--c-muted);
  padding-bottom: 14px;
  margin-bottom: 16px;
  border-bottom: 1px solid var(--c-border);
}
.lp-roi-col-head-good { color: var(--c-green); }

.lp-roi-line-items {
  display: flex;
  flex-direction: column;
  gap: 10px;
  min-height: 160px;
  margin-bottom: 18px;
}

.lp-roi-line {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  font-size: .82rem;
  color: var(--c-muted);
  padding: 4px 0;
}
.lp-roi-line span:first-child { flex: 1; line-height: 1.4; }

.lp-roi-line-val {
  font-weight: 700;
  color: var(--c-text-2);
  flex-shrink: 0;
}
.lp-roi-check {
  color: var(--c-green);
  font-size: 1rem;
}

.lp-roi-total-wrap {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-top: 16px;
  border-top: 1px solid var(--c-border);
  font-size: .82rem;
  color: var(--c-muted);
  font-weight: 600;
  letter-spacing: .02em;
}

.lp-roi-total {
  font-size: 1.55rem;
  font-weight: 900;
  letter-spacing: -.02em;
  line-height: 1;
}
.lp-roi-total-bad  { color: var(--c-red); }
.lp-roi-total-good { color: var(--c-green); }

.lp-roi-vs {
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: .7rem;
  font-weight: 800;
  letter-spacing: .14em;
  color: var(--c-muted);
  background: rgba(255,255,255,.04);
  border-left: 1px solid var(--c-border);
  border-right: 1px solid var(--c-border);
}

.lp-roi-savings-banner {
  position: relative;
  text-align: center;
  padding: 36px 32px;
  background:
    linear-gradient(135deg,
      rgba(124,106,247,.14) 0%,
      rgba(6,182,212,.1) 100%);
  border: 1px solid rgba(124,106,247,.32);
  border-radius: 16px;
  overflow: hidden;
}
.lp-roi-savings-banner::before {
  content: '';
  position: absolute;
  inset: 0;
  background: radial-gradient(ellipse at 50% 50%,
    rgba(167,139,250,.12) 0%, transparent 70%);
  pointer-events: none;
}

.lp-roi-savings-label {
  font-size: .76rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .14em;
  color: var(--c-muted);
  margin-bottom: 10px;
  position: relative;
}

.lp-roi-savings-val {
  font-size: clamp(2.4rem, 5vw, 3.6rem);
  font-weight: 900;
  letter-spacing: -.04em;
  line-height: 1;
  background: var(--grad-text);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 10px;
  display: block;
  position: relative;
}

.lp-roi-savings-sub {
  font-size: .92rem;
  color: var(--c-muted);
  position: relative;
}

/* ── Comparison table ───────────────────────────────────────────────────── */
.lp-table-wrap {
  border: 1px solid var(--c-border);
  border-radius: 16px;
  overflow: hidden;
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
  background: rgba(255,255,255,.02);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
}

.lp-compare-table {
  width: 100%;
  border-collapse: collapse;
  min-width: 720px;
  font-size: .9rem;
}

.lp-compare-table th {
  padding: 22px 20px;
  font-weight: 700;
  font-size: .9rem;
  text-align: center;
  color: var(--c-text-2);
  background: rgba(255,255,255,.03);
  border-bottom: 1px solid var(--c-border);
  white-space: nowrap;
}
.lp-compare-table th:first-child {
  text-align: left;
  font-size: .75rem;
  text-transform: uppercase;
  letter-spacing: .12em;
  color: var(--c-muted);
  font-weight: 700;
}

.lp-col-xarex {
  background: rgba(124,106,247,.1) !important;
  color: var(--c-violet) !important;
  border-left: 2px solid rgba(124,106,247,.4) !important;
  border-right: 2px solid rgba(124,106,247,.4) !important;
}

.lp-col-price {
  display: block;
  font-size: .72rem;
  font-weight: 500;
  color: var(--c-muted);
  margin-top: 4px;
  letter-spacing: 0;
  text-transform: none;
}

.lp-compare-table td {
  padding: 16px 20px;
  text-align: center;
  border-bottom: 1px solid rgba(255,255,255,.04);
  color: var(--c-muted);
}
.lp-compare-table td:first-child {
  text-align: left;
  color: var(--c-text-2);
  font-weight: 500;
}
.lp-compare-table tr:last-child td { border-bottom: none; }
.lp-compare-table tbody tr:hover td { background: rgba(255,255,255,.02); }
.lp-compare-table tbody tr:hover td.lp-col-xarex { background: rgba(124,106,247,.14) !important; }
.lp-compare-table td.lp-col-xarex { color: var(--c-text-2); font-weight: 600; }

.lp-yes  { color: var(--c-green); font-weight: 700; font-size: 1.15rem; }
.lp-no   { color: var(--c-red);   font-weight: 700; font-size: 1.15rem; opacity: .65; }
.lp-part { color: #f59e0b; font-size: .82rem; font-weight: 600; }

/* ── Pricing ────────────────────────────────────────────────────────────── */
.lp-pricing-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 24px;
  align-items: stretch;
}

.lp-price-card {
  background: rgba(255,255,255,.04);
  border: 1px solid rgba(255,255,255,.08);
  border-radius: 20px;
  padding: 40px 32px;
  position: relative;
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  transition: transform .28s var(--ease),
              box-shadow .28s,
              border-color .28s;
  display: flex;
  flex-direction: column;
}
.lp-price-card:hover {
  transform: translateY(-6px);
  box-shadow: 0 24px 64px rgba(0,0,0,.55);
  border-color: rgba(124,106,247,.4);
}

.lp-price-popular {
  border-color: rgba(124,106,247,.55);
  background:
    linear-gradient(180deg,
      rgba(124,106,247,.1) 0%,
      rgba(124,106,247,.04) 100%);
  transform: scale(1.04);
  z-index: 2;
  box-shadow:
    0 24px 64px rgba(124,106,247,.25),
    0 0 0 1px rgba(124,106,247,.3);
}
.lp-price-popular::before {
  content: '';
  position: absolute;
  inset: -1px;
  border-radius: 20px;
  padding: 1px;
  background: linear-gradient(135deg,
    rgba(124,106,247,.6) 0%,
    rgba(6,182,212,.4) 100%);
  -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  -webkit-mask-composite: xor;
          mask-composite: exclude;
  pointer-events: none;
}
.lp-price-popular:hover { transform: scale(1.04) translateY(-6px); }

.lp-popular-badge {
  position: absolute;
  top: -14px;
  left: 50%;
  transform: translateX(-50%);
  background: var(--grad-button);
  color: #fff;
  font-size: .7rem;
  font-weight: 800;
  letter-spacing: .12em;
  text-transform: uppercase;
  padding: 6px 18px;
  border-radius: 50px;
  white-space: nowrap;
  box-shadow: 0 6px 20px rgba(124,106,247,.55);
  z-index: 3;
}

.lp-price-tier {
  font-size: .78rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .14em;
  color: var(--c-muted);
  margin-bottom: 16px;
}

.lp-price-val {
  font-size: 2.9rem;
  font-weight: 900;
  letter-spacing: -.04em;
  line-height: 1;
  color: var(--c-text-2);
  margin-bottom: 10px;
}
.lp-price-val span {
  font-size: 1.05rem;
  font-weight: 500;
  color: var(--c-muted);
  letter-spacing: 0;
  margin-left: 2px;
}

.lp-price-sub {
  font-size: .85rem;
  color: var(--c-muted);
  margin-bottom: 28px;
  line-height: 1.55;
}

.lp-price-features {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 32px;
  flex: 1;
  padding-top: 24px;
  border-top: 1px solid var(--c-border);
}

.lp-price-features li {
  font-size: .88rem;
  color: var(--c-muted);
  line-height: 1.5;
  position: relative;
  padding-left: 0;
}
.lp-price-features li strong { color: var(--c-text-2); }

.lp-pricing-note {
  text-align: center;
  margin: 36px auto 0;
  max-width: 540px;
  font-size: .88rem;
  color: var(--c-muted);
  background: rgba(255,255,255,.03);
  border: 1px solid var(--c-border);
  border-radius: 12px;
  padding: 16px 24px;
}
.lp-pricing-note strong { color: var(--c-text-2); }

/* ── Testimonials ───────────────────────────────────────────────────────── */
.lp-testimonials {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 22px;
  align-items: stretch;
}

.lp-testi {
  background: rgba(255,255,255,.04);
  border: 1px solid rgba(255,255,255,.08);
  border-radius: 16px;
  padding: 32px 28px;
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  transition: border-color .3s, transform .3s, box-shadow .3s;
  display: flex;
  flex-direction: column;
  transform-style: preserve-3d;
  position: relative;
}
.lp-testi::before {
  content: '"';
  position: absolute;
  top: 12px;
  right: 24px;
  font-size: 5rem;
  font-family: Georgia, serif;
  color: rgba(124,106,247,.12);
  line-height: 1;
  pointer-events: none;
}
.lp-testi:hover {
  border-color: rgba(124,106,247,.4);
  transform: translateY(-4px);
  box-shadow: 0 16px 48px rgba(0,0,0,.4);
}

.lp-testi-stars {
  color: #fbbf24;
  font-size: 1rem;
  letter-spacing: 3px;
  margin-bottom: 18px;
}

.lp-testi p {
  font-size: .95rem;
  color: var(--c-text);
  line-height: 1.75;
  margin-bottom: 26px;
  flex: 1;
}

.lp-testi-author {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-top: auto;
  padding-top: 20px;
  border-top: 1px solid var(--c-border);
}

.lp-testi-avatar {
  width: 44px; height: 44px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: .9rem;
  font-weight: 700;
  color: #fff;
  flex-shrink: 0;
  letter-spacing: .02em;
  box-shadow: 0 4px 12px rgba(0,0,0,.35);
}

.lp-testi-author strong {
  font-size: .9rem;
  color: var(--c-text-2);
  display: block;
  margin-bottom: 2px;
  font-weight: 700;
}
.lp-testi-author span {
  font-size: .76rem;
  color: var(--c-muted);
}

/* ── FAQ ────────────────────────────────────────────────────────────────── */
.lp-faq-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.lp-faq-item {
  background: rgba(255,255,255,.04);
  border: 1px solid rgba(255,255,255,.08);
  border-radius: 14px;
  overflow: hidden;
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  transition: border-color .25s, background .25s;
}
.lp-faq-item:hover {
  border-color: rgba(124,106,247,.35);
  background: rgba(255,255,255,.05);
}
.lp-faq-item.open {
  border-color: rgba(124,106,247,.45);
  background: rgba(124,106,247,.04);
}

.lp-faq-q {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 22px 26px;
  background: none;
  border: none;
  color: var(--c-text-2);
  font-size: .96rem;
  font-weight: 600;
  cursor: pointer;
  text-align: left;
  transition: color .2s;
}
.lp-faq-q:hover { color: var(--c-violet); }

.lp-faq-arrow {
  font-size: 1.6rem;
  line-height: 1;
  color: var(--c-accent);
  flex-shrink: 0;
  font-weight: 300;
  transition: transform .32s var(--ease);
  user-select: none;
}
.lp-faq-item.open .lp-faq-arrow { transform: rotate(45deg); }

.lp-faq-a {
  max-height: 0;
  overflow: hidden;
  transition: max-height .4s var(--ease), padding .3s;
  font-size: .92rem;
  color: var(--c-muted);
  line-height: 1.75;
  padding: 0 26px;
}
.lp-faq-item.open .lp-faq-a {
  max-height: 320px;
  padding: 0 26px 24px;
}

/* ── CTA section ────────────────────────────────────────────────────────── */
.lp-cta-section {
  position: relative;
  padding: 120px 40px;
  text-align: center;
  overflow: hidden;
  isolation: isolate;
}
.lp-cta-section::before {
  content: '';
  position: absolute;
  inset: 0;
  background: radial-gradient(ellipse 80% 70% at 50% 50%,
    rgba(124,106,247,.22) 0%,
    rgba(6,182,212,.08) 45%,
    transparent 72%);
  pointer-events: none;
  z-index: 1;
}
.lp-cta-section::after {
  content: '';
  position: absolute;
  inset: 0;
  background:
    linear-gradient(180deg,
      rgba(255,255,255,.02) 0%,
      transparent 30%,
      transparent 70%,
      rgba(255,255,255,.02) 100%);
  pointer-events: none;
  z-index: 1;
}

#lpCtaCanvas {
  position: absolute;
  inset: 0;
  width: 100%; height: 100%;
  z-index: 0;
  pointer-events: none;
  opacity: .5;
}

.lp-cta-inner {
  position: relative;
  z-index: 2;
  max-width: 720px;
  margin: 0 auto;
}

.lp-cta-h2 {
  font-size: clamp(2.2rem, 4.6vw, 3.4rem);
  font-weight: 900;
  letter-spacing: -.04em;
  line-height: 1.1;
  color: var(--c-text-2);
  margin: 18px 0;
}

.lp-cta-sub {
  font-size: 1.08rem;
  color: var(--c-muted);
  line-height: 1.7;
  max-width: 560px;
  margin: 0 auto 40px;
}

.lp-cta-btns {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 14px;
  flex-wrap: wrap;
}

/* ── Footer ─────────────────────────────────────────────────────────────── */
.lp-footer {
  border-top: 1px solid var(--c-border);
  padding: 72px 0 36px;
  background: rgba(0,0,0,.35);
}

.lp-footer-top {
  display: flex;
  gap: 60px;
  margin-bottom: 56px;
  flex-wrap: wrap;
}

.lp-footer-brand { flex: 0 0 240px; }
.lp-footer-brand p {
  font-size: .88rem;
  color: var(--c-muted);
  margin-top: 16px;
  line-height: 1.7;
}

.lp-footer-links {
  display: flex;
  gap: 56px;
  flex: 1;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.lp-footer-col {
  display: flex;
  flex-direction: column;
  gap: 14px;
  min-width: 130px;
}

.lp-footer-col strong {
  font-size: .76rem;
  text-transform: uppercase;
  letter-spacing: .14em;
  color: var(--c-text-2);
  font-weight: 700;
  margin-bottom: 4px;
}

.lp-footer-col a {
  font-size: .88rem;
  color: var(--c-muted);
  transition: color .2s;
}
.lp-footer-col a:hover { color: var(--c-text-2); }

.lp-footer-bottom {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  padding-top: 28px;
  border-top: 1px solid var(--c-border);
  font-size: .8rem;
  color: var(--c-muted);
  flex-wrap: wrap;
}

/* ── Responsive ─────────────────────────────────────────────────────────── */
@media (max-width: 1200px) {
  .lp-hero {
    gap: 48px;
    padding: 100px clamp(32px, 5vw, 80px) 90px;
  }
  .lp-hero-inner  { flex-basis: 560px; }
  .lp-hero-mockup { flex: 0 0 440px; max-width: 440px; }
  .lp-container   { padding: 0 40px; }
  .lp-links       { gap: 24px; }
}

@media (max-width: 1100px) {
  .lp-hero {
    flex-direction: column;
    text-align: center;
    padding: 80px 32px 64px;
    gap: 56px;
    min-height: auto;
  }
  .lp-hero-inner {
    flex: none;
    width: 100%;
    max-width: 700px;
    text-align: center;
    margin: 0 auto;
  }
  .lp-hero-eyebrow,
  .lp-hero-ctas,
  .lp-hero-trust { justify-content: center; }
  .lp-hero-sub   { margin-left: auto; margin-right: auto; }
  .lp-hero-mockup {
    max-width: 540px;
    flex: none;
    width: 100%;
    margin: 0 auto;
  }
  .lp-pain-grid    { grid-template-columns: repeat(2, 1fr); }
  .lp-price-popular { transform: scale(1); }
  .lp-price-popular:hover { transform: translateY(-6px); }
  .lp-footer-links { justify-content: flex-start; }
}

@media (max-width: 900px) {
  .lp-section { padding: 80px 0; }
  .lp-feat-grid     { grid-template-columns: repeat(2, 1fr); }
  .lp-pricing-grid  {
    grid-template-columns: 1fr;
    max-width: 460px;
    margin-left: auto;
    margin-right: auto;
  }
  .lp-testimonials {
    grid-template-columns: 1fr;
    max-width: 580px;
    margin-left: auto;
    margin-right: auto;
  }
  .lp-roi-controls   { grid-template-columns: 1fr; gap: 24px; }
  .lp-roi-result     { grid-template-columns: 1fr; }
  .lp-roi-vs         { display: none; }
  .lp-roi-traditional {
    border-right: none;
    border-bottom: 1px solid var(--c-border);
  }
  .lp-steps {
    grid-template-columns: 1fr;
    gap: 20px;
    max-width: 540px;
    margin-left: auto;
    margin-right: auto;
  }
  .lp-step-arrow      { display: none; }
  .lp-footer-top      { gap: 40px; }
  .lp-footer-brand    { flex-basis: 100%; }
  .lp-footer-links    { justify-content: flex-start; gap: 36px; }
}

@media (max-width: 768px) {
  .lp-nav-inner       { padding: 0 20px; gap: 12px; }
  .lp-links,
  .lp-nav-actions     { display: none; }
  .lp-mobile-menu     { display: flex; }
  .lp-section         { padding: 72px 0; }
  .lp-section-head    { margin-bottom: 44px; }
  .lp-container       { padding: 0 20px; }
  .lp-hero            { padding: 64px 24px 56px; gap: 40px; }
  .lp-stats-strip     { padding: 36px 20px; gap: 8px; }
  .lp-stat-item       { padding: 8px 24px; min-width: 140px; }
  .lp-stat-div        { height: 40px; }
  .lp-roi-wrap        { padding: 32px 22px; }
  .lp-cta-section     { padding: 80px 22px; }
  .lp-footer          { padding: 56px 0 24px; }
  .lp-footer-links    { gap: 28px; }
  .lp-footer-bottom   {
    justify-content: center;
    text-align: center;
    flex-direction: column;
    gap: 8px;
  }
}

@media (max-width: 600px) {
  .lp-alert-bar       { font-size: .76rem; padding: 0 16px; gap: 6px; height: auto; min-height: 44px; }
  .lp-pain-grid       { grid-template-columns: 1fr; }
  .lp-feat-grid       { grid-template-columns: 1fr; }
  .lp-stats-strip     { flex-direction: column; gap: 18px; padding: 32px 20px; }
  .lp-stat-div        { display: none; }
  .lp-stat-item       { width: 100%; }
  .lp-hero-h1         { font-size: 2.4rem; }
  .lp-h2              { font-size: 1.85rem; }
  .lp-hero-ctas,
  .lp-cta-btns        { flex-direction: column; width: 100%; }
  .lp-hero-ctas .lp-btn,
  .lp-cta-btns  .lp-btn { width: 100%; justify-content: center; }
  .lp-mockup-body     { grid-template-columns: repeat(2, 1fr); }
  .lp-roi-wrap        { padding: 26px 18px; }
  .lp-pain-card       { padding: 26px 22px; }
  .lp-feat-card       { padding: 24px 22px; }
  .lp-step            { padding: 28px 24px; }
  .lp-price-card      { padding: 30px 24px; }
  .lp-testi           { padding: 28px 22px; }
  .lp-faq-q           { padding: 18px 22px; font-size: .9rem; }
  .lp-faq-item.open .lp-faq-a { padding: 0 22px 20px; }
}
