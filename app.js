/* MuleLint in the browser: hash-routed views over the shared engine (mulelint-core.js). */
(function () {
  "use strict";
  const ML = window.MuleLint;
  const SAMPLES = window.MULELINT_SAMPLES || {};
  const view = document.getElementById("view");
  const toastEl = document.getElementById("toast");

  const SEV_ORDER = ["BLOCKER", "MAJOR", "MINOR", "INFO"];
  const SEV_LABEL = { BLOCKER: "Blocker", MAJOR: "Major", MINOR: "Minor", INFO: "Info" };
  const CAT_LABEL = {};
  for (const r of ML.RULE_META) CAT_LABEL[r.category] = r.categoryLabel;
  const LAYOUT_LABEL = { MULE_SRC: "deployable JAR with sources", SOURCE: "project ZIP", JAR: "deployable JAR without sources" };
  const MAX_BYTES = 50 * 1024 * 1024;

  // ------------------------------------------------------------------ helpers

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;
  const bytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${Math.round(n / 1024)} KB` : `${(n / 1048576).toFixed(1)} MB`);
  const when = (iso) => new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  const tick = () => new Promise((r) => setTimeout(r, 30));

  function toast(msg) {
    toastEl.textContent = msg;
    toastEl.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => (toastEl.hidden = true), 2600);
  }

  const store = {
    get(key, fallback) {
      try {
        const v = localStorage.getItem("mulelint." + key);
        return v == null ? fallback : JSON.parse(v);
      } catch (e) {
        return fallback;
      }
    },
    set(key, value) {
      try {
        localStorage.setItem("mulelint." + key, JSON.stringify(value));
        return true;
      } catch (e) {
        return false;
      }
    },
  };

  // History lives in memory first; localStorage keeps it across visits when the browser allows it.
  let history = store.get("history", []);
  let profile = store.get("profile", { disabled: [], severities: {}, params: {} });
  let ignored = store.get("ignored", {}); // artifactId -> [fingerprints]

  function saveHistory() {
    while (!store.set("history", history) && history.length > 1) history.pop();
  }
  /** Matches a finding across scans even when one upload is a JAR and the next a project ZIP (paths differ). */
  const keyOf = (f) => {
    const path = f.file.replace(/^src\/main\/(mule|resources)\//, "").replace(/^META-INF\/maven\/.*\/pom\.xml$/, "pom.xml");
    return `${f.ruleId}|${path}|${f.message}`;
  };
  const ignoredSet = (artifactId) => new Set(ignored[artifactId] || []);
  function setIgnored(artifactId, fp, on) {
    const s = ignoredSet(artifactId);
    on ? s.add(fp) : s.delete(fp);
    ignored[artifactId] = [...s];
    store.set("ignored", ignored);
  }
  const profileChanges = () => profile.disabled.length + Object.keys(profile.severities).length + Object.values(profile.params).filter(Boolean).length;

  /** Score and counts from what is still open. */
  function summary(scan) {
    const ign = ignoredSet(scan.project.artifactId);
    const open = scan.findings.filter((f) => !ign.has(keyOf(f)));
    const counts = { BLOCKER: 0, MAJOR: 0, MINOR: 0, INFO: 0 };
    for (const f of open) counts[f.severity]++;
    return { open, ign, counts, ignoredCount: scan.findings.length - open.length, score: ML.score(open), grade: ML.grade(open), categories: ML.categoryScores(open), top: ML.topFixes(open) };
  }
  const previousOf = (scan) => history.find((h) => h.id !== scan.id && h.project.artifactId === scan.project.artifactId && h.date < scan.date);

  // ------------------------------------------------------------------ scanning

  async function runScan(name, loader, size, isSample) {
    renderProgress(name, size, 0);
    try {
      await tick();
      const files = await loader();
      renderProgress(name, size, 1);
      await tick();
      const cfg = { disabled: profile.disabled, severities: profile.severities, params: profile.params };
      const r = await ML.analyzeFiles(files, name, cfg);
      renderProgress(name, size, 3);
      await tick();
      const scan = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        date: new Date().toISOString(),
        fileName: name,
        fileSize: size,
        sample: !!isSample,
        profileChanges: profileChanges(),
        project: r.project,
        findings: r.findings,
        stats: r.stats,
      };
      history.unshift(scan);
      history = history.slice(0, 15);
      saveHistory();
      location.hash = "scan-" + scan.id;
    } catch (e) {
      const msg = e instanceof ML.UserError ? e.message : "The file could not be analysed: " + (e && e.message ? e.message : e);
      location.hash = "";
      route();
      showDropError(msg);
    }
  }

  function scanFile(file) {
    if (!file) return;
    const lower = file.name.toLowerCase();
    if (!lower.endsWith(".jar") && !lower.endsWith(".zip")) return showDropError("Choose the .jar from target/ or a .zip of the project folder.");
    if (file.size > MAX_BYTES) return showDropError(`This file is ${bytes(file.size)}. The limit is 50 MB.`);
    runScan(file.name, async () => {
      const head = new Uint8Array(await file.slice(0, 4).arrayBuffer());
      if (head[0] !== 0x50 || head[1] !== 0x4b) throw new ML.UserError("This file is not a JAR or ZIP archive.");
      const zipData = await file.arrayBuffer();
      return readZip(zipData);
    }, file.size, false);
  }

  async function readZip(data) {
    if (!window.JSZip) throw new ML.UserError("The ZIP reader did not load. Check your connection and reload the page.");
    // The engine's own archive reader: same size limits and unsafe-path checks as the server.
    return ML.readArchive(data, window.JSZip);
  }

  function scanSample(key) {
    const s = SAMPLES[key];
    runScan(s.fileName, async () => new Map(Object.entries(s.files)), JSON.stringify(s.files).length, true);
  }

  // ------------------------------------------------------------------ shared pieces

  const grade = (g) => (g ? `<span class="grade grade-${esc(g)}" aria-label="Grade ${esc(g)}">${esc(g)}</span>` : "");
  const sev = (s) => `<span class="sev sev-${s}">${SEV_LABEL[s]}</span>`;

  function dial(score, g) {
    const r = 46, c = 2 * Math.PI * r;
    const color = g === "A" ? "var(--good)" : g === "B" ? "var(--grade-b)" : g === "C" ? "var(--major)" : "var(--blocker)";
    return `<svg class="dial" viewBox="0 0 112 112" role="img" aria-label="Score ${score} out of 100, grade ${g}">
      <circle cx="56" cy="56" r="${r}" fill="none" stroke="var(--line)" stroke-width="8"/>
      <circle cx="56" cy="56" r="${r}" fill="none" stroke="${color}" stroke-width="8" stroke-linecap="round" stroke-dasharray="${(c * score) / 100} ${c}" transform="rotate(-90 56 56)"/>
      <text x="56" y="60" text-anchor="middle" font-size="30" font-weight="700" fill="var(--ink)" font-family="var(--font-sans)">${score}</text>
      <text x="56" y="78" text-anchor="middle" font-size="12" fill="var(--ink-3)" font-family="var(--font-sans)">Grade ${g}</text></svg>`;
  }

  const EXAMPLE = [
    [21, '<db:config name="orders-db">'],
    [22, '  <db:my-sql-connection user="orders" password="Pa55word!"/>', "BLOCKER", "SEC-01", "Plaintext password. Encrypt it and read it as ${secure::db.password}."],
    [23, "</db:config>"],
    [24, ""],
    [25, '<flow name="get-orders-flow">'],
    [26, '  <http:listener config-ref="api-listener" path="/orders"/>'],
    [27, '  <logger level="INFO" message="#[payload]"/>', "MAJOR", "LOG-02", "Whole payload logged at INFO: customer data lands in log storage."],
    [28, '  <db:select config-ref="orders-db">'],
    [29, "    <db:sql>SELECT * FROM orders</db:sql>"],
    [30, "  </db:select>"],
    [31, "  <error-handler>"],
    [32, '    <on-error-continue type="DB:CONNECTIVITY"/>', "MAJOR", "ERR-02", "Empty on-error-continue: the caller gets a 200 and nothing is logged."],
    [33, "  </error-handler>"],
    [34, "</flow>"],
  ];
  function highlight(code) {
    let out = "", last = 0, m;
    const re = /(<\/?[\w:-]+)|([\w:-]+)(=)("[^"]*")|(\/?>)/g;
    while ((m = re.exec(code))) {
      out += esc(code.slice(last, m.index));
      if (m[1]) out += `<span class="tok-tag">${esc(m[1])}</span>`;
      else if (m[2]) out += `<span class="tok-attr">${esc(m[2])}</span>=<span class="tok-val">${esc(m[4])}</span>`;
      else out += `<span class="tok-tag">${esc(m[5])}</span>`;
      last = re.lastIndex;
    }
    return out + esc(code.slice(last));
  }

  function setNav(name) {
    for (const a of document.querySelectorAll("[data-nav]")) {
      if (a.dataset.nav === name) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
  }

  // ------------------------------------------------------------------ views

  function renderHome() {
    setNav("home");
    const cats = {};
    for (const r of ML.RULE_META) cats[r.category] = (cats[r.category] || 0) + 1;
    const examples = {
      SECURITY: "plaintext passwords, insecure TLS", CONFIGURATION: "hardcoded hosts, keys missing in prod", ERROR_HANDLING: "swallowed errors, unreachable handlers",
      LOGGING: "payload at INFO, no correlation ID", STRUCTURE: "oversized and unused flows", NAMING: "flow and variable conventions",
      DATAWEAVE: "match without else, orphan .dwl", PERFORMANCE: "no timeout, no reconnection", DEPENDENCIES: "old runtime, SNAPSHOTs, no MUnit",
    };
    const recent = history.slice(0, 5);
    view.innerHTML = `
      <div class="wrap">
        <section class="hero">
          <div>
            <h1>Code review for Mule apps, before the code review.</h1>
            <p class="lede">Drop a Mule 4 JAR or a project ZIP. You get every hardcoded secret, swallowed error and missing timeout, with the file, the line and the fix.</p>
            <ul class="facts">
              <li>The archive is read in this browser and never uploaded.</li>
              <li>${ML.RULE_META.length} rules in ${Object.keys(cats).length} categories, scored 0 to 100.</li>
              <li>Same engine as the MuleLint CLI, so the score matches your CI gate.</li>
            </ul>
          </div>
          <div class="drop" id="drop">
            <div class="stack" style="gap:8px">
              <h2 style="font-size:1.1875rem">Check a Mule app</h2>
              <p>Drop the deployable JAR from <code>target/</code>, or a .zip of the project folder to include MUnit checks. Up to 50 MB.</p>
            </div>
            <div class="row">
              <button class="btn" id="pick">Choose file</button>
              <span class="small muted">${profileChanges() ? `Using your rule profile (${plural(profileChanges(), "change")}). <a href="#rule-profile">Edit</a>` : `Default rules. <a href="#rule-profile">Customise</a>`}</span>
            </div>
            <input type="file" id="file" accept=".jar,.zip" hidden>
            <div id="drop-error"></div>
            <div class="samples">
              <span class="small muted">No JAR to hand? Try a sample.</span>
              ${Object.entries(SAMPLES).map(([k, s]) => `<div class="sample"><span><code>${esc(s.label)}</code> <span class="small muted">${esc(s.note)}</span></span><button class="btn btn-quiet btn-small" data-sample="${esc(k)}">Scan sample</button></div>`).join("")}
            </div>
          </div>
        </section>
        ${recent.length ? `<section style="padding-bottom:40px">
          <div class="spread" style="margin-bottom:10px"><h2 style="font-size:1.1875rem">Recent scans</h2><a href="#history" class="small">All history</a></div>
          ${historyTable(recent)}</section>` : ""}
      </div>
      <section class="section"><div class="wrap split">
        <div><h2>What a finding looks like</h2><p>Each one points at the line, says what goes wrong in production, and links to the rule with the fix.</p></div>
        <figure class="review" style="margin:0" aria-label="Example findings on a Mule flow">
          <div class="review-head"><span><strong>orders-papi</strong> src/main/mule/orders.xml</span><span>3 findings on this screen</span></div>
          <div class="code">${EXAMPLE.map(([n, code, s, rule, note]) => `<div class="code-line${s ? " flag-" + s : ""}"><span class="ln">${n}</span><span>${highlight(code)}</span></div>${s ? `<div class="code-note">${sev(s).replace("</span>", ` ${rule}</span>`)} ${esc(note)}</div>` : ""}`).join("")}</div>
        </figure>
      </div></section>
      <section class="section"><div class="wrap split">
        <div><h2>What it checks</h2><p>The comments senior reviewers leave on every Mule pull request, turned into rules. Switch rules off or set your own conventions in the rule profile.</p></div>
        <ul class="catlist">${Object.keys(cats).map((c) => `<li><span><a href="#rules-${c.toLowerCase()}">${esc(CAT_LABEL[c])}</a><span class="small muted" style="display:block">${esc(examples[c] || "")}</span></span><span class="small muted">${cats[c]} rules</span></li>`).join("")}</ul>
      </div></section>
      <section class="section"><div class="wrap split">
        <div><h2>Gate your builds</h2><p>The same rules run from the command line, so a pull request can fail on a Major finding or a low score.</p></div>
        <div class="stack" style="min-width:0">
          <pre class="block"><code>java -jar mulelint-analyzer.jar target/orders-papi-1.0.0-mule-application.jar --fail-on=MAJOR --min-score=80</code></pre>
          <p class="small muted">Exit code 0 passes, 1 fails the gate, 2 means the archive could not be read. The CLI ships in the MuleLint repository.</p>
        </div>
      </div></section>`;
    const drop = document.getElementById("drop");
    const input = document.getElementById("file");
    document.getElementById("pick").onclick = () => input.click();
    input.onchange = () => { scanFile(input.files[0]); input.value = ""; };
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); scanFile(e.dataTransfer.files[0]); });
    for (const b of view.querySelectorAll("[data-sample]")) b.onclick = () => scanSample(b.dataset.sample);
  }

  function showDropError(msg) {
    const el = document.getElementById("drop-error");
    if (el) el.innerHTML = `<p class="notice notice-error" role="alert">${esc(msg)}</p>`;
    else toast(msg);
  }

  function renderProgress(name, size, step) {
    const stages = ["Reading the archive", "Parsing flows, properties and pom.xml", "Running the rules", "Scoring"];
    view.innerHTML = `<div class="wrap narrow"><div class="page-head"><h1>Checking ${esc(name)}</h1><p>${bytes(size)}, read in this browser.</p></div>
      <div class="sheet progress"><ol>${stages.map((s, i) => `<li class="${i < step ? "done" : i === step ? "now" : ""}">${s}</li>`).join("")}</ol></div></div>`;
  }

  function historyTable(list) {
    return `<div class="sheet table-scroll"><table class="ledger"><thead><tr><th>Application</th><th class="num">Score</th><th>Grade</th><th class="num">Blocker</th><th class="num">Major</th><th class="num">Minor</th><th>When</th></tr></thead><tbody>
      ${list.map((h) => {
        const s = summary(h);
        return `<tr><td><a href="#scan-${esc(h.id)}">${esc(h.project.name)}</a>${h.sample ? ' <span class="small muted">sample</span>' : ""}<div class="small muted">${esc(h.fileName)}</div></td>
          <td class="num">${s.score}</td><td>${grade(s.grade)}</td><td class="num">${s.counts.BLOCKER}</td><td class="num">${s.counts.MAJOR}</td><td class="num">${s.counts.MINOR}</td><td class="small muted" style="white-space:nowrap">${when(h.date)}</td></tr>`;
      }).join("")}</tbody></table></div>`;
  }

  function renderHistory() {
    setNav("history");
    view.innerHTML = `<div class="wrap" style="padding-bottom:64px"><div class="page-head spread"><div><h1>History</h1><p>Your last ${history.length ? plural(history.length, "scan") : "scans"}, kept in this browser only.</p></div>
      ${history.length ? `<div class="row" id="clear-zone"><button class="btn btn-quiet btn-small" id="clear">Clear history</button></div>` : ""}</div>
      ${history.length ? historyTable(history) : `<div class="sheet empty"><h2 style="font-size:1.1875rem">No scans yet</h2><p style="margin-top:6px">Check a JAR or one of the samples and it appears here. <a href="#">Check an app</a></p></div>`}</div>`;
    const clear = document.getElementById("clear");
    if (clear) clear.onclick = () => {
      document.getElementById("clear-zone").innerHTML = `<span class="small">Delete all ${history.length} reports from this browser?</span><button class="btn btn-small" id="yes">Delete</button><button class="btn btn-quiet btn-small" id="no">Keep</button>`;
      document.getElementById("yes").onclick = () => { history = []; saveHistory(); toast("History cleared."); renderHistory(); };
      document.getElementById("no").onclick = renderHistory;
    };
  }

  // report state survives re-renders while the same scan is open
  const filters = { sev: "ALL", cat: "ALL", q: "", showIgnored: false, open: new Set(), scanId: null };

  function renderReport(id) {
    setNav("report");
    const scan = id ? history.find((h) => h.id === id) : history[0];
    if (!scan) {
      view.innerHTML = `<div class="wrap narrow"><div class="page-head"><h1>No report yet</h1><p>${id ? "This report is no longer in this browser's history." : "Check a Mule app and its report opens here."}</p></div>
        <div class="row"><a class="btn" href="#">Check an app</a>${Object.keys(SAMPLES).length ? `<button class="btn btn-quiet" id="try">Scan the orders-papi sample</button>` : ""}</div></div>`;
      const t = document.getElementById("try");
      if (t) t.onclick = () => scanSample(Object.keys(SAMPLES)[0]);
      return;
    }
    if (filters.scanId !== scan.id) Object.assign(filters, { sev: "ALL", cat: "ALL", q: "", showIgnored: false, open: new Set(), scanId: scan.id });
    const s = summary(scan);
    const prev = previousOf(scan);
    let delta = "";
    let prevFps = null;
    if (prev) {
      const ps = summary(prev);
      prevFps = new Set(ps.open.map(keyOf));
      const nowFps = new Set(s.open.map(keyOf));
      const fixed = ps.open.filter((f) => !nowFps.has(keyOf(f))).length;
      const added = s.open.filter((f) => !prevFps.has(keyOf(f))).length;
      const d = s.score - ps.score;
      delta = `<div class="delta"><h2 style="font-size:1rem">Since the scan of ${when(prev.date)}</h2>
        <span style="font-weight:700;color:${d > 0 ? "var(--good)" : d < 0 ? "var(--blocker)" : "var(--ink-3)"}">${d > 0 ? "+" + d + " points" : d < 0 ? d + " points" : "Same score"}</span>
        <span class="muted">${fixed} fixed, ${added} new</span></div>`;
    }
    const p = scan.project;
    const meta = [p.version ? "version " + p.version : null, p.runtimeVersion ? "Mule " + p.runtimeVersion : null, LAYOUT_LABEL[p.layout], when(scan.date)].filter(Boolean).join(". ");
    const st = scan.stats;
    view.innerHTML = `<div class="wrap">
      <div class="page-head spread">
        <div style="min-width:0"><p class="small muted">${esc(scan.fileName)}${scan.sample ? " (sample)" : ""}</p><h1>${esc(p.name)}</h1><p class="small">${esc(meta)}.</p></div>
        <div class="row"><button class="btn btn-small" id="copy">Copy report as Markdown</button><a class="btn btn-quiet btn-small" href="#">Check another file</a></div>
      </div>
      <div class="report">
        <aside>
          <div class="scoreblock">${dial(s.score, s.grade)}
            <div class="counts">${SEV_ORDER.map((k) => `<span class="sev sev-${k}"><b>${s.counts[k]}</b> ${SEV_LABEL[k].toLowerCase()}</span>`).join("")}
              ${s.ignoredCount ? `<span class="small muted" style="margin-top:4px">${plural(s.ignoredCount, "finding")} marked not an issue</span>` : ""}</div>
          </div>
          ${delta}
          <div class="cats">${ML.CATEGORIES.map((c) => { const v = s.categories[c]; return `<div class="cat"><span>${esc(CAT_LABEL[c])}</span><b>${v}</b><div class="bar" aria-hidden="true"><span class="${v < 70 ? "bad" : v < 90 ? "low" : ""}" style="width:${v}%"></span></div></div>`; }).join("")}</div>
          ${s.top.length ? `<div><h2 style="font-size:1rem;margin-bottom:10px">Fix these first</h2><ol class="topfix">${s.top.map((t) => `<li><span class="gain">+${t.pointsGained}</span><span><button class="linkbtn" data-q="${esc(t.ruleId)}">${esc(t.title)}</button> <span class="muted">(${plural(t.findings, "finding")})</span></span></li>`).join("")}</ol></div>` : ""}
          <p class="small muted">Checked ${plural(st.muleConfigFiles, "config file")}, ${plural(st.flows, "flow")}, ${plural(st.subFlows, "sub-flow")}, ${plural(st.propertyFiles, "property file")} and ${plural(st.dataWeaveFiles, ".dwl file")} in ${(st.durationMillis / 1000).toFixed(2)} s${scan.profileChanges ? `, with your rule profile (${plural(scan.profileChanges, "change")})` : ""}.</p>
        </aside>
        <section aria-label="Findings" style="min-width:0">
          <div class="filters" role="group" aria-label="Filter by severity">
            <button class="chip" data-sev="ALL" aria-pressed="${filters.sev === "ALL"}">All ${s.open.length}</button>
            ${SEV_ORDER.map((k) => `<button class="chip" data-sev="${k}" aria-pressed="${filters.sev === k}" ${s.counts[k] ? "" : "disabled"}>${SEV_LABEL[k]} ${s.counts[k]}</button>`).join("")}
          </div>
          <div class="filters">
            <select class="select" id="f-cat" aria-label="Category"><option value="ALL">All categories</option>${ML.CATEGORIES.map((c) => `<option value="${c}" ${filters.cat === c ? "selected" : ""}>${esc(CAT_LABEL[c])}</option>`).join("")}</select>
            <input class="input" id="f-q" type="search" style="max-width:260px" placeholder="Search file, rule or message" aria-label="Search findings" value="${esc(filters.q)}">
            <label class="row small" style="gap:8px"><input type="checkbox" class="toggle" id="f-ign" ${filters.showIgnored ? "checked" : ""}> Show findings marked not an issue</label>
          </div>
          <div id="list" style="border-top:1px solid var(--line)"></div>
        </section>
      </div></div>`;

    const list = document.getElementById("list");
    const drawList = () => {
      const q = filters.q.trim().toLowerCase();
      const items = scan.findings.filter((f) => {
        const isIgn = s.ign.has(keyOf(f));
        return (filters.showIgnored || !isIgn) && (filters.sev === "ALL" || f.severity === filters.sev) && (filters.cat === "ALL" || f.category === filters.cat) &&
          (!q || `${f.message} ${f.file} ${f.ruleId} ${f.title}`.toLowerCase().includes(q));
      });
      if (!scan.findings.length) {
        list.innerHTML = `<div class="empty"><h2 style="font-size:1.1875rem">No findings</h2><p style="margin-top:6px">Every enabled rule passed.</p></div>`;
        return;
      }
      if (!items.length) {
        list.innerHTML = `<p class="muted" style="padding:20px 4px">Nothing matches these filters. <button class="linkbtn" id="clr">Clear filters</button></p>`;
        document.getElementById("clr").onclick = () => { Object.assign(filters, { sev: "ALL", cat: "ALL", q: "" }); renderReport(scan.id); };
        return;
      }
      list.innerHTML = items.map((f, i) => {
        const isIgn = s.ign.has(keyOf(f));
        const isNew = prevFps && !isIgn && !prevFps.has(keyOf(f));
        const open = filters.open.has(f.fingerprint + i);
        return `<div class="finding${isIgn ? " ignored" : ""}">
          <button aria-expanded="${open}" data-open="${esc(f.fingerprint + i)}">${sev(f.severity)}<span class="rid">${esc(f.ruleId)}</span>
            <span><span class="msg">${esc(f.message)}</span>${isNew ? '<span class="new">new</span>' : ""}<span class="loc">${esc(f.file)}${f.line > 0 ? ":" + f.line : ""}</span></span></button>
          ${open ? `<div class="finding-body">
            ${f.snippet ? `<pre><code>${f.line > 0 ? f.line + "  " : ""}${esc(f.snippet)}</code></pre>` : ""}
            <p class="why"><strong>${esc(f.title)}.</strong> ${esc(f.fixHint)}</p>
            <div class="row"><a class="small" href="#rule-${esc(f.ruleId)}">Why this rule exists</a>
              <button class="btn btn-quiet btn-small" data-ign="${esc(keyOf(f))}">${isIgn ? "Reopen finding" : "Mark as not an issue"}</button>
              <span class="small muted">${esc(CAT_LABEL[f.category])}</span></div></div>` : ""}
        </div>`;
      }).join("");
    };
    drawList();

    list.addEventListener("click", (e) => {
      const o = e.target.closest("[data-open]");
      if (o) {
        const k = o.dataset.open;
        filters.open.has(k) ? filters.open.delete(k) : filters.open.add(k);
        drawList();
        return;
      }
      const g = e.target.closest("[data-ign]");
      if (g) {
        const fp = g.dataset.ign;
        const on = !ignoredSet(p.artifactId).has(fp);
        setIgnored(p.artifactId, fp, on);
        toast(on ? "Marked as not an issue. It stays ignored on later scans of this app." : "Finding reopened.");
        const y = window.scrollY;
        renderReport(scan.id);
        window.scrollTo(0, y);
      }
    });
    for (const b of view.querySelectorAll("[data-sev]")) b.onclick = () => { filters.sev = b.dataset.sev; renderReport(scan.id); };
    for (const b of view.querySelectorAll("[data-q]")) b.onclick = () => { Object.assign(filters, { q: b.dataset.q, sev: "ALL", cat: "ALL" }); renderReport(scan.id); document.getElementById("list").scrollIntoView({ block: "start" }); };
    document.getElementById("f-cat").onchange = (e) => { filters.cat = e.target.value; drawList(); };
    document.getElementById("f-q").oninput = (e) => { filters.q = e.target.value; drawList(); };
    document.getElementById("f-ign").onchange = (e) => { filters.showIgnored = e.target.checked; drawList(); };
    document.getElementById("copy").onclick = () => copyText(markdown(scan, s), "Report copied as Markdown.");
  }

  function markdown(scan, s) {
    const p = scan.project;
    const lines = [`# MuleLint report: ${p.name}${p.version ? " " + p.version : ""}`, "",
      `Score **${s.score}/100**, grade **${s.grade}**. ${s.counts.BLOCKER} blocker, ${s.counts.MAJOR} major, ${s.counts.MINOR} minor, ${s.counts.INFO} info.`,
      `File: ${scan.fileName}${p.runtimeVersion ? `. Mule runtime ${p.runtimeVersion}` : ""}. Scanned ${new Date(scan.date).toUTCString()}.`, "",
      "| Category | Score |", "| --- | --- |", ...ML.CATEGORIES.map((c) => `| ${CAT_LABEL[c]} | ${s.categories[c]} |`), "",
      "## Findings", "", "| Severity | Rule | Location | Finding |", "| --- | --- | --- | --- |",
      ...s.open.map((f) => `| ${SEV_LABEL[f.severity]} | ${f.ruleId} | \`${f.file}${f.line > 0 ? ":" + f.line : ""}\` | ${f.message.replace(/\|/g, "\\|")} |`)];
    if (s.ignoredCount) lines.push("", `${plural(s.ignoredCount, "finding")} marked not an issue and left out.`);
    return lines.join("\n");
  }

  function copyText(text, ok) {
    const fallback = () => {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      let done = false;
      try { done = document.execCommand("copy"); } catch (e) { done = false; }
      ta.remove();
      toast(done ? ok : "Copy is blocked here. Select the report text manually.");
    };
    try {
      navigator.clipboard.writeText(text).then(() => toast(ok), fallback);
    } catch (e) {
      fallback();
    }
  }

  function renderRules(focusCat) {
    setNav("rules");
    const byCat = {};
    for (const r of ML.RULE_META) (byCat[r.category] = byCat[r.category] || []).push(r);
    view.innerHTML = `<div class="wrap narrow" style="padding-bottom:64px"><div class="page-head"><h1>Rule catalog</h1>
      <p>${ML.RULE_META.length} rules MuleLint runs on every scan. Each explains the problem it prevents and the change that fixes it.</p></div>
      ${Object.keys(byCat).map((c) => `<section id="cat-${c.toLowerCase()}"><h2 class="cat-head">${esc(CAT_LABEL[c])}</h2>
        ${byCat[c].map((r) => `<div class="rule-row"><span class="rid">${esc(r.id)}</span><span><a href="#rule-${esc(r.id)}">${esc(r.title)}</a></span>${sev(r.severity)}</div>`).join("")}</section>`).join("")}</div>`;
    if (focusCat) {
      const el = document.getElementById("cat-" + focusCat);
      if (el) el.scrollIntoView({ block: "start" });
    } else window.scrollTo(0, 0);
  }

  function renderRule(id) {
    setNav("rules");
    const i = ML.RULE_META.findIndex((r) => r.id.toLowerCase() === id.toLowerCase());
    if (i < 0) return renderRules();
    const r = ML.RULE_META[i], prev = ML.RULE_META[i - 1], next = ML.RULE_META[i + 1];
    const off = profile.disabled.includes(r.id), sv = profile.severities[r.id];
    view.innerHTML = `<div class="wrap narrow" style="padding-bottom:64px"><div class="page-head">
      <p class="small"><a href="#rules-${r.category.toLowerCase()}">${esc(r.categoryLabel)}</a></p><h1>${esc(r.title)}</h1>
      <p class="row" style="margin-top:10px"><code>${esc(r.id)}</code>${sev(r.severity)}<span class="small muted">by default${off ? ", switched off in your rule profile" : sv ? `, ${SEV_LABEL[sv]} in your rule profile` : ""}</span></p></div>
      <article class="prose"><h2>Why it matters</h2><p>${esc(r.description)}</p><h2>How to fix it</h2><p>${esc(r.fixHint)}</p>
      <h2>Changing this rule</h2><p>Switch it off or change its severity in your <a href="#rule-profile">rule profile</a>. A single finding that is a deliberate exception can be marked as not an issue on the report, and it stays ignored on later scans of that app.</p></article>
      <nav class="spread" style="margin-top:44px;padding-top:16px;border-top:1px solid var(--line)" aria-label="Other rules">
        ${prev ? `<a href="#rule-${esc(prev.id)}">${esc(prev.id)} ${esc(prev.title)}</a>` : "<span></span>"}${next ? `<a href="#rule-${esc(next.id)}">${esc(next.id)} ${esc(next.title)}</a>` : "<span></span>"}</nav></div>`;
    window.scrollTo(0, 0);
  }

  const PARAMS = [
    ["flowMaxProcessors", "Max processors per flow", "STR-01 flags flows above this."],
    ["flowNameRegex", "Flow name pattern", "NAM-01, a regular expression."],
    ["variableNameRegex", "Variable name pattern", "NAM-02, a regular expression."],
    ["minRuntimeVersion", "Minimum Mule runtime", "DEP-01 flags anything older."],
    ["inlineDataWeaveMaxLines", "Max lines of inline DataWeave", "DW-01 flags longer scripts."],
  ];

  function renderProfile() {
    setNav("rule-profile");
    const draft = JSON.parse(JSON.stringify(profile));
    const byCat = {};
    for (const r of ML.RULE_META) (byCat[r.category] = byCat[r.category] || []).push(r);
    view.innerHTML = `<div class="wrap" style="max-width:980px"><div class="page-head"><h1>Rule profile</h1>
      <p>Switch rules off, change severities and set your team's conventions. Applies to the next scan and is saved in this browser.</p></div>
      <div class="stack" style="gap:28px">
        <div><h2 style="font-size:1.1875rem;margin-bottom:12px">Conventions</h2>
          <div class="sheet params">${PARAMS.map(([k, label, hint]) => `<div class="field"><label for="p-${k}">${label}</label>
            <input class="input" id="p-${k}" data-param="${k}" placeholder="${esc(ML.DEFAULT_PARAMS[k])}" value="${esc(draft.params[k] || "")}" ${k.endsWith("Regex") ? 'style="font-family:var(--font-mono)" spellcheck="false"' : ""}>
            <span class="hint">${hint} Default: <code>${esc(ML.DEFAULT_PARAMS[k])}</code></span></div>`).join("")}</div></div>
        <div><h2 style="font-size:1.1875rem;margin-bottom:4px">Rules</h2>
          ${Object.keys(byCat).map((c) => `<h3 style="font-size:1rem;margin:16px 0 8px">${esc(CAT_LABEL[c])}</h3><div class="sheet table-scroll"><table class="ledger"><tbody>
            ${byCat[c].map((r) => `<tr data-row="${r.id}"><td style="width:52px"><input type="checkbox" class="toggle" id="en-${r.id}" data-enable="${r.id}" aria-label="Run ${r.id}" ${draft.disabled.includes(r.id) ? "" : "checked"}></td>
              <td style="width:84px"><code>${esc(r.id)}</code></td><td style="min-width:200px"><a href="#rule-${esc(r.id)}" style="font-weight:400">${esc(r.title)}</a></td>
              <td style="width:160px"><select class="select" id="sv-${r.id}" data-sev="${r.id}" aria-label="Severity for ${r.id}">${SEV_ORDER.map((k) => `<option value="${k}" ${(draft.severities[r.id] || r.severity) === k ? "selected" : ""}>${SEV_LABEL[k]}${k === r.severity ? " (default)" : ""}</option>`).join("")}</select></td></tr>`).join("")}
          </tbody></table></div>`).join("")}</div>
      </div>
      <div class="savebar row" style="margin-top:20px"><button class="btn" id="save">Save profile</button><button class="btn btn-quiet" id="reset">Reset to defaults</button><span class="small muted" id="changes"></span></div></div>`;

    const countEl = document.getElementById("changes");
    const refresh = () => {
      for (const r of ML.RULE_META) {
        const row = view.querySelector(`[data-row="${r.id}"]`);
        const on = !draft.disabled.includes(r.id);
        row.style.opacity = on ? 1 : 0.55;
        view.querySelector(`[data-sev="${r.id}"]`).disabled = !on;
      }
      const n = draft.disabled.length + Object.keys(draft.severities).length + Object.values(draft.params).filter(Boolean).length;
      countEl.textContent = `${plural(n, "change")} from the MuleLint defaults`;
    };
    refresh();
    view.addEventListener("change", (e) => {
      const t = e.target;
      if (t.dataset.enable) {
        const id = t.dataset.enable;
        draft.disabled = draft.disabled.filter((x) => x !== id);
        if (!t.checked) draft.disabled.push(id);
      } else if (t.dataset.sev) {
        const r = ML.RULE_META.find((x) => x.id === t.dataset.sev);
        if (t.value === r.severity) delete draft.severities[r.id];
        else draft.severities[r.id] = t.value;
      }
      refresh();
    });
    view.addEventListener("input", (e) => {
      const t = e.target;
      if (t.dataset.param) {
        const v = t.value.trim();
        if (v) draft.params[t.dataset.param] = v;
        else delete draft.params[t.dataset.param];
        refresh();
      }
    });
    document.getElementById("save").onclick = () => {
      for (const [k] of PARAMS) {
        const v = draft.params[k];
        if (!v) continue;
        if (k.endsWith("Regex")) { try { new RegExp(v); } catch (e) { return toast(`The ${k === "flowNameRegex" ? "flow" : "variable"} name pattern is not a valid regular expression.`); } }
        if ((k === "flowMaxProcessors" || k === "inlineDataWeaveMaxLines") && !/^\d{1,4}$/.test(v)) return toast("Limits must be whole numbers.");
        if (k === "minRuntimeVersion" && !/^\d+(\.\d+){0,2}$/.test(v)) return toast("Minimum Mule runtime must look like 4.6.0.");
      }
      profile = draft;
      toast(store.set("profile", profile) ? "Profile saved. It applies to your next scan." : "Profile applied for this visit. This browser blocks saving it.");
    };
    document.getElementById("reset").onclick = () => {
      profile = { disabled: [], severities: {}, params: {} };
      store.set("profile", profile);
      toast("Rule profile reset to the MuleLint defaults.");
      renderProfile();
    };
  }

  // ------------------------------------------------------------------ routing

  function route() {
    const h = decodeURIComponent(location.hash.replace(/^#/, ""));
    if (h === "report") renderReport(null);
    else if (h.startsWith("scan-")) renderReport(h.slice(5));
    else if (h === "history") renderHistory();
    else if (h === "rule-profile") renderProfile();
    else if (h === "rules") renderRules();
    else if (h.startsWith("rules-")) renderRules(h.slice(6));
    else if (h.startsWith("rule-")) renderRule(h.slice(5));
    else renderHome();
    if (!h.startsWith("rules-")) window.scrollTo(0, 0);
  }
  window.addEventListener("hashchange", route);
  route();
})();
