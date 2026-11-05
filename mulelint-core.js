/* MuleLint engine, JavaScript port of the Java analyzer (same rules, messages, scoring and fingerprints).
 * Runs in the browser and in Node. Input: a Map of entry name -> text, or a ZIP read with JSZip. */
(function (root) {
  "use strict";

  const RULE_META = [{"id": "SEC-01","category": "SECURITY","categoryLabel": "Security","severity": "BLOCKER","title": "No plaintext secrets in code or property files","description": "Passwords, tokens, client secrets and API keys written in plain text end up in Git, in the JAR and in every log of the build. Anyone with read access to the repo or the artifact gets production credentials.","fixHint": "Move the value to a secure properties file, encrypt it with the Secure Properties Tool (value becomes ![...]) and reference it as ${secure::key}."},{"id": "SEC-02","category": "SECURITY","categoryLabel": "Security","severity": "BLOCKER","title": "Sensitive values come from Secure Properties","description": "A credential attribute that reads ${db.password} instead of ${secure::db.password} means the value sits unencrypted in a normal property file, or that the encrypted value will never be decrypted.","fixHint": "Store the value encrypted in a secure properties file and change the reference to ${secure::<key>}."},{"id": "SEC-03","category": "SECURITY","categoryLabel": "Security","severity": "MAJOR","title": "TLS is not weakened","description": "insecure=\"true\" on a trust store accepts any certificate, so a man-in-the-middle can read and change traffic. TLSv1 and TLSv1.1 are deprecated and broken.","fixHint": "Remove insecure=\"true\" and add the server's CA to a trust store; allow only TLSv1.2 and TLSv1.3."},{"id": "SEC-04","category": "SECURITY","categoryLabel": "Security","severity": "BLOCKER","title": "secure:: references have a Secure Properties config","description": "${secure::...} placeholders only resolve when a <secure-properties:config> is declared. Without it the app fails at deploy time.","fixHint": "Add <secure-properties:config> pointing at your encrypted file, with key=\"${secure.key}\" supplied as a runtime property."},{"id": "SEC-05","category": "SECURITY","categoryLabel": "Security","severity": "MINOR","title": "HTTP APIs are paired with API Manager (autodiscovery)","description": "Without <api-gateway:autodiscovery> the API cannot receive policies (client ID enforcement, rate limiting, JWT validation) from API Manager.","fixHint": "Add <api-gateway:autodiscovery apiId=\"${api.id}\" flowRef=\"<main-flow>\"/> and pass api.id per environment."},{"id": "CFG-01","category": "CONFIGURATION","categoryLabel": "Configuration","severity": "MAJOR","title": "No hardcoded hosts, ports, paths or URLs in connector configs","description": "Literal connection values tie the app to one environment. Promoting to QA or Prod then needs a code change and a rebuild instead of a property change.","fixHint": "Replace the literal with a placeholder such as ${http.port} or ${db.host} and define it in each environment's property file."},{"id": "CFG-02","category": "CONFIGURATION","categoryLabel": "Configuration","severity": "MAJOR","title": "Environment property files exist and define the same keys","description": "When dev.yaml has a key that prod.yaml lacks, the app deploys to dev and then fails on start in prod with an unresolved placeholder.","fixHint": "Keep one file per environment (e.g. config-dev.yaml, config-prod.yaml), load it with file=\"config-${env}.yaml\", and add every key to every file."},{"id": "CFG-03","category": "CONFIGURATION","categoryLabel": "Configuration","severity": "MAJOR","title": "Every ${property} used is defined","description": "A placeholder with no matching key makes the app fail at deploy time, usually only in the environment where nobody tested.","fixHint": "Add the key to every environment's property file, or fix the typo in the placeholder. Values passed only at runtime should be listed in the README."},{"id": "CFG-04","category": "CONFIGURATION","categoryLabel": "Configuration","severity": "BLOCKER","title": "Declared property files exist in the package","description": "<configuration-properties file=\"...\"> pointing at a file that is not packaged makes the app fail on start.","fixHint": "Add the file under src/main/resources, or fix the file name / ${env} pattern in the declaration."},{"id": "ERR-01","category": "ERROR_HANDLING","categoryLabel": "Error handling","severity": "MAJOR","title": "A global default error handler is configured","description": "Flows without their own error handler fall back to Mule's default, which logs a stack trace and returns a generic 500 with internal details. A global handler gives one consistent error response and log format.","fixHint": "Create a top-level <error-handler name=\"global-error-handler\"> and set <configuration defaultErrorHandler-ref=\"global-error-handler\"/> in global.xml."},{"id": "ERR-02","category": "ERROR_HANDLING","categoryLabel": "Error handling","severity": "MAJOR","title": "No on-error-continue that silently swallows errors","description": "An empty <on-error-continue> turns every failure into a success: callers get a 200 with whatever payload was left, and nothing is logged.","fixHint": "At minimum log the error (with correlation ID) and set a meaningful payload, or use on-error-propagate if the caller should know about the failure."},{"id": "ERR-03","category": "ERROR_HANDLING","categoryLabel": "Error handling","severity": "MINOR","title": "APIkit errors map to proper HTTP status codes","description": "Unmapped APIKIT errors come back to the client as 500 instead of 400/404/405/406/415/501, which breaks client error handling and hides bad requests in server-error dashboards.","fixHint": "Keep the APIkit-generated error handler in the main flow (or the global handler) with one on-error-propagate per APIKIT error type and the matching httpStatus."},{"id": "ERR-04","category": "ERROR_HANDLING","categoryLabel": "Error handling","severity": "MAJOR","title": "Catch-all handlers come last","description": "Mule runs the first matching handler. An ANY (or untyped) handler placed before specific ones means those specific handlers can never run.","fixHint": "Move the on-error-* with type=\"ANY\" (or no type) to the end of the error handler."},{"id": "LOG-01","category": "LOGGING","categoryLabel": "Logging","severity": "MINOR","title": "Log messages carry the correlation ID","description": "Without the correlation ID you cannot follow one request across the experience, process and system APIs in Anypoint Monitoring or Splunk.","fixHint": "Add #[correlationId] to the message, or add %X{correlationId} to the log4j2 PatternLayout so every line carries it automatically."},{"id": "LOG-02","category": "LOGGING","categoryLabel": "Logging","severity": "MAJOR","title": "Whole payloads are not logged at INFO","description": "Logging the full payload writes customer data (PII, card numbers, addresses) into log storage and slows the flow down, because a streamed payload must be loaded into memory to print it.","fixHint": "Log identifiers and counts instead (order ID, record count). If you need the payload for debugging, log it at DEBUG level."},{"id": "LOG-03","category": "LOGGING","categoryLabel": "Logging","severity": "MINOR","title": "log4j2.xml is present, async and not at DEBUG","description": "Without log4j2.xml the app uses runtime defaults. Synchronous appenders block the flow thread on every log call, and a DEBUG root level floods logs in production.","fixHint": "Ship a log4j2.xml with an AsyncRoot / AsyncLogger at INFO (or WARN) and raise specific packages to DEBUG only when needed."},{"id": "STR-01","category": "STRUCTURE","categoryLabel": "Structure","severity": "MINOR","title": "Flows stay small","description": "Long flows are hard to read, test with MUnit and reuse. Most teams cap a flow at 20-30 processors.","fixHint": "Split the flow into sub-flows by responsibility (validate, transform, call target, build response) and connect them with flow-ref."},{"id": "STR-02","category": "STRUCTURE","categoryLabel": "Structure","severity": "MINOR","title": "No unused flows or sub-flows","description": "Dead flows add build time, confuse readers and keep stale logic (and its connectors) in the app.","fixHint": "Delete the flow, or reference it with flow-ref if it is still needed."},{"id": "STR-03","category": "STRUCTURE","categoryLabel": "Structure","severity": "MINOR","title": "No unused global configurations","description": "An unused connector config still initialises at start-up: it may open connections, fail on missing properties and slow deployment.","fixHint": "Remove the global element, or reference it from the operation that needs it via config-ref."},{"id": "STR-04","category": "STRUCTURE","categoryLabel": "Structure","severity": "INFO","title": "Global configurations live in one file","description": "When connector configs are spread across many XML files, it is hard to see what an app connects to and easy to define the same config twice.","fixHint": "Move connector configs, configuration-properties and the global error handler into global.xml."},{"id": "STR-05","category": "STRUCTURE","categoryLabel": "Structure","severity": "MINOR","title": "No empty flows","description": "An empty flow (or one with only a source) is usually a leftover scaffold; APIkit-generated stubs left empty return the request back as the response.","fixHint": "Implement the flow or delete it. For unimplemented APIkit operations, return 501."},{"id": "STR-06","category": "STRUCTURE","categoryLabel": "Structure","severity": "MAJOR","title": "All XML files are well-formed","description": "A file MuleLint cannot parse is not checked by any other rule, and may also break the build.","fixHint": "Fix the XML error reported at the given line."},{"id": "NAM-01","category": "NAMING","categoryLabel": "Naming","severity": "MINOR","title": "Flow and sub-flow names follow the team convention","description": "Consistent names make flows searchable in logs, Anypoint Monitoring and stack traces. The default convention is kebab-case (get-orders-flow); change it in your rule profile.","fixHint": "Rename the flow to match the convention and update its flow-ref references."},{"id": "NAM-02","category": "NAMING","categoryLabel": "Naming","severity": "MINOR","title": "Variable names follow the team convention","description": "vars.OrderID, vars.order_id and vars.orderId in one app lead to typos that DataWeave only reports at runtime as null. The default convention is camelCase.","fixHint": "Rename the variable (set-variable variableName, or target=) and update the DataWeave that reads it."},{"id": "NAM-03","category": "NAMING","categoryLabel": "Naming","severity": "INFO","title": "Mule config files use kebab-case names","description": "File names like Orders_Impl.xml and order-utils.xml side by side make the project harder to navigate.","fixHint": "Rename files to kebab-case: orders-impl.xml, global.xml, common-error-handler.xml."},{"id": "DW-01","category": "DATAWEAVE","categoryLabel": "DataWeave","severity": "MINOR","title": "Large DataWeave scripts live in .dwl files","description": "Long scripts inside the XML are hard to diff in code review, cannot be reused and cannot be unit-tested on their own.","fixHint": "Move the script to src/main/resources/dwl/<name>.dwl and reference it with <ee:set-payload resource=\"dwl/<name>.dwl\"/>."},{"id": "DW-02","category": "DATAWEAVE","categoryLabel": "DataWeave","severity": "MINOR","title": "Every DataWeave match has an else case","description": "DataWeave's match has no implicit fallthrough: a value that hits no case throws at runtime, usually on the first unexpected input in production.","fixHint": "Add a final 'else -> <default>' case, even if it only returns null or raises a clear error."},{"id": "DW-03","category": "DATAWEAVE","categoryLabel": "DataWeave","severity": "MINOR","title": "No unused .dwl files","description": "Orphan .dwl files look like live mappings; developers fix bugs in them that never reach production.","fixHint": "Delete the file, or reference it with resource=\"...\" or an import in another script."},{"id": "PRF-01","category": "PERFORMANCE","categoryLabel": "Performance","severity": "MAJOR","title": "HTTP requests have an explicit response timeout","description": "Without responseTimeout the requester falls back to the default, so one slow backend holds threads until the caller (or the load balancer) gives up first.","fixHint": "Set responseTimeout=\"${http.timeout}\" on the <http:request-config> (or on each request) and tune it per environment."},{"id": "PRF-02","category": "PERFORMANCE","categoryLabel": "Performance","severity": "MINOR","title": "Connectors define a reconnection strategy","description": "Without reconnection, a short network blip or a database failover fails every message until the app is restarted.","fixHint": "Inside the connection element add <reconnection><reconnect frequency=\"${reconnect.frequency}\" count=\"${reconnect.attempts}\"/></reconnection>."},{"id": "PRF-03","category": "PERFORMANCE","categoryLabel": "Performance","severity": "INFO","title": "Review outbound calls inside For Each","description": "One HTTP or database call per record (the N+1 pattern) makes run time grow with input size. Large collections usually belong in Batch, Parallel For Each or a bulk operation.","fixHint": "Use a bulk operation (db:bulk-insert, Salesforce create with a list), Parallel For Each with a maxConcurrency, or a Batch Job."},{"id": "PRF-04","category": "PERFORMANCE","categoryLabel": "Performance","severity": "INFO","title": "Schedulers do not poll more often than every 5 seconds","description": "Very short polling intervals keep a worker busy and hammer the source system; on a cluster without primary-node-only every node polls.","fixHint": "Raise the frequency, or switch to an event source (listener, CDC, Anypoint MQ)."},{"id": "DEP-01","category": "DEPENDENCIES","categoryLabel": "Dependencies","severity": "MAJOR","title": "Mule runtime is not below the supported baseline","description": "Old runtimes stop receiving security patches and block newer connector versions. The baseline (default 4.6.0) is set in your rule profile; keep it in step with MuleSoft's support policy.","fixHint": "Raise app.runtime in pom.xml (and minMuleVersion in mule-artifact.json), then run the MUnit suite against the new runtime."},{"id": "DEP-02","category": "DEPENDENCIES","categoryLabel": "Dependencies","severity": "MINOR","title": "MUnit tests exist and enforce coverage","description": "Without MUnit (and a coverage threshold in the build) regressions reach QA unnoticed, and the build cannot gate pull requests.","fixHint": "Add munit-maven-plugin with <coverage><runCoverage>true</runCoverage><failBuild>true</failBuild><requiredApplicationCoverage>70</requiredApplicationCoverage></coverage> and write suites under src/test/munit."},{"id": "DEP-03","category": "DEPENDENCIES","categoryLabel": "Dependencies","severity": "MAJOR","title": "No SNAPSHOT dependencies","description": "A SNAPSHOT can change under you between two builds of the same commit, so the artifact you tested is not the one you deploy.","fixHint": "Depend on a released version. Publish the shared library to Exchange with a fixed version first."}];

  // ------------------------------------------------------------------ model

  const SEV = { BLOCKER: { o: 0, pts: 10, cap: 30 }, MAJOR: { o: 1, pts: 4, cap: 16 }, MINOR: { o: 2, pts: 1, cap: 6 }, INFO: { o: 3, pts: 0, cap: 0 } };
  const CATEGORIES = ["SECURITY", "CONFIGURATION", "ERROR_HANDLING", "LOGGING", "STRUCTURE", "NAMING", "DATAWEAVE", "PERFORMANCE", "DEPENDENCIES"];
  const DEFAULT_PARAMS = {
    flowMaxProcessors: "25",
    flowNameRegex: "^[a-z0-9]+(-[a-z0-9]+)*$",
    variableNameRegex: "^[a-z][a-zA-Z0-9]*$",
    minRuntimeVersion: "4.6.0",
    inlineDataWeaveMaxLines: "30",
  };

  class UserError extends Error {}

  class SourceFile {
    constructor(path, text) {
      this.path = path;
      this.text = text;
      this._lines = null;
    }
    get name() {
      const i = this.path.lastIndexOf("/");
      return i >= 0 ? this.path.slice(i + 1) : this.path;
    }
    lines() {
      if (!this._lines) this._lines = this.text.split(/\r?\n/);
      return this._lines;
    }
    line(n) {
      const l = this.lines();
      return n >= 1 && n <= l.length ? l[n - 1] : null;
    }
    lineOf(offset) {
      let line = 1;
      for (let i = 0; i < offset && i < this.text.length; i++) if (this.text.charCodeAt(i) === 10) line++;
      return line;
    }
  }

  // ------------------------------------------------------------------ XML

  const ENTITIES = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };
  function decode(s, lineAt) {
    return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[A-Za-z][\w.-]*);/g, (m, e) => {
      if (e[0] === "#") return String.fromCodePoint(e[1] === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
      if (e in ENTITIES) return ENTITIES[e];
      throw new XmlError(`The entity "${e}" was referenced, but not declared.`, lineAt());
    });
  }
  class XmlError extends Error {
    constructor(msg, line) {
      super(msg);
      this.line = line;
    }
  }

  /** Tolerant-but-strict XML reader: well-formedness errors throw, DOCTYPE is refused (no XXE), elements keep their start line. */
  function parseXml(file) {
    const s = file.text.charCodeAt(0) === 0xfeff ? file.text.slice(1) : file.text;
    const starts = [0];
    for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) === 10) starts.push(i + 1);
    const lineAt = (off) => {
      let lo = 0, hi = starts.length - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (starts[mid] <= off) lo = mid; else hi = mid - 1;
      }
      return lo + 1;
    };
    let i = 0;
    const stack = [];
    let root = null;
    const nsStack = [{ "": null, xml: "http://www.w3.org/XML/1998/namespace" }];
    const appendText = (t) => {
      const top = stack[stack.length - 1];
      if (top) top.texts.push(t);
      else if (t.trim()) throw new XmlError("Content is not allowed in prolog.", lineAt(i));
    };
    while (i < s.length) {
      const lt = s.indexOf("<", i);
      if (lt < 0) {
        appendText(decode(s.slice(i), () => lineAt(i)));
        break;
      }
      if (lt > i) {
        const at = i;
        appendText(decode(s.slice(i, lt), () => lineAt(at)));
      }
      i = lt;
      if (s.startsWith("<!--", i)) {
        const e = s.indexOf("-->", i + 4);
        if (e < 0) throw new XmlError("The comment is not terminated.", lineAt(i));
        i = e + 3;
      } else if (s.startsWith("<![CDATA[", i)) {
        const e = s.indexOf("]]>", i + 9);
        if (e < 0) throw new XmlError("The CDATA section is not terminated.", lineAt(i));
        if (!stack.length) throw new XmlError("CDATA outside the root element.", lineAt(i));
        stack[stack.length - 1].texts.push(s.slice(i + 9, e));
        i = e + 3;
      } else if (s.startsWith("<?", i)) {
        const e = s.indexOf("?>", i + 2);
        if (e < 0) throw new XmlError("The processing instruction is not terminated.", lineAt(i));
        i = e + 2;
      } else if (s.startsWith("<!DOCTYPE", i) || s.startsWith("<!doctype", i)) {
        throw new XmlError('DOCTYPE is disallowed when the feature "http://apache.org/xml/features/disallow-doctype-decl" set to true.', lineAt(i));
      } else if (s.startsWith("</", i)) {
        const e = s.indexOf(">", i);
        if (e < 0) throw new XmlError("The end tag is not terminated.", lineAt(i));
        const name = s.slice(i + 2, e).trim();
        const top = stack.pop();
        if (!top || top.tag !== name) {
          throw new XmlError(`The element type "${top ? top.tag : name}" must be terminated by the matching end-tag "</${top ? top.tag : name}>".`, lineAt(i));
        }
        nsStack.pop();
        i = e + 1;
      } else {
        const m = /^<([A-Za-z_][\w.:-]*)/.exec(s.slice(i, i + 300));
        if (!m) throw new XmlError("The markup in the document following the root element must be well-formed.", lineAt(i));
        const tag = m[1];
        const startLine = lineAt(i);
        let j = i + m[0].length;
        const raw = [];
        let selfClose = false;
        for (;;) {
          while (j < s.length && /\s/.test(s[j])) j++;
          if (j >= s.length) throw new XmlError(`Element type "${tag}" is not terminated.`, startLine);
          if (s[j] === ">") { j++; break; }
          if (s[j] === "/" && s[j + 1] === ">") { selfClose = true; j += 2; break; }
          const am = /^([^\s=/>]+)\s*=\s*("([^"]*)"|'([^']*)')/.exec(s.slice(j, j + 100000));
          if (!am) throw new XmlError(`Element type "${tag}" must be followed by either attribute specifications, ">" or "/>".`, lineAt(j));
          const at = j;
          raw.push([am[1], decode(am[3] !== undefined ? am[3] : am[4], () => lineAt(at))]);
          j += am[0].length;
        }
        const ns = Object.assign({}, nsStack[nsStack.length - 1]);
        const attrs = [];
        const seen = new Set();
        for (const [q, v] of raw) {
          if (seen.has(q)) throw new XmlError(`Attribute "${q}" was already specified for element "${tag}".`, startLine);
          seen.add(q);
          if (q === "xmlns") ns[""] = v || null;
          else if (q.startsWith("xmlns:")) ns[q.slice(6)] = v;
        }
        for (const [q, v] of raw) {
          if (q === "xmlns" || q.startsWith("xmlns:")) continue;
          const c = q.indexOf(":");
          attrs.push({ q, local: c >= 0 ? q.slice(c + 1) : q, value: v });
        }
        attrs.sort((a, b) => (a.q < b.q ? -1 : a.q > b.q ? 1 : 0));
        const c = tag.indexOf(":");
        const prefix = c >= 0 ? tag.slice(0, c) : "";
        if (prefix && !(prefix in ns)) throw new XmlError(`The prefix "${prefix}" for element "${tag}" is not bound.`, startLine);
        const el = { tag, local: c >= 0 ? tag.slice(c + 1) : tag, nsUri: ns[prefix] || null, attrs, kids: [], texts: [], line: startLine, parent: null, _all: [] };
        const parent = stack[stack.length - 1];
        if (parent) {
          el.parent = parent;
          parent.kids.push(el);
          parent.texts.push(el); // keep document order for textContent
        } else {
          if (root) throw new XmlError("The markup in the document following the root element must be well-formed.", startLine);
          root = el;
        }
        i = j;
        if (!selfClose) {
          stack.push(el);
          nsStack.push(ns);
        }
      }
    }
    if (stack.length) throw new XmlError(`XML document structures must start and end within the same entity.`, lineAt(s.length));
    if (!root) throw new XmlError("Premature end of file.", 1);
    return root;
  }

  // ------------------------------------------------------------------ Mule helpers

  const CORE_NS = "http://www.mulesoft.org/schema/mule/core";
  const NS_PREFIX = "http://www.mulesoft.org/schema/mule/";
  const M = {
    ns(e) {
      const u = e.nsUri;
      if (!u) return "";
      if (u === CORE_NS) return "core";
      if (u.startsWith(NS_PREFIX)) {
        const rest = u.slice(NS_PREFIX.length);
        const sl = rest.indexOf("/");
        const n = sl > 0 ? rest.slice(0, sl) : rest;
        return n === "mule-apikit" ? "apikit" : n;
      }
      return u;
    },
    local: (e) => e.local,
    is: (e, ns, local) => M.ns(e) === ns && e.local === local,
    isCore: (e, local) => M.is(e, "core", local),
    line: (e) => (e ? e.line : 0),
    has: (e, q) => e.attrs.some((a) => a.q === q),
    attr(e, name) {
      const a = e.attrs.find((x) => x.q === name) || e.attrs.find((x) => x.local === name);
      return a ? a.value : null;
    },
    children: (e) => e.kids,
    walk(e, fn) {
      fn(e);
      for (const k of e.kids) M.walk(k, fn);
    },
    descendants(e) {
      const out = [];
      M.walk(e, (x) => out.push(x));
      out.shift();
      return out;
    },
    text(e) {
      let t = "";
      for (const p of e.texts) t += typeof p === "string" ? p : M.text(p);
      return t;
    },
    isExpression: (v) => v != null && v.trim().startsWith("#["),
    hasPlaceholder: (v) => v != null && v.includes("${"),
    isLiteral: (v) => v != null && v.trim() !== "" && !M.hasPlaceholder(v) && !M.isExpression(v),
    placeholders(v) {
      const out = [];
      if (v == null) return out;
      const re = /\$\{([^}]+)\}/g;
      let m;
      while ((m = re.exec(v))) out.push(m[1].trim());
      return out;
    },
    isInside(e, ns, local) {
      for (let p = e.parent; p; p = p.parent) if (M.is(p, ns, local)) return true;
      return false;
    },
    source(flow) {
      const first = flow.kids[0];
      if (!first) return null;
      const l = first.local;
      const looks = l === "scheduler" || l.includes("listener") || l.startsWith("on-") || l === "subscriber" || l.endsWith("-trigger") ||
        l === "consume-messages" || l.startsWith("subscribe") || l === "polling" || l === "watch" || l.startsWith("replay");
      return looks && !M.isCore(first, "logger") ? first : null;
    },
    isApikitFlowName: (n) => n != null && /^(get|post|put|patch|delete|head|options|trace):\\/.test(n),
  };
  const childEl = (p, local) => (p ? p.kids.find((c) => c.local === local) || null : null);
  const childText = (p, local) => {
    const c = childEl(p, local);
    if (!c) return null;
    const t = M.text(c).trim();
    return t === "" ? null : t;
  };
  const countNewlines = (s, upTo) => {
    let n = 0;
    for (let i = 0; i < upTo && i < s.length; i++) if (s.charCodeAt(i) === 10) n++;
    return n;
  };
  const quoteRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  // ------------------------------------------------------------------ property files

  const ENV_TOKEN = /(?:^|[-_.])(local|dev|develop|development|sit|qa|test|uat|stg|stage|staging|preprod|prod|production)(?=[-_.]|$)/g;
  class PropertyFile {
    constructor(file, props) {
      this.file = file;
      this.props = props;
    }
    envToken() {
      const base = this.file.name.toLowerCase().replace(/\.(ya?ml|properties)$/, "");
      let found = null, m;
      ENV_TOKEN.lastIndex = 0;
      while ((m = ENV_TOKEN.exec(base))) found = m[1];
      return found;
    }
    envGroup() {
      const env = this.envToken();
      if (env == null) return null;
      const n = this.file.name.toLowerCase();
      return n.replace(new RegExp("(^|[-_.])" + quoteRe(env) + "(?=[-_.]|\\.(ya?ml|properties)$)"), "$1*");
    }
    static parse(file) {
      const n = file.name.toLowerCase();
      return new PropertyFile(file, n.endsWith(".properties") ? parseProperties(file) : parseYaml(file));
    }
  }
  const isWs = (c) => /\s/.test(c);
  const stripLeading = (s) => s.replace(/^\s+/, "");
  function parseProperties(file) {
    const out = new Map();
    const lines = file.lines();
    for (let i = 0; i < lines.length; i++) {
      const startLine = i + 1;
      let l = stripLeading(lines[i]);
      const endsCont = (s) => {
        let n = 0;
        for (let k = s.length - 1; k >= 0 && s[k] === "\\"; k--) n++;
        return n % 2 === 1;
      };
      while (endsCont(l) && i + 1 < lines.length) l = l.slice(0, -1) + stripLeading(lines[++i]);
      if (l === "" || l.startsWith("#") || l.startsWith("!")) continue;
      let sep = -1;
      for (let k = 0; k < l.length; k++) {
        const c = l[k];
        if (c === "\\") { k++; continue; }
        if (c === "=" || c === ":" || isWs(c)) { sep = k; break; }
      }
      let key = sep < 0 ? l : l.slice(0, sep);
      let value = "";
      if (sep >= 0) {
        let v = sep;
        while (v < l.length && isWs(l[v])) v++;
        if (v < l.length && (l[v] === "=" || l[v] === ":")) v++;
        while (v < l.length && isWs(l[v])) v++;
        value = l.slice(v);
      }
      key = key.split("\\").join("").trim();
      if (key) out.set(key, { key, value: value.trim(), line: startLine });
    }
    return out;
  }
  const YAML_KEY = /^(\s*)("[^"]*"|'[^']*'|[^\s#'"][^:#]*?)\s*:(?:\s+(.*))?$/;
  function stripComment(s) {
    let sq = false, dq = false;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === "'" && !dq) sq = !sq;
      else if (c === '"' && !sq) dq = !dq;
      else if (c === "#" && !sq && !dq && (i === 0 || isWs(s[i - 1]))) return s.slice(0, i).replace(/\s+$/, "");
    }
    return s;
  }
  const unquote = (v) => (v.length >= 2 && ((v[0] === '"' && v.endsWith('"')) || (v[0] === "'" && v.endsWith("'"))) ? v.slice(1, -1) : v);
  const indentOf = (s) => {
    let i = 0;
    while (i < s.length && (s[i] === " " || s[i] === "\t")) i++;
    return i;
  };
  function parseYaml(file) {
    const out = new Map();
    const lines = file.lines();
    const indents = [], prefixes = [];
    let depth = 0, listIndent = -1;
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i];
      const trimmed = raw.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed === "---" || trimmed === "...") continue;
      const indent = indentOf(raw);
      if (listIndent >= 0) {
        if (indent > listIndent || (indent === listIndent && trimmed.startsWith("- "))) continue;
        listIndent = -1;
      }
      if (trimmed.startsWith("- ") || trimmed === "-") {
        listIndent = indent;
        continue;
      }
      const m = YAML_KEY.exec(stripComment(raw));
      if (!m) continue;
      const key = unquote(m[2].trim());
      const value = m[3] == null ? "" : m[3].trim();
      while (depth > 0 && indents[depth - 1] >= indent) depth--;
      const full = (depth === 0 ? "" : prefixes[depth - 1] + ".") + key;
      if (!value) {
        if (depth < 64) {
          indents[depth] = indent;
          prefixes[depth] = full;
          depth++;
        }
        continue;
      }
      if (value.startsWith("|") || value.startsWith(">")) {
        const parts = [];
        let j = i + 1;
        while (j < lines.length && (!lines[j].trim() || indentOf(lines[j]) > indent)) {
          parts.push(lines[j].trim());
          j++;
        }
        out.set(full, { key: full, value: parts.join("\n").trim(), line: i + 1 });
        i = j - 1;
        continue;
      }
      out.set(full, { key: full, value: value.startsWith("[") || value.startsWith("{") ? value : unquote(value), line: i + 1 });
    }
    return out;
  }

  // ------------------------------------------------------------------ archive + project model

  const LIMITS = { entries: 100000, fileBytes: 5 * 1024 * 1024, totalBytes: 120 * 1024 * 1024, textFiles: 5000 };
  const TEXT_EXT = [".xml", ".yaml", ".yml", ".properties", ".dwl", ".json", ".raml"];
  function checkName(name) {
    if (name.startsWith("/") || name.includes("../") || name === ".." || name.includes("\0") || /^[A-Za-z]:/.test(name)) {
      throw new UserError("Unsafe path in archive: " + name);
    }
  }
  function isWanted(name) {
    const l = name.toLowerCase();
    if (l.startsWith("repository/")) return false;
    if (l.includes("/target/") || l.startsWith("target/")) return false;
    if (l.includes("/.mule/") || l.startsWith(".mule/")) return false;
    if (l.includes("/node_modules/") || l.includes("/.git/")) return false;
    if (l.includes("exchange_modules/") || l.includes("/exchange-docs/")) return false;
    return TEXT_EXT.some((e) => l.endsWith(e));
  }

  /** Reads the wanted text files from a ZIP/JAR (ArrayBuffer/Uint8Array) using JSZip. */
  async function readArchive(data, JSZipLib) {
    let zip;
    try {
      zip = await JSZipLib.loadAsync(data);
    } catch (e) {
      throw new UserError("Not a valid JAR/ZIP archive: " + (e && e.message ? e.message : e));
    }
    const files = new Map();
    let entries = 0, total = 0;
    const list = [];
    zip.forEach((path, entry) => list.push(entry));
    for (const entry of list) {
      if (++entries > LIMITS.entries) throw new UserError(`Archive has more than ${LIMITS.entries} entries`);
      const name = (entry.unsafeOriginalName || entry.name).replace(/\\/g, "/");
      checkName(name);
      if (entry.dir || !isWanted(name)) continue;
      if (files.size >= LIMITS.textFiles) throw new UserError(`Archive has more than ${LIMITS.textFiles} source files`);
      const size = entry._data && entry._data.uncompressedSize;
      if (size > LIMITS.fileBytes) continue;
      const bytes = await entry.async("uint8array");
      if (bytes.length > LIMITS.fileBytes) continue;
      total += bytes.length;
      if (total > LIMITS.totalBytes) throw new UserError("Archive expands to more than 120 MB of source");
      let text = new TextDecoder("utf-8").decode(bytes);
      if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
      files.set(name, text);
    }
    return files;
  }

  const SRC_ROOT = /^(.*?)src\/main\/mule\/[^/]+\.xml$/;
  function findSourcePrefix(files) {
    let best = null;
    for (const n of files.keys()) {
      const m = SRC_ROOT.exec(n);
      if (m && (best == null || m[1].length < best.length)) best = m[1];
    }
    return best;
  }
  const byPath = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

  function buildModel(files, fallbackName) {
    const m = { muleConfigs: [], munitConfigs: [], propertyFiles: [], dwlFiles: [], parseErrors: [], pom: null, log4j2: null, muleArtifactJson: null, layout: "JAR", info: null };
    const parse = (f) => {
      try {
        return { file: f, root: parseXml(f) };
      } catch (e) {
        if (!(e instanceof XmlError)) throw e;
        m.parseErrors.push({ file: f, line: e.line || 0, message: e.message });
        return null;
      }
    };
    const isMuleRoot = (x) => x.root && M.isCore(x.root, "mule");
    const isApiSpecPath = (r) => r.startsWith("api/") || r.includes("/api/") || r.includes("exchange") || r.startsWith("examples/") || r.includes("/examples/") || r.startsWith("schemas/");
    const looksLikeApiSpec = (f) => {
      const head = f.text.slice(0, 400);
      return head.startsWith("#%RAML") || /(^|\n)(openapi|swagger)\s*:/.test(head);
    };
    const classify = (f, rel) => {
      if (rel === "log4j2.xml") m.log4j2 = parse(f);
      else if (rel.endsWith(".dwl")) m.dwlFiles.push(f);
      else if ((rel.endsWith(".yaml") || rel.endsWith(".yml") || rel.endsWith(".properties")) && !isApiSpecPath(rel) && !looksLikeApiSpec(f)) m.propertyFiles.push(PropertyFile.parse(f));
      else if (rel.endsWith(".xml") && !isApiSpecPath(rel)) {
        const x = parse(f);
        if (x && isMuleRoot(x)) m.muleConfigs.push(x);
      }
    };
    const prefix = findSourcePrefix(files);
    if (prefix != null) {
      m.layout = prefix.toLowerCase().startsWith("meta-inf/mule-src/") ? "MULE_SRC" : "SOURCE";
      for (const [raw, text] of files) {
        if (!raw.startsWith(prefix)) continue;
        const rel = raw.slice(prefix.length);
        if (rel.includes("/target/") || rel.startsWith("target/")) continue;
        const f = new SourceFile(rel, text);
        const lower = rel.toLowerCase();
        if (lower === "pom.xml") m.pom = parse(f);
        else if (lower === "mule-artifact.json") m.muleArtifactJson = f;
        else if (lower.startsWith("src/main/mule/") && lower.endsWith(".xml")) {
          const x = parse(f);
          if (x && isMuleRoot(x)) m.muleConfigs.push(x);
        } else if (lower.startsWith("src/test/munit/") && lower.endsWith(".xml")) {
          const x = parse(f);
          if (x) m.munitConfigs.push(x);
        } else if (lower.startsWith("src/main/resources/")) classify(f, lower.slice("src/main/resources/".length));
      }
    } else {
      for (const [raw, text] of files) {
        const lower = raw.toLowerCase();
        const f = new SourceFile(raw, text);
        if (lower.startsWith("meta-inf/")) {
          if (lower.endsWith("/pom.xml") && lower.startsWith("meta-inf/maven/") && m.pom == null) m.pom = parse(f);
          else if (lower === "meta-inf/mule-artifact/mule-artifact.json") m.muleArtifactJson = f;
          continue;
        }
        if (lower.endsWith(".xml") && !lower.includes("/")) {
          if (lower === "log4j2.xml") { m.log4j2 = parse(f); continue; }
          if (lower.startsWith("log4j2")) continue;
          const x = parse(f);
          if (x && isMuleRoot(x)) m.muleConfigs.push(x);
          continue;
        }
        classify(f, lower);
      }
    }
    m.muleConfigs.sort((a, b) => byPath(a.file.path, b.file.path));
    m.munitConfigs.sort((a, b) => byPath(a.file.path, b.file.path));
    m.propertyFiles.sort((a, b) => byPath(a.file.path, b.file.path));
    m.dwlFiles.sort((a, b) => byPath(a.path, b.path));

    m.forEachElement = (fn) => {
      for (const x of m.muleConfigs) M.walk(x.root, (e) => fn(x, e));
    };
    m.topLevel = (local) => {
      const out = [];
      for (const x of m.muleConfigs) for (const e of x.root.kids) if (M.isCore(e, local)) out.push(e);
      return out;
    };
    m.pomProperties = () => {
      const out = new Map();
      if (!m.pom) return out;
      const props = childEl(m.pom.root, "properties");
      if (props) for (const p of props.kids) out.set(p.local, M.text(p).trim());
      return out;
    };

    let groupId = null, artifactId = null, version = null, name = null, runtime = null;
    if (m.pom) {
      const project = m.pom.root;
      groupId = childText(project, "groupId");
      artifactId = childText(project, "artifactId");
      version = childText(project, "version");
      name = childText(project, "name");
      const parent = childEl(project, "parent");
      if (groupId == null && parent) groupId = childText(parent, "groupId");
      if (version == null && parent) version = childText(parent, "version");
      const props = m.pomProperties();
      runtime = props.get("app.runtime") ?? props.get("mule.version") ?? props.get("mule.runtime.version") ?? null;
    }
    if (m.muleArtifactJson) {
      const mm = /"minMuleVersion"\s*:\s*"([^"]+)"/.exec(m.muleArtifactJson.text);
      if (mm && (runtime == null || runtime.includes("${"))) runtime = mm[1];
      if (artifactId == null) {
        const n = /"name"\s*:\s*"([^"]+)"/.exec(m.muleArtifactJson.text);
        if (n) artifactId = n[1];
      }
    }
    if (runtime != null && runtime.includes("${")) runtime = null;
    if (artifactId == null) artifactId = fallbackName;
    if (name == null) name = artifactId;
    m.info = { groupId, artifactId, version, name, runtimeVersion: runtime, layout: m.layout };
    return m;
  }

  // ------------------------------------------------------------------ reporting

  function mask(value) {
    if (value == null) return null;
    const v = value.trim();
    if (v.length <= 6) return "****";
    return v.slice(0, 2) + "*".repeat(Math.min(v.length - 4, 12)) + v.slice(-2);
  }
  const isEncrypted = (v) => v != null && v.trim().startsWith("![") && v.trim().endsWith("]");
  const maskIfLiteral = (v) => (v == null || !v.trim() || isEncrypted(v) || M.hasPlaceholder(v) || M.isExpression(v) || v.includes("*") ? v : mask(v));
  function redact(line) {
    if (line == null) return null;
    let out = line.replace(
      /(?<=[\s<])(password|passwd|pwd|secret|clientSecret|client-secret|consumerSecret|token|accessToken|securityToken|apiKey|api-key|privateKey|keyPassword|passphrase|sasToken|sharedAccessKey|accountKey|secretKey|key)\s*=\s*(["'])(.*?)\2/gi,
      (m0, a, q, v) => `${a}=${q}${maskIfLiteral(v)}${q}`,
    );
    out = out.replace(/<([\w:.-]*(?:password|secret|token|apikey)[\w.-]*)>([^<]+)<\/\1>/gi, (m0, t, v) => `<${t}>${maskIfLiteral(v)}</${t}>`);
    out = out.replace(
      /^(\s*[\w.\-"']*(?:password|passwd|pwd|secret|token|apikey|api[._-]key|private[._-]?key|passphrase|client[._-]?secret|access[._-]?key|secret[._-]?key|credentials?)["']?\s*[:=]\s*)(.+)$/i,
      (m0, k, raw) => {
        let v = raw.trim();
        let q = "";
        if (v.length >= 2 && ((v[0] === '"' && v.endsWith('"')) || (v[0] === "'" && v.endsWith("'")))) {
          q = v[0];
          v = v.slice(1, -1);
        }
        return k + q + maskIfLiteral(v) + q;
      },
    );
    out = out.replace(/\b(Basic|Bearer)(\s+)([A-Za-z0-9+/._~-]{12,}={0,2})/gi, (m0, a, sp, v) => a + sp + mask(v));
    return out;
  }
  function maskLine(line, secret) {
    if (line == null) return null;
    if (secret == null || !secret.trim()) return line;
    const masked = mask(secret);
    let out = line.split(secret).join(masked);
    if (out === line) out = line.split(secret.trim()).join(masked);
    return out;
  }

  class Ctx {
    constructor(config, sink) {
      this.config = config;
      this.sink = sink;
    }
    begin(meta) {
      this.meta = meta;
      this.sev = (this.config.severities && this.config.severities[meta.id]) || meta.severity;
      this.count = 0;
    }
    param(k) {
      return (this.config.params && this.config.params[k]) || DEFAULT_PARAMS[k];
    }
    intParam(k, fb) {
      const v = this.param(k);
      return /^-?\d+$/.test(String(v).trim()) ? parseInt(v, 10) : fb;
    }
    /** report(file, elementOrLine, message, snippet?) */
    report(file, at, message, snippet) {
      if (this.count >= 200) return;
      this.count++;
      const line = typeof at === "number" ? at : at ? at.line : 0;
      let snip = snippet !== undefined ? snippet : file && line > 0 ? file.line(line) : null;
      if (snip != null) {
        snip = redact(snip).trim();
        if (snip.length > 240) snip = snip.slice(0, 237) + "...";
      }
      const path = file ? file.path : "(project)";
      this.sink.push({
        ruleId: this.meta.id, category: this.meta.category, severity: this.sev, title: this.meta.title,
        file: path, line: Math.max(line, 0), message, fixHint: this.meta.fixHint, snippet: snip, _fp: `${this.meta.id}|${path}|${message}`,
      });
    }
  }

  // ------------------------------------------------------------------ rules

  const SECRET_ATTR = /^(password|passwd|pwd|secret|clientSecret|client-secret|consumerSecret|token|accessToken|securityToken|apiKey|api-key|privateKey|keyPassword|passphrase|sasToken|sharedAccessKey|accountKey|secretKey)$/i;
  const SECRET_KEY = /(^|[._-])(password|passwd|pwd|secret|token|apikey|api[._-]key|private[._-]?key|passphrase|client[._-]?secret|access[._-]?key|secret[._-]?key|credentials?)$/i;
  const INLINE_AUTH = /\b(Basic\s+[A-Za-z0-9+/]{12,}={0,2}|Bearer\s+[A-Za-z0-9._~+/-]{20,})/i;
  const isHandler = (e) => M.isCore(e, "on-error-continue") || M.isCore(e, "on-error-propagate");
  const WRAPPERS = new Set(["when", "otherwise", "route", "process-records", "step", "on-complete", "aggregator", "size-based-aggregator", "group-based-aggregator", "processors"]);
  const SCOPES = new Set(["choice", "scatter-gather", "foreach", "parallel-foreach", "try", "async", "until-successful", "first-successful", "round-robin", "cache", "job"]);
  function countProcessors(c) {
    let n = 0;
    for (const k of c.kids) {
      if (M.isCore(k, "error-handler")) continue;
      if (WRAPPERS.has(k.local)) { n += countProcessors(k); continue; }
      n++;
      if (SCOPES.has(k.local)) n += countProcessors(k);
    }
    return n;
  }
  const topFlows = (m, fn) => {
    for (const x of m.muleConfigs) for (const f of x.root.kids) if (M.isCore(f, "flow") || M.isCore(f, "sub-flow")) fn(x, f);
  };
  const compileFull = (src, fb) => {
    try {
      return { re: new RegExp("^(?:" + src + ")$"), src };
    } catch (e) {
      return { re: new RegExp("^(?:" + fb + ")$"), src: fb };
    }
  };
  function compareVersions(a, b) {
    const pa = a.replace(/[^0-9.].*$/, "").split("."), pb = b.replace(/[^0-9.].*$/, "").split(".");
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const x = i < pa.length && pa[i] !== "" ? parseInt(pa[i], 10) : 0;
      const y = i < pb.length && pb[i] !== "" ? parseInt(pb[i], 10) : 0;
      if (Number.isNaN(x) || Number.isNaN(y)) throw new Error("version");
      if (x !== y) return x < y ? -1 : 1;
    }
    return 0;
  }
  const isInlineScript = (e) => M.ns(e) === "ee" && ["set-payload", "set-variable", "set-attributes"].includes(e.local) && M.isInside(e, "ee", "transform");
  function stripDwComments(s) {
    const sb = s.split("");
    let str = false, q = "";
    for (let i = 0; i < sb.length; i++) {
      const c = sb[i];
      if (str) {
        if (c === "\\") { i++; continue; }
        if (c === q) str = false;
        continue;
      }
      if (c === '"' || c === "'") { str = true; q = c; continue; }
      if (c === "/" && sb[i + 1] === "/") {
        while (i < sb.length && sb[i] !== "\n") sb[i++] = " ";
      } else if (c === "/" && sb[i + 1] === "*") {
        while (i < sb.length && !(sb[i] === "*" && sb[i + 1] === "/")) {
          if (sb[i] !== "\n") sb[i] = " ";
          i++;
        }
        if (i + 1 < sb.length) { sb[i] = " "; sb[i + 1] = " "; i++; }
      }
    }
    return sb.join("");
  }
  function matchingBrace(s, open) {
    let depth = 0, str = false, q = "";
    for (let i = open; i < s.length; i++) {
      const c = s[i];
      if (str) {
        if (c === "\\") { i++; continue; }
        if (c === q) str = false;
        continue;
      }
      if (c === '"' || c === "'" || c === "`") { str = true; q = c; continue; }
      if (c === "{") depth++;
      else if (c === "}" && --depth === 0) return i;
    }
    return -1;
  }
  function missingElse(script) {
    const out = [];
    const clean = stripDwComments(script);
    const re = /\bmatch\s*\{/g;
    let mm;
    while ((mm = re.exec(clean))) {
      const open = mm.index + mm[0].length - 1;
      const close = matchingBrace(clean, open);
      if (close < 0) continue;
      if (!/\belse\s*->/.test(clean.slice(open + 1, close))) out.push(mm.index);
    }
    return out;
  }
  const RUNTIME_PROVIDED = new Set(["env", "mule.env", "environment", "secure.key", "mule.key", "encryption.key", "key", "app.name", "app.home", "mule.home", "mule.version", "mule.env.name",
    "http.port", "https.port", "http.private.port", "https.private.port", "api.id", "apiId", "anypoint.platform.client_id", "anypoint.platform.client_secret", "worker.id", "app.id",
    "domain", "deployment.id", "mule.vcore", "region"]);
  const stripSecure = (k) => (k.startsWith("secure::") ? k.slice(8) : k);

  const RULES = {
    "SEC-01"(m, c) {
      m.forEachElement((x, e) => {
        for (const a of e.attrs) {
          const name = a.local, value = a.value;
          const secretAttr = SECRET_ATTR.test(name) || (name === "key" && e.local === "config" && M.ns(e) === "secure-properties");
          if (secretAttr && M.isLiteral(value)) {
            c.report(x.file, e.line, `Attribute '${name}' on <${e.tag}> holds a plaintext value`, maskLine(x.file.line(e.line), value));
          } else if (value != null && !M.isExpression(value)) {
            const mm = INLINE_AUTH.exec(value);
            if (mm) c.report(x.file, e.line, `Hardcoded Authorization header value in attribute '${name}'`, maskLine(x.file.line(e.line), mm[1]));
          }
        }
        if (!e.kids.length) {
          const t = M.text(e);
          const mm = INLINE_AUTH.exec(t);
          if (mm) {
            const line = e.line + countNewlines(t, mm.index);
            c.report(x.file, line, `Hardcoded Authorization header value in <${e.tag}>`, maskLine(x.file.line(line), mm[1]));
          }
        }
      });
      for (const pf of m.propertyFiles) {
        for (const p of pf.props.values()) {
          const v = p.value;
          if (!SECRET_KEY.test(p.key)) continue;
          if (v == null || !v.trim() || isEncrypted(v) || M.hasPlaceholder(v)) continue;
          if (v.toLowerCase() === "null" || v === '""' || v === "''") continue;
          c.report(pf.file, p.line, `Property '${p.key}' holds an unencrypted secret`, maskLine(pf.file.line(p.line), v));
        }
      }
      if (m.pom) {
        const pom = m.pom;
        M.walk(pom.root, (e) => {
          if (e.kids.length) return;
          const name = e.local, v = M.text(e).trim();
          if ((SECRET_ATTR.test(name) || /(password|clientsecret|secret)$/i.test(name)) && M.isLiteral(v)) {
            c.report(pom.file, e.line, `pom.xml element <${name}> holds a plaintext secret`, maskLine(pom.file.line(e.line), v));
          }
        });
      }
    },
    "SEC-02"(m, c) {
      m.forEachElement((x, e) => {
        for (const a of e.attrs) {
          if (!SECRET_ATTR.test(a.local)) continue;
          for (const ph of M.placeholders(a.value)) {
            if (!ph.startsWith("secure::")) c.report(x.file, e, `Attribute '${a.local}' reads \${${ph}} without the secure:: prefix`);
          }
        }
      });
    },
    "SEC-03"(m, c) {
      m.forEachElement((x, e) => {
        if (e.local === "trust-store" && (M.attr(e, "insecure") || "").toLowerCase() === "true") {
          c.report(x.file, e, 'Trust store is marked insecure="true" and accepts any certificate');
        }
        const protocols = M.attr(e, "enabledProtocols");
        if (e.local === "context" && M.isLiteral(protocols)) {
          for (const p of protocols.split(/[,\s]+/)) {
            if (/^tlsv1(\.1)?$/i.test(p) || p.toUpperCase().startsWith("SSL")) c.report(x.file, e, "TLS context enables deprecated protocol " + p);
          }
        }
      });
    },
    "SEC-04"(m, c) {
      let has = false;
      m.forEachElement((x, e) => { if (M.ns(e) === "secure-properties" && e.local === "config") has = true; });
      if (has) return;
      let done = false;
      m.forEachElement((x, e) => {
        if (done) return;
        if (e.attrs.some((a) => a.value.includes("${secure::"))) {
          c.report(x.file, e, "secure:: placeholders are used but no <secure-properties:config> is declared");
          done = true;
        }
      });
    },
    "SEC-05"(m, c) {
      let listener = null, lf = null, auto = false;
      m.forEachElement((x, e) => {
        if (M.is(e, "http", "listener") && !listener) { listener = e; lf = x; }
        if (M.ns(e) === "api-gateway" && e.local === "autodiscovery") auto = true;
      });
      if (listener && !auto) c.report(lf.file, listener, "App exposes an HTTP listener but declares no API autodiscovery");
    },
    "CFG-01"(m, c) {
      const ATTRS = new Set(["host", "port", "url", "basePath", "path", "domain", "instanceName", "database", "workingDir", "authorizationUrl", "tokenUrl", "brokerUrl", "endpoint"]);
      m.forEachElement((x, e) => {
        const l = e.local, ns = M.ns(e);
        const conn = l.endsWith("connection") || l.endsWith("-config") || l === "config" || M.is(e, "http", "request") || l === "listener-config";
        if (!conn || ["core", "secure-properties", "api-gateway", "apikit"].includes(ns)) return;
        if (M.is(e, "http", "listener")) return;
        for (const a of e.attrs) {
          const name = a.local, v = a.value;
          if (!ATTRS.has(name) || !M.isLiteral(v)) continue;
          if (name === "host" && ["0.0.0.0", "localhost", "127.0.0.1"].includes(v)) continue;
          if (M.is(e, "http", "request") && name === "path") continue;
          if (name === "basePath" && v === "/") continue;
          c.report(x.file, e, `<${e.tag}> has a hardcoded ${name}="${v}"`);
        }
      });
    },
    "CFG-02"(m, c) {
      const groups = new Map();
      for (const pf of m.propertyFiles) {
        const g = pf.envGroup();
        if (g != null) {
          if (!groups.has(g)) groups.set(g, []);
          groups.get(g).push(pf);
        }
      }
      if (!groups.size) {
        if (m.propertyFiles.length) c.report(m.propertyFiles[0].file, 0, "No environment-specific property files found (e.g. config-dev.yaml, config-prod.yaml)");
        else if (m.muleConfigs.length) c.report(null, 0, "Project has no property files; all configuration is inside the XML");
        return;
      }
      for (const g of [...groups.keys()].sort(byPath)) {
        const files = groups.get(g);
        if (files.length < 2) continue;
        const union = new Set();
        for (const pf of files) for (const k of pf.props.keys()) union.add(k);
        for (const pf of files) {
          const missing = [...union].filter((k) => !pf.props.has(k));
          if (!missing.length) continue;
          const list = missing.length > 8 ? missing.slice(0, 8).join(", ") + " and " + (missing.length - 8) + " more" : missing.join(", ");
          c.report(pf.file, 0, `${pf.file.name} is missing ${missing.length} key(s) that other ${g} files define: ${list}`);
        }
      }
    },
    "CFG-03"(m, c) {
      const defined = new Set();
      for (const pf of m.propertyFiles) for (const k of pf.props.keys()) defined.add(k);
      m.forEachElement((x, e) => { if (M.isCore(e, "global-property") && M.attr(e, "name") != null) defined.add(M.attr(e, "name")); });
      const first = new Map();
      const DW_P = /\bp\(\s*['"]([^'"]+)['"]\s*\)/g;
      m.forEachElement((x, e) => {
        const loader = e.local === "configuration-properties" || (M.ns(e) === "secure-properties" && e.local === "config");
        for (const a of e.attrs) {
          if (loader && (a.local === "file" || a.local === "key")) continue;
          for (const ph of M.placeholders(a.value)) { const k = stripSecure(ph); if (!first.has(k)) first.set(k, [x.file, e.line]); }
        }
        if (!e.kids.length) {
          const t = M.text(e);
          let mm;
          DW_P.lastIndex = 0;
          while ((mm = DW_P.exec(t))) { const k = stripSecure(mm[1]); if (!first.has(k)) first.set(k, [x.file, e.line + countNewlines(t, mm.index)]); }
        }
      });
      for (const d of m.dwlFiles) {
        let mm;
        DW_P.lastIndex = 0;
        while ((mm = DW_P.exec(d.text))) { const k = stripSecure(mm[1]); if (!first.has(k)) first.set(k, [d, d.lineOf(mm.index)]); }
      }
      for (const [key, [file, line]] of first) {
        if (!key || defined.has(key) || RUNTIME_PROVIDED.has(key)) continue;
        if (key.startsWith("mule.") || key.startsWith("anypoint.") || key.startsWith("sys.")) continue;
        if (key.includes("${") || key.includes("#[")) continue;
        c.report(file, line, `Property '${key}' is used but not defined in any property file`);
      }
    },
    "CFG-04"(m, c) {
      if (m.layout === "JAR" && !m.propertyFiles.length) return;
      const names = new Set();
      for (const pf of m.propertyFiles) {
        const p = pf.file.path;
        names.add(p);
        names.add(pf.file.name);
        const i = p.indexOf("src/main/resources/");
        if (i >= 0) names.add(p.slice(i + 19));
      }
      m.forEachElement((x, e) => {
        const loader = e.local === "configuration-properties" || (M.ns(e) === "secure-properties" && e.local === "config");
        if (!loader) return;
        const file = M.attr(e, "file");
        if (file == null || !file.trim() || M.isExpression(file)) return;
        let src = "^(.*/)?", last = 0, mm;
        const re = /\$\{[^}]+\}/g;
        while ((mm = re.exec(file))) { src += quoteRe(file.slice(last, mm.index)) + "[^/]+"; last = mm.index + mm[0].length; }
        const rx = new RegExp(src + quoteRe(file.slice(last)) + "$");
        if (![...names].some((n) => rx.test(n))) c.report(x.file, e, `Property file '${file}' is declared but not found in the package`);
      });
    },
    "ERR-01"(m, c) {
      if (!m.topLevel("flow").length) return;
      let ref = null, refFile = null, refEl = null;
      const top = new Set();
      for (const x of m.muleConfigs) {
        for (const e of x.root.kids) {
          if (M.isCore(e, "configuration") && M.attr(e, "defaultErrorHandler-ref") != null) { ref = M.attr(e, "defaultErrorHandler-ref"); refFile = x; refEl = e; }
          if (M.isCore(e, "error-handler") && M.attr(e, "name") != null) top.add(M.attr(e, "name"));
        }
      }
      if (ref == null) c.report(m.muleConfigs[0].file, 0, 'No <configuration defaultErrorHandler-ref="..."/> found in any config file');
      else if (!top.has(ref)) c.report(refFile.file, refEl, `defaultErrorHandler-ref points to '${ref}', but no top-level <error-handler> has that name`);
    },
    "ERR-02"(m, c) {
      m.forEachElement((x, e) => {
        if (M.isCore(e, "on-error-continue") && !e.kids.length) {
          const type = M.attr(e, "type");
          c.report(x.file, e, `Empty on-error-continue${type == null ? "" : " for " + type} swallows the error without logging or a response`);
        }
      });
    },
    "ERR-03"(m, c) {
      const routers = [];
      let rf = null;
      m.forEachElement((x, e) => { if (M.is(e, "apikit", "router")) { routers.push(e); if (!rf) rf = x; } });
      if (!routers.length) return;
      const handled = new Set();
      m.forEachElement((x, e) => { if (isHandler(e) && M.attr(e, "type") != null) for (const t of M.attr(e, "type").split(",")) handled.add(t.trim().toUpperCase()); });
      const missing = ["APIKIT:BAD_REQUEST", "APIKIT:NOT_FOUND", "APIKIT:METHOD_NOT_ALLOWED", "APIKIT:NOT_ACCEPTABLE", "APIKIT:UNSUPPORTED_MEDIA_TYPE", "APIKIT:NOT_IMPLEMENTED"].filter((t) => !handled.has(t));
      if (missing.length) c.report(rf.file, routers[0], "APIkit router present but these error types are not handled: " + missing.join(", "));
    },
    "ERR-04"(m, c) {
      m.forEachElement((x, e) => {
        if (!M.isCore(e, "error-handler")) return;
        const hs = e.kids.filter(isHandler);
        for (let i = 0; i < hs.length - 1; i++) {
          const type = M.attr(hs[i], "type"), when = M.attr(hs[i], "when");
          if ((type == null || !type.trim() || type.trim().toUpperCase() === "ANY") && (when == null || !when.trim())) {
            c.report(x.file, hs[i], `Catch-all handler is followed by ${hs.length - 1 - i} handler(s) that can never run`);
            break;
          }
        }
      });
    },
    "LOG-01"(m, c) {
      if (m.log4j2 && m.log4j2.file.text.includes("correlationId")) return;
      let json = false;
      m.forEachElement((x, e) => { if (M.ns(e).includes("json-logger")) json = true; });
      if (json) return;
      m.forEachElement((x, e) => {
        if (!M.isCore(e, "logger")) return;
        const msg = M.attr(e, "message");
        if (msg == null || !msg.trim()) return;
        if (!msg.includes("correlationId")) c.report(x.file, e, "Logger message does not include the correlation ID");
      });
    },
    "LOG-02"(m, c) {
      const WHOLE = /#\[\s*(?:write\s*\(\s*)?payload\s*(?:as\s+\w+\s*)?(?:[,)\]]|$)/;
      m.forEachElement((x, e) => {
        if (!M.isCore(e, "logger")) return;
        const level = M.attr(e, "level");
        const lv = level == null ? "INFO" : level.toUpperCase();
        if (lv === "DEBUG" || lv === "TRACE") return;
        const msg = M.attr(e, "message");
        if (msg != null && WHOLE.test(msg)) c.report(x.file, e, `Logger prints the whole payload at ${lv} level`);
      });
    },
    "LOG-03"(m, c) {
      if (!m.log4j2) {
        if (m.muleConfigs.length) c.report(null, 0, "No log4j2.xml found in the package");
        return;
      }
      const l = m.log4j2;
      let async = false;
      M.walk(l.root, (e) => {
        if (["AsyncRoot", "AsyncLogger", "Async"].includes(e.local)) async = true;
        if (e.local === "Root" || e.local === "AsyncRoot") {
          const level = M.attr(e, "level");
          if (level != null && ["DEBUG", "TRACE", "ALL"].includes(level.toUpperCase())) c.report(l.file, e, "Root logger level is " + level);
        }
      });
      if (!async) c.report(l.file, l.root, "log4j2.xml uses synchronous loggers only (no AsyncRoot / AsyncLogger)");
    },
    "STR-01"(m, c) {
      const max = c.intParam("flowMaxProcessors", 25);
      topFlows(m, (x, f) => {
        const n = countProcessors(f);
        if (n > max) c.report(x.file, f, `'${M.attr(f, "name")}' has ${n} processors (limit ${max})`);
      });
    },
    "STR-02"(m, c) {
      const refs = new Set();
      let dynamic = false;
      let text = "";
      m.forEachElement((x, e) => {
        if (M.isCore(e, "flow-ref")) {
          const n = M.attr(e, "name");
          if (n == null || M.isExpression(n) || M.hasPlaceholder(n)) dynamic = true;
          else refs.add(n);
        }
        for (const a of e.attrs) if (a.local.toLowerCase() === "flowref" || a.local.endsWith("-ref") || a.local === "flowName") refs.add(a.value);
        if (!e.kids.length) text += M.text(e) + "\n";
      });
      if (dynamic) return;
      for (const d of m.dwlFiles) text += d.text + "\n";
      topFlows(m, (x, f) => {
        const flow = M.isCore(f, "flow");
        const name = M.attr(f, "name");
        if (name == null || refs.has(name)) return;
        if (flow && (M.source(f) != null || M.isApikitFlowName(name) || name.includes(":\\"))) return;
        if (text.includes("'" + name + "'") || text.includes('"' + name + '"')) return;
        c.report(x.file, f, `${flow ? "Flow" : "Sub-flow"} '${name}' is never referenced`);
      });
    },
    "STR-03"(m, c) {
      const SKIP = new Set(["flow", "sub-flow", "configuration", "configuration-properties", "global-property", "autodiscovery", "import", "notifications", "object", "description", "spring:config", "error-handler"]);
      const defs = [];
      for (const x of m.muleConfigs) {
        for (const g of x.root.kids) {
          if (SKIP.has(g.local) && (M.ns(g) === "core" || M.ns(g) === "api-gateway")) continue;
          if (M.ns(g) === "secure-properties" || M.ns(g) === "spring") continue;
          if (M.attr(g, "name") != null) defs.push([g, x]);
        }
      }
      if (!defs.length) return;
      const defSet = new Set(defs.map((d) => d[0]));
      const values = new Set();
      m.forEachElement((x, e) => { for (const a of e.attrs) { if (a.local === "name" && defSet.has(e)) continue; values.add(a.value); } });
      for (const t of m.munitConfigs) M.walk(t.root, (e) => { for (const a of e.attrs) values.add(a.value); });
      for (const [g, x] of defs) {
        const name = M.attr(g, "name");
        if (!values.has(name)) c.report(x.file, g, `Global element <${g.tag} name="${name}"> is never referenced`);
      }
    },
    "STR-04"(m, c) {
      const files = m.muleConfigs.filter((x) => x.root.kids.some((g) => M.ns(g) !== "core" && (g.local.endsWith("config") || g.local.endsWith("-config"))));
      if (files.length > 1) c.report(files[0].file, 0, `Connector configurations are spread across ${files.length} files: ${files.map((x) => x.file.name).join(", ")}`);
    },
    "STR-05"(m, c) {
      topFlows(m, (x, f) => {
        const n = countProcessors(f) - (M.source(f) != null ? 1 : 0);
        if (n <= 0) c.report(x.file, f, `'${M.attr(f, "name")}' has no processors`);
      });
    },
    "STR-06"(m, c) {
      for (const e of m.parseErrors) c.report(e.file, e.line, "XML could not be parsed: " + e.message);
    },
    "NAM-01"(m, c) {
      const p = compileFull(c.param("flowNameRegex"), DEFAULT_PARAMS.flowNameRegex);
      topFlows(m, (x, f) => {
        const name = M.attr(f, "name");
        if (name == null || M.isApikitFlowName(name) || name.includes(":\\")) return;
        if (!p.re.test(name)) c.report(x.file, f, `Flow name '${name}' does not match ${p.src}`);
      });
    },
    "NAM-02"(m, c) {
      const p = compileFull(c.param("variableNameRegex"), DEFAULT_PARAMS.variableNameRegex);
      const seen = new Set();
      m.forEachElement((x, e) => {
        let v = null;
        if (M.isCore(e, "set-variable")) v = M.attr(e, "variableName");
        else if (e.local === "set-variable" && M.ns(e) === "ee") v = M.attr(e, "variableName");
        else if (M.has(e, "target")) v = M.attr(e, "target");
        if (v == null || !v.trim() || M.isExpression(v) || M.hasPlaceholder(v)) return;
        if (!p.re.test(v) && !seen.has(v)) {
          seen.add(v);
          c.report(x.file, e, `Variable '${v}' does not match ${p.src}`);
        }
      });
    },
    "NAM-03"(m, c) {
      for (const x of m.muleConfigs) if (!/^[a-z0-9]+(-[a-z0-9]+)*\.xml$/.test(x.file.name)) c.report(x.file, 0, `File name '${x.file.name}' is not kebab-case`);
    },
    "DW-01"(m, c) {
      const max = c.intParam("inlineDataWeaveMaxLines", 30);
      m.forEachElement((x, e) => {
        if (!isInlineScript(e) || M.has(e, "resource")) return;
        const script = M.text(e).trim();
        if (!script) return;
        const lines = script.split(/\r?\n/).length;
        if (lines > max) c.report(x.file, e, `Inline DataWeave script has ${lines} lines (limit ${max})`);
      });
    },
    "DW-02"(m, c) {
      m.forEachElement((x, e) => {
        if (!isInlineScript(e) || M.has(e, "resource")) return;
        const s = M.text(e);
        for (const off of missingElse(s)) c.report(x.file, e.line + countNewlines(s, off), "match expression has no 'else ->' case");
      });
      for (const d of m.dwlFiles) for (const off of missingElse(d.text)) c.report(d, d.lineOf(off), "match expression has no 'else ->' case");
    },
    "DW-03"(m, c) {
      if (!m.dwlFiles.length) return;
      let xml = "";
      for (const x of m.muleConfigs) xml += x.file.text + "\n";
      for (const x of m.munitConfigs) xml += x.file.text + "\n";
      for (const d of m.dwlFiles) {
        let text = xml;
        for (const o of m.dwlFiles) if (o !== d) text += o.text + "\n";
        let rel = d.path;
        const i = rel.indexOf("src/main/resources/");
        if (i >= 0) rel = rel.slice(i + 19);
        const module = rel.replace(/\.dwl$/, "").split("/").join("::");
        const used = text.includes(rel) || text.includes(d.name) || new RegExp("\\b" + quoteRe(module) + "\\b").test(text);
        if (!used) c.report(d, 0, `'${rel}' is not referenced by any flow or script`);
      }
    },
    "PRF-01"(m, c) {
      const reqs = [];
      m.forEachElement((x, e) => { if (M.is(e, "http", "request")) reqs.push(e); });
      m.forEachElement((x, e) => {
        if (!M.is(e, "http", "request-config") || M.has(e, "responseTimeout")) return;
        const name = M.attr(e, "name");
        let all = true, used = false;
        for (const r of reqs) if (name != null && name === M.attr(r, "config-ref")) { used = true; if (!M.has(r, "responseTimeout")) all = false; }
        if (!used || !all) c.report(x.file, e, `<http:request-config name="${name}"> has no responseTimeout`);
      });
    },
    "PRF-02"(m, c) {
      const NS = new Set(["db", "sftp", "ftp", "ftps", "salesforce", "jms", "ibm-mq", "amqp", "email", "sockets", "kafka", "mongo", "redis", "sap", "netsuite", "servicenow", "workday", "s3", "sqs", "sns", "dynamodb", "http"]);
      for (const x of m.muleConfigs) {
        for (const g of x.root.kids) {
          if (!NS.has(M.ns(g)) || M.is(g, "http", "listener-config")) continue;
          for (const conn of g.kids) {
            if (!conn.local.endsWith("connection")) continue;
            if (!M.descendants(conn).some((d) => ["reconnection", "reconnect", "reconnect-forever"].includes(d.local))) {
              c.report(x.file, g, `<${g.tag} name="${M.attr(g, "name")}"> has no reconnection strategy`);
            }
          }
        }
      }
    },
    "PRF-03"(m, c) {
      m.forEachElement((x, e) => {
        if (!M.isCore(e, "foreach")) return;
        const d = M.descendants(e).find((d) => M.ns(d) !== "core" && M.ns(d) !== "ee" && M.has(d, "config-ref"));
        if (d) c.report(x.file, e, `For Each calls <${d.tag}> once per item`);
      });
    },
    "PRF-04"(m, c) {
      m.forEachElement((x, e) => {
        if (!M.isCore(e, "fixed-frequency")) return;
        const f = M.attr(e, "frequency");
        if (!M.isLiteral(f) || !/^\s*-?\d+\s*$/.test(f)) return;
        const freq = parseInt(f, 10);
        const unit = (M.attr(e, "timeUnit") || "MILLISECONDS").toUpperCase();
        const ms = { SECONDS: freq * 1000, MINUTES: freq * 60000, HOURS: freq * 3600000, DAYS: freq * 86400000, MICROSECONDS: Math.trunc(freq / 1000), NANOSECONDS: Math.trunc(freq / 1000000) }[unit] ?? freq;
        if (ms < 5000) c.report(x.file, e, `Scheduler runs every ${ms} ms`);
      });
    },
    "DEP-01"(m, c) {
      const runtime = m.info.runtimeVersion, min = c.param("minRuntimeVersion");
      if (runtime == null || min == null) return;
      try {
        if (compareVersions(runtime, min) < 0) {
          const file = m.pom ? m.pom.file : m.muleArtifactJson;
          let line = 0;
          if (file) {
            const ls = file.lines();
            for (let i = 0; i < ls.length; i++) if (ls[i].includes(runtime)) { line = i + 1; break; }
          }
          c.report(file, line, `Mule runtime ${runtime} is below the baseline ${min}`);
        }
      } catch (e) {
        /* unparseable version */
      }
    },
    "DEP-02"(m, c) {
      if (!m.pom) return;
      const pom = m.pom;
      const art = M.descendants(pom.root).find((e) => e.local === "artifactId" && M.text(e).trim() === "munit-maven-plugin");
      if (!art) c.report(pom.file, 0, "munit-maven-plugin is not configured in pom.xml");
      else if (!/requiredApplicationCoverage|requiredResourceCoverage|requiredFlowCoverage/.test(pom.file.text)) c.report(pom.file, art.parent, "MUnit runs without a required coverage threshold");
      if (m.layout !== "JAR" && !m.munitConfigs.length) c.report(null, 0, "No MUnit test suites found under src/test/munit");
    },
    "DEP-03"(m, c) {
      if (!m.pom) return;
      const props = m.pomProperties();
      for (const e of M.descendants(m.pom.root)) {
        if (e.local !== "dependency" && e.local !== "plugin") continue;
        const version = childText(e, "version"), artifact = childText(e, "artifactId");
        if (version == null) continue;
        let resolved = version;
        if (version.startsWith("${") && version.endsWith("}")) resolved = props.get(version.slice(2, -1)) ?? version;
        if (resolved.toUpperCase().includes("SNAPSHOT")) c.report(m.pom.file, e, `${e.local} ${artifact} uses SNAPSHOT version ${resolved}`);
      }
    },
  };

  // ------------------------------------------------------------------ scoring

  function score(findings) {
    const per = new Map();
    for (const f of findings) {
      const cur = per.get(f.ruleId) || { pts: 0, sev: f.severity };
      cur.pts += SEV[f.severity].pts;
      cur.sev = f.severity;
      per.set(f.ruleId, cur);
    }
    let lost = 0;
    for (const v of per.values()) lost += Math.min(v.pts, SEV[v.sev].cap);
    return Math.round(100 * Math.exp(-lost / 100));
  }
  function grade(findings) {
    const s = score(findings);
    let g = s >= 90 ? "A" : s >= 75 ? "B" : s >= 60 ? "C" : "D";
    if (findings.some((f) => f.severity === "BLOCKER") && (g === "A" || g === "B")) g = "C";
    return g;
  }
  function categoryScores(findings) {
    const out = {};
    for (const c of CATEGORIES) out[c] = score(findings.filter((f) => f.category === c));
    return out;
  }
  function topFixes(findings, limit = 3) {
    const by = new Map();
    for (const f of findings) {
      if (!by.has(f.ruleId)) by.set(f.ruleId, []);
      by.get(f.ruleId).push(f);
    }
    const cur = score(findings);
    const out = [];
    for (const [rule, fs] of by) {
      const gain = score(findings.filter((f) => f.ruleId !== rule)) - cur;
      if (gain > 0) out.push({ ruleId: rule, title: fs[0].title, severity: fs[0].severity, findings: fs.length, pointsGained: gain });
    }
    out.sort((a, b) => b.pointsGained - a.pointsGained || byPath(a.ruleId, b.ruleId));
    return out.slice(0, limit);
  }

  async function sha24(s) {
    const buf = await root.crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return [...new Uint8Array(buf).slice(0, 12)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function baseName(n) {
    if (!n || !n.trim()) return "mule-app";
    n = n.replace(/\\/g, "/");
    n = n.slice(n.lastIndexOf("/") + 1);
    const d = n.lastIndexOf(".");
    return d > 0 ? n.slice(0, d) : n;
  }

  /** files: Map(entryName -> text). config: {disabled: [ids], severities: {id: SEV}, params: {...}} */
  async function analyzeFiles(files, originalName, config = {}) {
    const t0 = Date.now();
    const names = [...files.keys()].map((n) => n.toLowerCase());
    const mule4 = names.some((n) => n.endsWith("mule-artifact.json"));
    const mule3 = names.some((l) => l.endsWith("mule-deploy.properties") || l === "mule-app.properties" || (l.endsWith("/mule-app.properties") && !l.includes("src/main/resources")));
    if (mule3 && !mule4) throw new UserError("This looks like a Mule 3 application. MuleLint checks Mule 4 apps only.");
    const model = buildModel(files, baseName(originalName));
    if (!model.muleConfigs.length) {
      if (model.parseErrors.length) {
        const e = model.parseErrors[0];
        throw new UserError(`No Mule configuration could be parsed. First error in ${e.file.path}: ${e.message}`);
      }
      throw new UserError("No Mule 4 configuration files found. Upload the deployable JAR built by mule-maven-plugin, or a ZIP of the project (pom.xml + src/main/mule).");
    }
    const disabled = new Set(config.disabled || []);
    const findings = [];
    const ctx = new Ctx(config, findings);
    const ruleErrors = [];
    for (const meta of RULE_META) {
      if (disabled.has(meta.id)) continue;
      ctx.begin(meta);
      try {
        RULES[meta.id](model, ctx);
      } catch (e) {
        ruleErrors.push(meta.id + ": " + e);
      }
    }
    for (const f of findings) {
      f.fingerprint = await sha24(f._fp);
      delete f._fp;
    }
    findings.sort((a, b) => SEV[a.severity].o - SEV[b.severity].o || byPath(a.ruleId, b.ruleId) || byPath(a.file, b.file) || a.line - b.line);
    return {
      project: model.info,
      findings,
      score: score(findings),
      grade: grade(findings),
      categoryScores: categoryScores(findings),
      stats: {
        muleConfigFiles: model.muleConfigs.length,
        flows: model.topLevel("flow").length,
        subFlows: model.topLevel("sub-flow").length,
        propertyFiles: model.propertyFiles.length,
        dataWeaveFiles: model.dwlFiles.length,
        munitFiles: model.munitConfigs.length,
        durationMillis: Date.now() - t0,
      },
      ruleErrors,
    };
  }

  async function analyzeArchive(data, originalName, config, JSZipLib) {
    return analyzeFiles(await readArchive(data, JSZipLib), originalName, config);
  }

  const api = { RULE_META, CATEGORIES, DEFAULT_PARAMS, SEV, UserError, analyzeFiles, analyzeArchive, readArchive, score, grade, categoryScores, topFixes, mask, redact };
  root.MuleLint = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
