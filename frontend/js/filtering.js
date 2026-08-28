/* DNS Filtering view: the resolution pipeline, and a box to push a name
 * through it.
 *
 * The test box calls POST /api/analyze - the same endpoint the Domain
 * Analysis view uses and the same pipeline the DNS gateway runs per query.
 * The pipeline diagram is drawn from what the backend reports about itself
 * (cache state, protocols, gateway status), so a stage cannot be shown as
 * live when it is not running.
 */

(function () {
  "use strict";

  var UI = window.UI;
  var $ = UI.$, el = UI.el, request = UI.request;

  var EXAMPLES = [
    "github.com",
    "malware-c2-panel.test",
    "xjqzwvbnmk4d8f2.top",
    "aGVsbG93b3JsZGRhdGFleGZpbA.dGhpc2lzZGF0YQ.tunnel.test",
    "192.168.1.10"
  ];

  /* Stage list mirrors the order in backend/app/dns_gateway/handler.py.
     `key` names the backend fact that decides whether a stage is live. */
  var STAGES = [
    { key: "query",    title: "DNS QUERY",            detail: "UDP or TCP on the gateway port. Parsed with dnspython." },
    { key: "cache",    title: "CACHE CHECK",          detail: "Bounded TTL-aware LRU of upstream answers." },
    { key: "intel",    title: "THREAT INTELLIGENCE",  detail: "Indicator lookup, exact and parent-domain." },
    { key: "analysis", title: "AI / ML ANALYSIS",     detail: "DGA (bigram_llr_v1), lexical, tunnelling, behavioural." },
    { key: "fusion",   title: "RISK SCORE",           detail: "Confidence-weighted fusion of every reporting signal." },
    { key: "decision", title: "ALLOW / MONITOR / BLOCK", detail: "Score against the configured decision bands." },
    { key: "response", title: "DNS RESPONSE",         detail: "Upstream answer, or the configured block response." }
  ];

  function pipelineDiagram(state) {
    var wrap = el("div", "pipeline");
    STAGES.forEach(function (stage, index) {
      var node = el("div", "pipe-stage");
      var head = el("div", "pipe-head");
      head.appendChild(el("span", "pipe-num", index + 1));
      head.appendChild(el("span", "pipe-title", stage.title));
      var badge = state[stage.key];
      if (badge) head.appendChild(el("span", "badge badge-" + badge.cls, badge.text));
      node.appendChild(head);
      node.appendChild(el("div", "pipe-detail", stage.detail));
      wrap.appendChild(node);
      if (index < STAGES.length - 1) wrap.appendChild(el("div", "pipe-arrow", "↓"));
    });
    return wrap;
  }

  function loadPipeline() {
    return request("/api/dns/status").then(function (response) {
      var d = response.ok ? response.data : {};
      var cache = d.cache || {};
      var running = !!d.running;
      var state = {
        query: running
          ? { cls: "ALLOW", text: (d.protocol || "udp").toUpperCase() + " LIVE" }
          : { cls: "UNKNOWN", text: "GATEWAY OFF" },
        cache: cache.enabled
          ? { cls: "ALLOW", text: "ENABLED" }
          : { cls: "UNKNOWN", text: "DISABLED" },
        intel: { cls: "ALLOW", text: "LOCAL DATASET" },
        analysis: { cls: "ALLOW", text: "ACTIVE" },
        fusion: { cls: "ALLOW", text: "ACTIVE" },
        decision: { cls: "ALLOW", text: "ACTIVE" },
        response: running
          ? { cls: "ALLOW", text: "POLICY " + (d.block_policy || "-") }
          : { cls: "UNKNOWN", text: "API ONLY" }
      };
      var host = $("pipelineDiagram");
      host.innerHTML = "";
      host.appendChild(pipelineDiagram(state));
      if (!running) {
        host.appendChild(el("div", "note",
          "The DNS gateway is not bound right now, so stages 1 and 7 are not "
          + "serving live queries. Stages 2-6 are the analysis path and run on "
          + "every request to this page. " + (d.bind_error || "")));
      }
      return d;
    });
  }

  /* -- protocols, cache, performance ------------------------------------ */

  function loadProtocols() {
    return request("/api/protocols").then(function (response) {
      var host = $("protocolList");
      host.innerHTML = "";
      if (!response.ok) return;
      var CLASS = { ACTIVE: "ALLOW", CONFIGURED: "MONITOR", NOT_IMPLEMENTED: "UNKNOWN" };
      response.data.protocols.forEach(function (p) {
        var row = el("div", "proto-row");
        var left = el("div");
        left.appendChild(el("span", "proto-name", p.short));
        left.appendChild(el("span", "muted", "  " + p.name + "  ·  port " + p.port));
        row.appendChild(left);
        row.appendChild(el("span", "badge badge-" + (CLASS[p.state] || "UNKNOWN"),
                           p.state.replace(/_/g, " ")));
        host.appendChild(row);
        host.appendChild(el("div", "proto-detail", p.detail));
      });
      host.appendChild(el("div", "note", response.data.note));
    });
  }

  function kv(host, pairs) {
    var dl = el("dl", "kv");
    pairs.forEach(function (pair) {
      if (pair[1] === undefined || pair[1] === null) return;
      dl.appendChild(el("dt", null, pair[0]));
      dl.appendChild(el("dd", null, pair[1]));
    });
    host.appendChild(dl);
  }

  function loadCache(status) {
    var host = $("cachePanel");
    host.innerHTML = "";
    var cache = (status && status.cache) || null;
    if (!cache) {
      host.appendChild(el("span", "badge badge-UNKNOWN", "NO GATEWAY"));
      host.appendChild(el("div", "note",
        "Cache statistics come from the running gateway process. It is not "
        + "running, so there are none to report - rather than showing zeros "
        + "that would look like a cold cache."));
      return;
    }
    host.appendChild(el("span", "badge badge-" + (cache.enabled ? "ALLOW" : "UNKNOWN"),
                        cache.enabled ? "ENABLED" : "DISABLED"));
    var total = (cache.hits || 0) + (cache.misses || 0);
    kv(host, [
      ["Hit rate", total ? (cache.hit_rate * 100).toFixed(1) + "%" : "no lookups yet"],
      ["Cache hits", cache.hits],
      ["Cache misses", cache.misses],
      ["Cached records", cache.entries + " / " + cache.max_entries],
      ["Max TTL held", cache.max_ttl_seconds + " s"],
      ["Evictions", cache.evictions],
      ["Expirations", cache.expirations]
    ]);
    host.appendChild(el("div", "note", cache.note));
  }

  function loadPerformance() {
    return request("/api/dns/stats").then(function (response) {
      var host = $("performancePanel");
      host.innerHTML = "";
      if (!response.ok) return;
      var p = response.data.performance || {};
      var measured = p.measured_queries || 0;
      if (!measured) {
        host.appendChild(el("span", "badge badge-UNKNOWN", "NO MEASUREMENTS"));
        host.appendChild(el("div", "note",
          "No DNS query has been through the gateway yet, so there is no "
          + "latency to report. Send one and this fills in."));
        return;
      }
      var TARGET = 100;
      var pass = p.mean_total_gateway_time_ms <= TARGET;
      var tiles = el("div", "tiles");
      [
        ["Average", p.mean_total_gateway_time_ms],
        ["P95", p.p95_total_gateway_time_ms],
        ["P99", p.p99_total_gateway_time_ms],
        ["Analysis only", p.mean_analysis_time_ms]
      ].forEach(function (pair) {
        var t = el("div", "tile");
        t.appendChild(el("div", "tile-k", pair[0]));
        var v = el("div", "tile-v", pair[1].toFixed(1));
        v.style.color = pair[1] <= TARGET ? "var(--safe)" : "var(--warning)";
        t.appendChild(v);
        t.appendChild(el("div", "tile-sub", "ms"));
        tiles.appendChild(t);
      });
      host.appendChild(tiles);
      var verdict = el("div", "perf-verdict");
      verdict.appendChild(el("span", "muted", "Target: end-to-end under " + TARGET + " ms  —  "));
      verdict.appendChild(el("span", "badge badge-" + (pass ? "ALLOW" : "MONITOR"),
                             pass ? "PASS" : "OVER TARGET"));
      verdict.appendChild(el("span", "muted", "  measured over " + measured + " gateway queries"));
      host.appendChild(verdict);
      host.appendChild(el("div", "note", p.note));
    });
  }

  /* -- the filter test box ---------------------------------------------- */

  function line(host, label, value, cls) {
    var row = el("div", "filter-line");
    row.appendChild(el("div", "filter-k", label));
    var v = el("div", "filter-v", value);
    if (cls) v.className = "filter-v " + cls;
    row.appendChild(v);
    host.appendChild(row);
  }

  function renderResult(result) {
    var host = $("filterResult");
    host.innerHTML = "";

    var verdict = el("div", "panel filter-verdict");
    var score = el("div", "verdict-score", result.risk_score);
    score.style.color = UI.scoreColor(result.risk_score);
    score.appendChild(el("small", null, " / 100"));
    verdict.appendChild(score);
    var meta = el("div", "verdict-meta");
    meta.appendChild(el("div", "domain-name", result.domain));
    var badges = el("div", "verdict-badges");
    badges.appendChild(el("span", "badge badge-" + result.decision, result.decision));
    badges.appendChild(el("span", "badge badge-" + result.classification, result.classification));
    meta.appendChild(badges);
    verdict.appendChild(meta);
    host.appendChild(verdict);

    var panel = el("div", "panel");
    panel.appendChild(el("h2", null, "Filter Decision"));

    var ti = result.threat_intelligence || {};
    var dga = result.dga_analysis || {};
    var tunnel = result.tunnel_analysis || {};
    var behavioural = result.behavioral_analysis || {};
    var signal = function (name) {
      var list = result.signals || [];
      for (var i = 0; i < list.length; i++) if (list[i].name === name) return list[i];
      return null;
    };
    var dgaSignal = signal("dga");
    var tunnelSignal = signal("tunnel");

    line(panel, "Threat Intelligence",
      ti.verdict === "UNKNOWN" ? "CLEAN (no indicator match)" : ti.verdict,
      ti.verdict === "MALICIOUS" ? "bad" : ti.verdict === "TRUSTED" ? "good" : "");
    line(panel, "AI / ML Risk", result.risk_score + " / 100");
    line(panel, "DGA",
      dgaSignal && !dgaSignal.used_in_fusion
        ? "NOT DETECTED (" + (dga.components && dga.components.bigram_llr !== undefined
            ? "suspicion " + dga.score.toFixed(2) + ", below threshold"
            : "not applicable to this name") + ")"
        : "DETECTED — suspicion " + dga.score.toFixed(2) + " (" + dga.model + ")",
      dgaSignal && dgaSignal.used_in_fusion ? "bad" : "");
    line(panel, "DNS Tunnelling",
      (tunnel.indicators && tunnel.indicators.length)
        ? "DETECTED — " + tunnel.indicators.join(", ")
        : "NOT DETECTED",
      (tunnel.indicators && tunnel.indicators.length) ? "bad" : "");
    line(panel, "Behavioural",
      (behavioural.indicators && behavioural.indicators.length)
        ? "ANOMALY — " + behavioural.indicators.join(", ")
        : "no anomaly in the observed window",
      (behavioural.indicators && behavioural.indicators.length) ? "bad" : "");
    line(panel, "Final Decision", result.decision,
      result.decision === "BLOCK" ? "bad" : result.decision === "ALLOW" ? "good" : "");
    line(panel, "Reason", result.risk_factors && result.risk_factors.length
      ? result.risk_factors[0].label : "no contributing factor");
    line(panel, "Processing Time", result.analysis_time_ms + " ms");
    line(panel, "Recommended Action", result.recommended_action);

    var stages = result.stage_timings_ms || {};
    var breakdown = Object.keys(stages).map(function (k) {
      return k + " " + stages[k].toFixed(2) + "ms";
    }).join("   ·   ");
    if (breakdown) {
      panel.appendChild(el("div", "note", "Stage timings: " + breakdown));
    }
    panel.appendChild(el("div", "note",
      "This is the same pipeline the DNS gateway runs for every query it "
      + "answers. The score, the decision and the timings above were computed "
      + "just now by the backend - nothing on this page is precomputed."));
    host.appendChild(panel);
  }

  function analyse() {
    var domain = ($("filterInput").value || "").trim();
    if (!domain) return;
    var button = $("filterBtn");
    button.disabled = true;
    $("filterResult").innerHTML = "";
    $("filterResult").appendChild(el("div", "panel muted", "Filtering " + domain + "…"));

    request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: domain, source: "filtering" })
    }).then(function (response) {
      button.disabled = false;
      if (!response.ok) {
        var e = (response.data && response.data.error) || {};
        var box = el("div", "panel error");
        box.appendChild(el("div", "error-code", e.code || "ERROR"));
        box.appendChild(el("div", null, e.message || "The domain could not be analysed."));
        if (e.detail) box.appendChild(el("div", "muted", e.detail));
        $("filterResult").innerHTML = "";
        $("filterResult").appendChild(box);
        return;
      }
      renderResult(response.data);
      loadPerformance();
    }).catch(function (err) {
      button.disabled = false;
      var box = el("div", "panel error");
      box.appendChild(el("div", "error-code", "RENDER_ERROR"));
      box.appendChild(el("div", null, "The analysis returned but could not be displayed."));
      box.appendChild(el("div", "muted", String(err)));
      $("filterResult").innerHTML = "";
      $("filterResult").appendChild(box);
    });
  }

  function renderExamples() {
    var host = $("filterExamples");
    if (host.childNodes.length) return;
    host.appendChild(el("span", "muted", "try: "));
    EXAMPLES.forEach(function (name) {
      var chip = el("button", "chip", name.length > 34 ? name.slice(0, 31) + "…" : name);
      chip.title = name;
      chip.addEventListener("click", function () {
        $("filterInput").value = name;
        analyse();
      });
      host.appendChild(chip);
    });
  }

  function load() {
    renderExamples();
    loadPipeline().then(loadCache);
    loadProtocols();
    loadPerformance();
  }

  /* Scripts load at the end of <body>, so the elements exist already - the
     same assumption app.js makes for its own controls. */
  $("filterBtn").addEventListener("click", analyse);
  $("filterInput").addEventListener("keydown", function (e) {
    if (e.key === "Enter") analyse();
  });

  window.FilteringView = { load: load };
})();
