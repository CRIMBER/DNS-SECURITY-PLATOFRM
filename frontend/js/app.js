/* Security operations console.
 *
 * Every value rendered here is fetched from the backend:
 *   POST /api/analyze   full pipeline, returns the decision and its factors
 *   GET  /api/stats     aggregates computed from stored events
 *   GET  /api/events    the event log
 *   GET  /api/health    engine status and component provenance
 *
 * The DNS Security view lives in js/dns.js and reads /api/dns/*.
 *
 * There are no hardcoded statistics anywhere in this file.
 */

(function () {
  "use strict";

  var STATUS = {
    SAFE:       "var(--safe)",
    SUSPICIOUS: "var(--warning)",
    MALICIOUS:  "var(--critical)",
    ALLOW:      "var(--safe)",
    MONITOR:    "var(--warning)",
    BLOCK:      "var(--critical)",
    TRUSTED:    "var(--safe)",
    UNKNOWN:    "var(--info)"
  };

  var STATUS_LEGEND = [
    { label: "Safe / allowed", color: "var(--safe)" },
    { label: "Suspicious / monitored", color: "var(--warning)" },
    { label: "Malicious / blocked", color: "var(--critical)" }
  ];

  var $ = function (id) { return document.getElementById(id); };

  function el(tag, className, text) {
    var n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function panel(title) {
    var p = el("div", "panel");
    if (title) p.appendChild(el("h2", null, title));
    return p;
  }

  function scoreColor(score) {
    if (score >= 70) return "var(--critical)";
    if (score >= 30) return "var(--warning)";
    return "var(--safe)";
  }

  function shortTime(iso) {
    // "2026-08-25T16:28:04Z" -> "16:28:04"
    return (iso || "").slice(11, 19) || iso;
  }

  function request(path, options) {
    return fetch(path, options).then(function (response) {
      return response.json().then(function (data) {
        return { ok: response.ok, status: response.status, data: data };
      });
    });
  }

  function post(path, body) {
    return request(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  }

  /* =====================================================================
   * Tabs
   * ===================================================================== */

  var VIEWS = ["overview", "analyse", "activity", "dns", "analytics"];

  function showTab(name) {
    VIEWS.forEach(function (view) {
      $("view-" + view).classList.toggle("hidden", view !== name);
    });
    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (tab) {
      tab.classList.toggle("active", tab.getAttribute("data-tab") === name);
    });
    if (name === "overview" || name === "analytics") loadStats();
    if (name === "activity") loadEvents();
    if (name === "dns" && window.DNSView) window.DNSView.load();
    if (name === "analyse") $("domainInput").focus();
  }

  /* =====================================================================
   * Overview + analytics
   * ===================================================================== */

  function tile(key, value, sub, color) {
    var t = el("div", "tile");
    t.appendChild(el("div", "tile-k", key));
    var v = el("div", "tile-v", value);
    if (color) v.style.color = color;
    t.appendChild(v);
    if (sub) t.appendChild(el("div", "tile-sub", sub));
    return t;
  }

  function renderTiles(stats) {
    var host = $("tiles");
    host.innerHTML = "";
    var total = stats.total_analyzed;
    var pct = function (n) {
      return total ? Math.round((n / total) * 100) + "% of traffic" : "no events yet";
    };

    host.appendChild(tile("Total analysed", total, "requests processed"));
    host.appendChild(tile("Allowed", stats.allowed, pct(stats.allowed), "var(--safe)"));
    host.appendChild(tile("Suspicious", stats.monitored, pct(stats.monitored), "var(--warning)"));
    host.appendChild(tile("Blocked", stats.blocked, pct(stats.blocked), "var(--critical)"));
    host.appendChild(tile("Threats detected", stats.threats_detected,
      "suspicious + malicious", "var(--critical)"));
  }

  function renderDecisionChart(stats) {
    Charts.horizontalBars($("decisionChart"), [
      { label: "Allowed",   value: stats.by_decision.ALLOW || 0,   color: "var(--safe)" },
      { label: "Monitored", value: stats.by_decision.MONITOR || 0, color: "var(--warning)" },
      { label: "Blocked",   value: stats.by_decision.BLOCK || 0,   color: "var(--critical)" }
    ], { labelWidth: 110, legend: STATUS_LEGEND });
  }

  function renderTopDomains(stats) {
    var host = $("topDomains");
    host.innerHTML = "";
    if (!stats.top_risky_domains.length) {
      return Charts.empty(host, "No domain has scored 30 or above yet.");
    }
    var wrap = el("div", "table-scroll");
    var table = el("table");
    var head = el("tr");
    ["Domain", "Risk", "Classification", "Seen"].forEach(function (h) {
      head.appendChild(el("th", null, h));
    });
    table.appendChild(head);

    stats.top_risky_domains.forEach(function (row) {
      var tr = el("tr");
      tr.appendChild(el("td", "mono", row.domain));
      var score = el("td", "num", row.risk_score);
      score.style.color = scoreColor(row.risk_score);
      tr.appendChild(score);
      var cls = el("td");
      cls.appendChild(el("span", "badge badge-" + row.classification, row.classification));
      tr.appendChild(cls);
      tr.appendChild(el("td", "num", row.hits));
      table.appendChild(tr);
    });
    wrap.appendChild(table);
    host.appendChild(wrap);
  }

  function renderPerformance(stats) {
    var host = $("performance");
    host.innerHTML = "";
    var p = stats.performance;
    var grid = el("div", "features");
    [
      ["mean", p.mean_analysis_time_ms + " ms"],
      ["p95", p.p95_analysis_time_ms + " ms"],
      ["fastest", p.fastest_ms + " ms"],
      ["slowest", p.slowest_ms + " ms"]
    ].forEach(function (pair) {
      var cell = el("div", "feature");
      cell.appendChild(el("div", "feature-k", pair[0]));
      cell.appendChild(el("div", "feature-v", pair[1]));
      grid.appendChild(cell);
    });
    host.appendChild(grid);
    host.appendChild(el("div", "note", p.note));
  }

  function renderRiskChart(stats) {
    var items = stats.risk_distribution.map(function (bucket) {
      var band = bucket.min >= 70 ? "MALICIOUS"
               : bucket.min >= 30 ? "SUSPICIOUS" : "SAFE";
      return {
        label: bucket.range,
        value: bucket.count,
        color: STATUS[band],
        note: "(" + band.toLowerCase() + " band)"
      };
    });
    Charts.columns($("riskChart"), items, { legend: STATUS_LEGEND });
  }

  function renderCategoryChart(stats) {
    // Magnitude by category, so ONE hue - these encode counts, not identity.
    var entries = Object.keys(stats.threat_categories).map(function (key) {
      return { label: key.replace(/_/g, " "), value: stats.threat_categories[key],
               color: "var(--accent)" };
    });
    Charts.horizontalBars($("categoryChart"), entries.slice(0, 8), {
      labelWidth: 170,
      emptyMessage: "No threat-intelligence categories recorded yet."
    });
  }

  function renderVerdictChart(stats) {
    var verdicts = stats.by_threat_intel_verdict || {};
    var order = ["MALICIOUS", "SUSPICIOUS", "TRUSTED", "UNKNOWN"];
    var items = order.filter(function (key) { return verdicts[key]; })
      .map(function (key) {
        return { label: key, value: verdicts[key], color: STATUS[key] };
      });
    Charts.horizontalBars($("verdictChart"), items, {
      labelWidth: 130,
      emptyMessage: "No lookups recorded yet.",
      legend: [
        { label: "Malicious", color: "var(--critical)" },
        { label: "Suspicious", color: "var(--warning)" },
        { label: "Trusted", color: "var(--safe)" },
        { label: "Unknown (no data held)", color: "var(--info)" }
      ]
    });
  }

  function renderActivityChart(stats) {
    var buckets = stats.activity.map(function (row) {
      return {
        label: shortTime(row.hour + "").slice(0, 5) || row.hour.slice(11, 16),
        segments: [
          { key: "safe", value: row.SAFE || 0, color: "var(--safe)" },
          { key: "suspicious", value: row.SUSPICIOUS || 0, color: "var(--warning)" },
          { key: "malicious", value: row.MALICIOUS || 0, color: "var(--critical)" }
        ]
      };
    });
    Charts.stackedColumns($("activityChart"), buckets, {
      legend: STATUS_LEGEND,
      emptyMessage: "No activity in the last 24 hours."
    });
  }

  function loadStats() {
    return request("/api/stats").then(function (response) {
      if (!response.ok) return;
      var stats = response.data;
      renderTiles(stats);
      renderDecisionChart(stats);
      renderTopDomains(stats);
      renderPerformance(stats);
      renderRiskChart(stats);
      renderCategoryChart(stats);
      renderVerdictChart(stats);
      renderActivityChart(stats);
    });
  }

  /* =====================================================================
   * Recent activity
   * ===================================================================== */

  function loadEvents() {
    var params = new URLSearchParams({ limit: "100" });
    var q = $("eventSearch").value.trim();
    var cls = $("classFilter").value;
    var dec = $("decisionFilter").value;
    if (q) params.set("q", q);
    if (cls) params.set("classification", cls);
    if (dec) params.set("decision", dec);

    return request("/api/events?" + params.toString()).then(function (response) {
      if (!response.ok) return;
      var data = response.data;
      $("eventCount").textContent = "(" + data.events.length + " of " + data.total + ")";

      var host = $("eventsTable");
      host.innerHTML = "";
      if (!data.events.length) {
        return Charts.empty(host, "No events match. Analyse a domain to create one.");
      }

      var wrap = el("div", "table-scroll");
      var table = el("table");
      var head = el("tr");
      ["Time", "Domain", "Risk", "Classification", "Action", "Threat intel", "Top factor", "ms"]
        .forEach(function (h) { head.appendChild(el("th", null, h)); });
      table.appendChild(head);

      data.events.forEach(function (event) {
        var tr = el("tr");
        tr.appendChild(el("td", "mono", shortTime(event.timestamp)));
        tr.appendChild(el("td", "mono", event.domain));

        var score = el("td", "num", event.risk_score);
        score.style.color = scoreColor(event.risk_score);
        tr.appendChild(score);

        var cls = el("td");
        cls.appendChild(el("span", "badge badge-" + event.classification, event.classification));
        tr.appendChild(cls);

        var dec = el("td");
        dec.appendChild(el("span", "badge badge-" + event.decision, event.decision));
        tr.appendChild(dec);

        tr.appendChild(el("td", "mono", event.threat_intelligence_verdict));
        tr.appendChild(el("td", null,
          event.top_factors.length ? event.top_factors[0].label : "-"));
        tr.appendChild(el("td", "num", event.analysis_time_ms.toFixed(2)));
        table.appendChild(tr);
      });

      wrap.appendChild(table);
      host.appendChild(wrap);
    });
  }

  /* =====================================================================
   * Domain analysis
   * ===================================================================== */

  function renderVerdict(result) {
    var p = panel(null);
    var row = el("div", "verdict");

    var score = el("div", "verdict-score");
    score.textContent = result.risk_score;
    score.style.color = scoreColor(result.risk_score);
    score.appendChild(el("small", null, " / 100"));
    row.appendChild(score);

    var meta = el("div", "verdict-meta");
    meta.appendChild(el("div", "domain-name", result.domain));

    var bits = "registrable: " + result.registrable_domain;
    bits += "   |   analysed in " + result.analysis_time_ms + " ms";
    meta.appendChild(el("div", "domain-meta", bits));

    var badges = el("div", "verdict-badges");
    badges.appendChild(el("span", "badge badge-" + result.classification, result.classification));
    badges.appendChild(el("span", "badge badge-" + result.decision, result.decision));
    meta.appendChild(badges);
    row.appendChild(meta);
    p.appendChild(row);

    var action = el("div", "action");
    action.appendChild(el("b", null, "Recommended action"));
    action.appendChild(document.createTextNode(result.recommended_action));
    p.appendChild(action);
    return p;
  }

  function renderFactors(result) {
    var p = panel("Risk Factors");
    var sum = 0;
    result.risk_factors.forEach(function (factor) {
      sum += factor.contribution;
      var row = el("div", "factor sev-" + factor.severity);
      row.appendChild(el("div", "factor-pts",
        factor.contribution > 0 ? "+" + factor.contribution.toFixed(1)
        : factor.contribution < 0 ? factor.contribution.toFixed(1) : "0"));
      var body = el("div", "factor-body");
      body.appendChild(el("div", "factor-label", factor.label));
      body.appendChild(el("div", "factor-detail", factor.detail));
      row.appendChild(body);
      p.appendChild(row);
    });
    p.appendChild(el("div", "note",
      "Contributions sum to " + sum.toFixed(1) + ", which is the final risk score of " +
      result.risk_score + ". The explanation is the computation, not a description " +
      "written after it."));
    return p;
  }

  function renderSignals(result) {
    var p = panel("Signal Fusion");
    var wrap = el("div", "table-scroll");
    var table = el("table");
    var head = el("tr");
    ["Signal", "Score", "Confidence", "Weight", "Contribution", "In fusion"]
      .forEach(function (h) { head.appendChild(el("th", null, h)); });
    table.appendChild(head);

    result.signals.forEach(function (signal) {
      var tr = el("tr", "signal-row" + (signal.used_in_fusion ? "" : " excluded"));
      tr.appendChild(el("td", null, signal.name));
      tr.appendChild(el("td", "num", signal.score.toFixed(1)));
      tr.appendChild(el("td", "num", signal.confidence.toFixed(2)));
      tr.appendChild(el("td", "num", signal.weight.toFixed(2)));
      tr.appendChild(el("td", "num", signal.weighted_contribution.toFixed(2)));
      tr.appendChild(el("td", null, signal.used_in_fusion ? "yes" : "excluded"));
      table.appendChild(tr);
    });
    wrap.appendChild(table);
    p.appendChild(wrap);

    var excluded = result.signals.filter(function (s) { return !s.used_in_fusion; });
    if (excluded.length) {
      p.appendChild(el("div", "note",
        "The " + excluded.map(function (s) { return s.name; }).join(", ") +
        " signal reported confidence 0.00 and was excluded from the weighted " +
        "average entirely. That is an absence of evidence, not evidence of " +
        "safety - the remaining signals decided this verdict on their own."));
    }
    if (result.overrides_applied.length) {
      p.appendChild(el("div", "note",
        "Policy overrides applied after fusion: " + result.overrides_applied.join(", ") + "."));
    }
    return p;
  }

  function renderIntel(result) {
    var p = panel("Threat Intelligence");
    var ti = result.threat_intelligence;
    p.appendChild(el("span", "badge badge-" + ti.verdict, ti.verdict));

    var dl = el("dl", "kv");
    dl.style.marginTop = "15px";
    function row(k, v) { dl.appendChild(el("dt", null, k)); dl.appendChild(el("dd", null, v)); }
    row("Matched indicator", ti.matched_indicator || "none");
    row("Match type", ti.match_type || "no match");
    row("Categories", ti.categories.length ? ti.categories.join(", ") : "none");
    row("Source confidence", (ti.confidence * 100).toFixed(0) + "%");
    row("Dataset", ti.source);
    if (ti.first_seen) row("First seen", ti.first_seen);
    p.appendChild(dl);
    if (ti.description) p.appendChild(el("div", "note", ti.description));
    return p;
  }

  function renderDGA(result) {
    var p = panel("DGA / Suspicion Analysis");
    var dga = result.dga_analysis;
    var pct = dga.score * 100;

    var head = el("div");
    head.style.cssText = "display:flex;align-items:baseline;gap:10px;margin-bottom:10px";
    var num = el("span", null, dga.score.toFixed(2));
    num.style.cssText = "font-family:var(--mono);font-size:32px;font-weight:700;color:" + scoreColor(pct);
    head.appendChild(num);
    head.appendChild(el("span", "muted", "suspicion (0.00 - 1.00)"));
    p.appendChild(head);

    var bar = el("div", "bar");
    var fill = el("div", "bar-fill");
    fill.style.width = Math.min(100, pct) + "%";
    fill.style.background = scoreColor(pct);
    bar.appendChild(fill);
    p.appendChild(bar);

    var dl = el("dl", "kv");
    dl.style.marginTop = "15px";
    function row(k, v) { dl.appendChild(el("dt", null, k)); dl.appendChild(el("dd", null, v)); }
    var c = dga.components;
    row("Model", dga.model + " (" + dga.model_type + ")");
    row("Bigram log-likelihood", c.bigram_llr.toFixed(3));
    row("Deviation from normal", c.z_score.toFixed(2) + " sigma");
    row("Length factor", c.length_factor.toFixed(2));
    row("Word coverage", (c.dictionary_word_coverage * 100).toFixed(0) + "%");
    if (dga.top_contributors.length) row("Contributors", dga.top_contributors.join(", "));
    p.appendChild(dl);
    p.appendChild(el("div", "note", dga.notes));
    return p;
  }

  function renderTunnel(result) {
    var t = result.tunnel_analysis || {};
    if (!t.indicators || !t.indicators.length) return null;

    var p = panel("DNS Tunnelling Analysis");
    p.appendChild(el("span", "badge badge-MALICIOUS",
      t.indicators.length + " INDICATOR" + (t.indicators.length > 1 ? "S" : "")));

    var dl = el("dl", "kv");
    dl.style.marginTop = "15px";
    function row(k, v) { dl.appendChild(el("dt", null, k)); dl.appendChild(el("dd", null, v)); }
    var m = t.measurements || {};
    row("Indicators", t.indicators.join(", "));
    row("Subdomain length", m.subdomain_length);
    row("Labels", m.subdomain_label_count);
    row("Longest label", m.longest_label);
    row("Subdomain entropy", m.subdomain_entropy);
    if (m.encoding_alphabet) row("Encoding alphabet", m.encoding_alphabet);
    if (m.query_type) row("Record type", m.query_type);
    row("Signal score", t.score + " / 100");
    row("Signal confidence", t.confidence);
    p.appendChild(dl);
    p.appendChild(el("div", "note",
      "Transparent rule-based detector (" + t.model_type + "). Measures the "
      + "query name for traces a covert channel leaves behind."));
    return p;
  }

  function renderBehavioral(result) {
    var b = result.behavioral_analysis || {};
    var o = b.observations || {};
    if (!o.history_available || !o.queries_in_window) return null;

    var p = panel("Behavioural Analysis");
    if (b.indicators && b.indicators.length) {
      p.appendChild(el("span", "badge badge-MALICIOUS", b.indicators.join(", ").toUpperCase()));
    } else {
      p.appendChild(el("span", "badge badge-SAFE", "NO ANOMALIES"));
    }

    var dl = el("dl", "kv");
    dl.style.marginTop = "15px";
    function row(k, v) { dl.appendChild(el("dt", null, k)); dl.appendChild(el("dd", null, v)); }
    row("Window", o.window_minutes + " minutes");
    row("Queries seen", o.queries_in_window);
    row("Distinct names", o.distinct_subdomains);
    row("Failed lookups", o.nxdomain_responses);
    if (o.nxdomain_ratio !== undefined) row("Failure ratio", o.nxdomain_ratio);
    row("Blocked before", o.blocked_before);
    row("Signal score", b.score + " / 100");
    row("Signal confidence", b.confidence);
    p.appendChild(dl);
    p.appendChild(el("div", "note",
      "Judged by what this domain has DONE, not what it is called. Abstains "
      + "with confidence 0.00 until enough history exists to say anything."));
    return p;
  }

  var FEATURE_VIEW = [
    ["length", "length"], ["entropy", "entropy"], ["sld_entropy", "label entropy"],
    ["digit_ratio", "digit ratio"], ["hyphen_count", "hyphens"],
    ["subdomain_count", "subdomains"], ["max_consonant_run", "consonant run"],
    ["vowel_ratio", "vowel ratio"], ["dictionary_word_coverage", "word coverage"],
    ["unique_char_ratio", "unique chars"], ["tld_risk_weight", "TLD abuse weight"],
    ["label_count", "labels"]
  ];

  function renderFeatures(result) {
    var p = panel("Extracted Features");
    var grid = el("div", "features");
    FEATURE_VIEW.forEach(function (pair) {
      var value = result.domain_features[pair[0]];
      if (value === undefined) return;
      var cell = el("div", "feature");
      cell.appendChild(el("div", "feature-k", pair[1]));
      cell.appendChild(el("div", "feature-v", value));
      grid.appendChild(cell);
    });
    p.appendChild(grid);

    var kw = result.domain_features.suspicious_keywords;
    if (kw && kw.length) {
      p.appendChild(el("div", "note", "Phishing-associated keywords: " + kw.join(", ")));
    }
    return p;
  }

  function renderError(error) {
    var box = el("div", "error");
    box.appendChild(el("div", "error-code", error.code || "ERROR"));
    box.appendChild(el("div", null, error.message || "Something went wrong."));
    if (error.detail) box.appendChild(el("div", "muted", error.detail));
    $("results").innerHTML = "";
    $("results").appendChild(box);
  }

  function analyse() {
    var domain = $("domainInput").value.trim();
    if (!domain) {
      return renderError({ code: "EMPTY_INPUT", message: "Please enter a domain name." });
    }

    var button = $("analyzeBtn");
    button.disabled = true;
    $("results").innerHTML = "";
    $("results").appendChild(el("div", "panel muted", "Analysing " + domain + "…"));

    post("/api/analyze", { domain: domain, source: "dashboard" })
      .then(function (response) {
        button.disabled = false;
        if (!response.ok) return renderError(response.data.error || {});

        var result = response.data;
        var host = $("results");
        host.innerHTML = "";
        host.appendChild(renderVerdict(result));
        host.appendChild(renderFactors(result));
        host.appendChild(renderSignals(result));
        host.appendChild(renderIntel(result));
        host.appendChild(renderDGA(result));
        var tunnelPanel = renderTunnel(result);
        if (tunnelPanel) host.appendChild(tunnelPanel);
        var behavioralPanel = renderBehavioral(result);
        if (behavioralPanel) host.appendChild(behavioralPanel);
        host.appendChild(renderFeatures(result));
        loadStats();     // the event this created is now part of the numbers
      })
      .catch(function (err) {
        button.disabled = false;
        renderError({
          code: "NETWORK_ERROR",
          message: "Could not reach the analysis engine.",
          detail: String(err)
        });
      });
  }

  /* Shared helpers for the DNS view module (js/dns.js). Exposed rather than
     duplicated, so both views render badges, tiles and timestamps identically. */
  window.UI = {
    $: $, el: el, panel: panel, tile: tile,
    scoreColor: scoreColor, shortTime: shortTime,
    request: request, STATUS: STATUS, STATUS_LEGEND: STATUS_LEGEND
  };

  /* =====================================================================
   * Wiring
   * ===================================================================== */

  $("tabs").addEventListener("click", function (event) {
    var tab = event.target.closest(".tab");
    if (tab) showTab(tab.getAttribute("data-tab"));
  });

  $("analyzeBtn").addEventListener("click", analyse);
  $("domainInput").addEventListener("keydown", function (e) {
    if (e.key === "Enter") analyse();
  });

  Array.prototype.forEach.call(document.querySelectorAll(".chip"), function (chip) {
    chip.addEventListener("click", function () {
      $("domainInput").value = chip.getAttribute("data-domain");
      analyse();
    });
  });

  ["eventSearch", "classFilter", "decisionFilter"].forEach(function (id) {
    var element = $(id);
    element.addEventListener(id === "eventSearch" ? "input" : "change", loadEvents);
  });

  $("refreshBtn").addEventListener("click", function () {
    loadStats();
    loadEvents();
    if (window.DNSView) window.DNSView.load();
  });

  /* Live mode: poll the backend every few seconds. Off by default, because a
     dashboard that silently refetches makes it hard to read a result. */
  var liveTimer = null;

  function refreshCurrentView() {
    var active = document.querySelector(".tab.active");
    var name = active ? active.getAttribute("data-tab") : "overview";
    if (name === "overview" || name === "analytics") loadStats();
    if (name === "activity") loadEvents();
    if (name === "dns" && window.DNSView) window.DNSView.load();
  }

  $("autoRefresh").addEventListener("change", function (event) {
    var label = event.target.closest(".toggle");
    if (event.target.checked) {
      label.classList.add("live-on");
      refreshCurrentView();
      liveTimer = window.setInterval(refreshCurrentView, 5000);
    } else {
      label.classList.remove("live-on");
      if (liveTimer) window.clearInterval(liveTimer);
      liveTimer = null;
    }
  });

  $("clearBtn").addEventListener("click", function () {
    if (!window.confirm("Delete all stored analysis events? This cannot be undone.")) return;
    request("/api/events", { method: "DELETE" }).then(function () {
      loadEvents();
      loadStats();
    });
  });

  request("/api/health").then(function (response) {
    if (!response.ok) {
      $("statusLine").textContent = "engine unreachable";
      return;
    }
    var health = response.data;
    var ti = health.components.threat_intelligence;
    var dga = health.components.dga_detector;
    $("statusLine").innerHTML =
      "engine <b>" + health.status + "</b> &middot; v" + health.version +
      " &middot; risk policy <b>v" + health.risk_config_version + "</b>" +
      " &middot; <b>" + ti.indicators_total + "</b> indicators, <b>" +
      ti.trusted_domains + "</b> trusted &middot; DGA <b>" + dga.model +
      "</b> (" + dga.corpus_size + "-label corpus, no accuracy claimed)" +
      " &middot; fusion <b>" + health.components.risk_engine.fusion + "</b>" +
      " &middot; DNS gateway <b>" + health.components.dns_gateway.status + "</b>" +
      (health.components.dns_gateway.listen_address
        ? " on " + health.components.dns_gateway.listen_address : "");
  }).catch(function () {
    $("statusLine").textContent = "engine unreachable";
  });

  loadStats();
})();
