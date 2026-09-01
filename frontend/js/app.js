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

  var VIEWS = ["overview", "filtering", "analyse", "capture", "intel",
               "activity", "dns", "analytics", "logs"];

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
    if (name === "filtering" && window.FilteringView) window.FilteringView.load();
    if (name === "capture" && window.CaptureView) window.CaptureView.load();
    if (name === "intel" && window.IntelView) window.IntelView.load();
    if (name === "logs" && window.LogsView) window.LogsView.load();
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
    host.appendChild(tile("Threats detected", stats.threats_detected,
      "suspicious + malicious", "var(--critical)"));
    host.appendChild(tile("Blocked", stats.blocked, pct(stats.blocked), "var(--critical)"));
    host.appendChild(tile("Monitored", stats.monitored, pct(stats.monitored), "var(--warning)"));
    host.appendChild(tile("Allowed", stats.allowed, pct(stats.allowed), "var(--safe)"));

    // Same measurement the Measured Performance panel prints, promoted to a
    // tile. Omitted rather than shown as zero when nothing has been timed yet.
    var perf = stats.performance || {};
    if (perf.mean_analysis_time_ms !== undefined && perf.mean_analysis_time_ms !== null) {
      host.appendChild(tile("Avg latency", perf.mean_analysis_time_ms.toFixed(2) + " ms",
        "mean, server-side"));
    }
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

  /* =====================================================================
   * Abstention
   *
   * A detector reporting confidence 0.00 is saying "I have no information
   * about this name" - not "this name is safe", and emphatically not
   * "something went wrong". The API returns 200 with a complete body for
   * these, so the dashboard must render them as the ordinary successful
   * results they are.
   *
   * Reaching for a measurement that was never taken used to throw here,
   * abort the whole render, and surface as "Could not reach the analysis
   * engine" - for a backend that had answered perfectly. Every detector
   * panel below therefore states abstention explicitly instead of guessing
   * at numbers or quietly disappearing.
   * ===================================================================== */

  /* Each signal emits its own INFO-severity factor carrying the reason it
     abstained, so the wording shown to an analyst is the backend's own
     sentence rather than something this file invented. */
  var FACTOR_PREFIX = {
    threat_intel: "TI_",
    dga:          "DGA_",
    lexical:      "LEXICAL_",
    tunnel:       "DNS_TUNNEL_",
    behavioral:   "BEHAVIORAL_"
  };

  function signalOf(result, name) {
    var list = result.signals || [];
    for (var i = 0; i < list.length; i++) {
      if (list[i].name === name) return list[i];
    }
    return null;
  }

  function isAbstaining(result, name) {
    var signal = signalOf(result, name);
    return !!signal && !signal.used_in_fusion;
  }

  function abstentionReason(result, name) {
    var prefix = FACTOR_PREFIX[name];
    var factors = result.risk_factors || [];
    for (var i = 0; i < factors.length; i++) {
      if (prefix && factors[i].code.indexOf(prefix) === 0 && factors[i].detail) {
        return factors[i].detail;
      }
    }
    return "This detector reported no usable information about this name.";
  }

  function kvRows(pairs) {
    var dl = el("dl", "kv");
    dl.style.marginTop = "15px";
    pairs.forEach(function (pair) {
      if (pair[1] === undefined || pair[1] === null) return;
      dl.appendChild(el("dt", null, pair[0]));
      dl.appendChild(el("dd", null, pair[1]));
    });
    return dl;
  }

  function abstentionNote() {
    return el("div", "note",
      "Abstaining is a successful analysis, not an error. The signal is "
      + "removed from BOTH sides of the weighted average, so it neither "
      + "raises nor lowers the score - the signals that did have evidence "
      + "decide the verdict on their own.");
  }

  /* Uniform panel for a detector that declined to contribute.
   *
   * `measured` separates the two kinds of abstention, which must not be
   * displayed the same way:
   *   false - the detector never ran, because this name has nothing for it
   *           to read (an IP literal has no registrant label). There is no
   *           number; printing "0" would be inventing a measurement.
   *   true  - the detector ran, found nothing, and still abstains, because
   *           finding no anomaly is not evidence of safety. The value it
   *           measured is shown, labelled as measured-but-not-used.
   */
  function abstentionPanel(title, result, signalName, measured, extraPairs) {
    var signal = signalOf(result, signalName);
    var p = panel(title);
    p.appendChild(el("span", "badge badge-ABSTAIN", "ABSTAINED"));

    var pairs = [
      ["Reported score", measured && signal
        ? signal.score.toFixed(1) + " / 100  (measured, not used as evidence)"
        : "not measured - this detector did not run on this name"],
      ["Confidence", (signal ? signal.confidence.toFixed(2) : "0.00")
        + "  (no information, not a claim of safety)"],
      ["Weight in fusion", signal
        ? signal.weight.toFixed(2) + "  (declared weight, unused here)" : "-"],
      ["Used in fusion", "no - excluded from the weighted average"]
    ];
    p.appendChild(kvRows(pairs.concat(extraPairs || [])));
    p.appendChild(el("div", "note", abstentionReason(result, signalName)));
    p.appendChild(abstentionNote());
    return p;
  }

  var KIND_LABEL = {
    REGISTRY_DOMAIN: "Registrable domain",
    PROVIDER_HOST:   "Host inside a provider namespace",
    INFRASTRUCTURE:  "Infrastructure / reverse-DNS name",
    LOCAL_NAME:      "Local / special-use name",
    IP_LITERAL:      "IP address literal",
    SINGLE_LABEL:    "Single label, no public suffix",
    MALFORMED:       "Malformed name"
  };

  var SCOPE_LABEL = {
    full_name:          "full name",
    registrable_domain: "registrable domain",
    registrant_label:   "registrant label",
    delegated_span:     "delegated span",
    controlled_span:    "controlled span",
    semantic_text:      "semantic text"
  };

  /* Surfaces the classification the pipeline already made and already
     returns. Nothing here is recomputed in the browser - if the field is
     absent the panel is omitted rather than guessed at. */
  function renderClassification(result) {
    var nc = (result.domain_features || {}).name_classification;
    if (!nc) return null;

    var p = panel("Name Classification");
    p.appendChild(el("span", "badge badge-KIND", nc.kind));

    var scopes = nc.scopes || {};
    var spans = Object.keys(scopes)
      .filter(function (key) { return scopes[key]; })
      .map(function (key) {
        return (SCOPE_LABEL[key] || key) + " = \u201c" + scopes[key] + "\u201d";
      });

    var pairs = [
      ["Name kind", KIND_LABEL[nc.kind] || nc.kind],
      ["Public suffix", nc.public_suffix || "none"],
      ["Suffix type", nc.suffix_kind],
      ["Label chosen by", nc.scope_is_registrant_chosen
        ? "a registrant who paid for it"
        : "not a registrant - allocated, derived or never registered"],
      ["Analysis scopes", spans.length
        ? spans.join("     ") : "none - there is nothing here to analyse"]
    ];
    if (nc.unicode_form) pairs.push(["Unicode form", nc.unicode_form]);
    if (nc.scripts && nc.scripts.length) pairs.push(["Scripts", nc.scripts.join(", ")]);
    if (nc.is_reverse_dns) {
      pairs.push(["Reverse-DNS target", nc.reverse_target || "could not be decoded"]);
    }
    if (nc.ip_address) {
      pairs.push(["IP address", nc.ip_address + "  (IPv" + nc.ip_version + ")"]);
      pairs.push(["Address range", nc.ip_is_private ? "private" : "public"]);
    }
    if (nc.special_use) pairs.push(["Special-use zone", "." + nc.special_use]);
    p.appendChild(kvRows(pairs));

    p.appendChild(el("div", "note", nc.reason));
    p.appendChild(el("div", "note",
      "Classification decides WHICH SPAN of the name each detector reads. "
      + "It never allows, blocks, caps or excuses a name by itself - no "
      + "detector is disabled and no score is capped on the strength of it."));
    return p;
  }

  /* The verdict block is now drawn by renderHero() further down, which shows
     the same fields (risk_score, classification, decision, recommended_action)
     as a gauge rather than a number. The .verdict-* styles it used are still
     live: js/filtering.js draws its result with them. */

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
      tr.appendChild(el("td", null, signal.used_in_fusion ? "yes" : "ABSTAINED"));
      table.appendChild(tr);
    });
    wrap.appendChild(table);
    p.appendChild(wrap);

    var excluded = result.signals.filter(function (s) { return !s.used_in_fusion; });
    if (excluded.length) {
      p.appendChild(el("div", "note",
        excluded.length + " of " + result.signals.length + " signals reported "
        + "confidence 0.00 and were excluded from the weighted average "
        + "entirely. That is an absence of evidence, not evidence of safety - "
        + "the signals that did have evidence decided this verdict alone. "
        + "Each one states below why it had nothing to say."));
      var why = el("div", "abstain-list");
      excluded.forEach(function (s) {
        var item = el("div", "abstain-item");
        item.appendChild(el("span", "badge badge-ABSTAIN", s.name));
        item.appendChild(el("span", "abstain-why", abstentionReason(result, s.name)));
        why.appendChild(item);
      });
      p.appendChild(why);
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
    var dga = result.dga_analysis || {};
    var c = dga.components || {};
    var measured = c.bigram_llr !== undefined;
    var provenance = [["Model", (dga.model || "unknown")
      + " (" + (dga.model_type || "unknown") + ")"]];

    // No components at all means the detector declined to measure: there was
    // no registrant-chosen label to read. Reading c.bigram_llr here is what
    // threw and took the whole page down with it.
    if (!measured) {
      return abstentionPanel("DGA / Suspicion Analysis", result, "dga",
        false, provenance);
    }

    var p = panel("DGA / Suspicion Analysis");
    var pct = dga.score * 100;
    var abstains = isAbstaining(result, "dga");

    // Measured, but still abstaining: the score sits below the threshold at
    // which "this looks algorithmically generated" is a finding. Saying
    // nothing here would let a 0.02 suspicion read as a safety vote.
    if (abstains) p.appendChild(el("span", "badge badge-ABSTAIN", "ABSTAINED"));

    var head = el("div");
    head.style.cssText = "display:flex;align-items:baseline;gap:10px;margin:10px 0";
    var num = el("span", null, dga.score.toFixed(2));
    num.style.cssText = "font-family:var(--mono);font-size:32px;font-weight:700;color:"
      + scoreColor(pct);
    head.appendChild(num);
    head.appendChild(el("span", "muted", "suspicion (0.00 - 1.00)"));
    p.appendChild(head);

    var bar = el("div", "bar");
    var fill = el("div", "bar-fill");
    fill.style.width = Math.min(100, pct) + "%";
    fill.style.background = scoreColor(pct);
    bar.appendChild(fill);
    p.appendChild(bar);

    var signal = signalOf(result, "dga");
    var pairs = provenance.concat([
      ["Bigram log-likelihood", c.bigram_llr.toFixed(3)],
      ["Deviation from normal", (c.z_score || 0).toFixed(2) + " sigma"],
      ["Length factor", (c.length_factor || 0).toFixed(2)],
      ["Word coverage", ((c.dictionary_word_coverage || 0) * 100).toFixed(0) + "%"]
    ]);
    if (dga.top_contributors && dga.top_contributors.length) {
      pairs.push(["Contributors", dga.top_contributors.join(", ")]);
    }
    if (signal) {
      pairs.push(["Signal score", signal.score.toFixed(1) + " / 100"
        + (abstains ? "  (measured, not used as evidence)" : "")]);
      pairs.push(["Signal confidence", signal.confidence.toFixed(2)
        + (abstains ? "  (no information, not a claim of safety)" : "")]);
      pairs.push(["Weight in fusion", signal.weight.toFixed(2)
        + (abstains ? "  (declared weight, unused here)" : "")]);
      pairs.push(["Used in fusion", abstains
        ? "no - excluded from the weighted average" : "yes"]);
    }
    p.appendChild(kvRows(pairs));

    if (dga.notes) p.appendChild(el("div", "note", dga.notes));
    if (abstains) {
      p.appendChild(el("div", "note", abstentionReason(result, "dga")));
      p.appendChild(abstentionNote());
    }
    return p;
  }

  function renderTunnel(result) {
    var t = result.tunnel_analysis || {};
    var m = t.measurements || {};

    /* This panel used to return null whenever no indicator fired, so the
       detector vanished from the page entirely and an analyst could not tell
       "examined, found nothing" apart from "never ran". Both now say so. */
    if (!t.indicators || !t.indicators.length) {
      var couldMeasure = !m.not_applicable;
      var extra = couldMeasure
        ? [["Subdomain length", m.subdomain_length],
           ["Labels", m.subdomain_label_count],
           ["Longest label", m.longest_label],
           ["Subdomain entropy", m.subdomain_entropy]]
        : [["Name kind", m.name_kind]];
      extra.unshift(["Detector", (t.method || "unknown")
        + " (" + (t.method_type || "unknown") + ")"]);
      return abstentionPanel("DNS Tunnelling Analysis", result, "tunnel",
        couldMeasure, extra);
    }

    var p = panel("DNS Tunnelling Analysis");
    p.appendChild(el("span", "badge badge-MALICIOUS",
      t.indicators.length + " INDICATOR" + (t.indicators.length > 1 ? "S" : "")));

    var pairs = [
      ["Indicators", t.indicators.join(", ")],
      ["Subdomain length", m.subdomain_length],
      ["Labels", m.subdomain_label_count],
      ["Longest label", m.longest_label],
      ["Subdomain entropy", m.subdomain_entropy]
    ];
    if (m.encoding_alphabet) pairs.push(["Encoding alphabet", m.encoding_alphabet]);
    if (m.query_type) pairs.push(["Record type", m.query_type]);
    pairs.push(["Signal score", t.score + " / 100"]);
    pairs.push(["Signal confidence", t.confidence]);
    p.appendChild(kvRows(pairs));

    // The API field is method_type, not model_type - reading the wrong name
    // rendered the provenance label as "undefined", which is precisely the
    // claim this note exists to keep honest.
    p.appendChild(el("div", "note",
      "Transparent rule-based detector (" + t.method + " / " + t.method_type
      + "). Measures the query name for traces a covert channel leaves behind."));
    return p;
  }

  function renderBehavioral(result) {
    var b = result.behavioral_analysis || {};
    var o = b.observations || {};
    var hasHistory = !!o.history_available && !!o.queries_in_window;

    /* Same silent-disappearance problem as tunnelling: a domain with no
       history and a domain with clean history both rendered as nothing. */
    if (!b.indicators || !b.indicators.length) {
      var extra = [["Detector", (b.method || "unknown")
        + " (" + (b.method_type || "unknown") + ")"]];
      if (hasHistory) {
        extra.push(["Window", o.window_minutes + " minutes"]);
        extra.push(["Queries seen", o.queries_in_window]);
        extra.push(["Distinct names", o.distinct_subdomains]);
        extra.push(["Failed lookups", o.nxdomain_responses]);
        extra.push(["Blocked before", o.blocked_before]);
      } else {
        extra.push(["History available", o.history_available ? "yes" : "no"]);
        extra.push(["Queries in window", o.queries_in_window || 0]);
      }
      return abstentionPanel("Behavioural Analysis", result, "behavioral",
        hasHistory, extra);
    }

    var p = panel("Behavioural Analysis");
    p.appendChild(el("span", "badge badge-MALICIOUS",
      b.indicators.join(", ").toUpperCase()));

    var pairs = [
      ["Window", o.window_minutes + " minutes"],
      ["Queries seen", o.queries_in_window],
      ["Distinct names", o.distinct_subdomains],
      ["Failed lookups", o.nxdomain_responses]
    ];
    if (o.nxdomain_ratio !== undefined) pairs.push(["Failure ratio", o.nxdomain_ratio]);
    pairs.push(["Blocked before", o.blocked_before]);
    pairs.push(["Signal score", b.score + " / 100"]);
    pairs.push(["Signal confidence", b.confidence]);
    p.appendChild(kvRows(pairs));

    p.appendChild(el("div", "note",
      "Judged by what this domain has DONE, not what it is called (" + b.method
      + " / " + b.method_type + "). Abstains with confidence 0.00 until enough "
      + "history exists to say anything."));
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

  /* =====================================================================
   * Mission-control presentation layer
   *
   * Everything below is a different DRAWING of data the backend already
   * returned. No value is computed here, no threshold is applied here, and
   * no state is asserted that the payload does not contain. If a field is
   * missing the element is omitted rather than guessed at.
   * ===================================================================== */

  /* -- system status strip (from /api/health) ---------------------------- */

  /* Product state, and only product state.
   *
   * Three things a person operating this console needs to know: is the service
   * up, is DNS traffic actually being filtered, and is analysis working. Build
   * numbers, model names, corpus sizes and the fusion formula answer none of
   * those questions - they moved to Diagnostics, under Activity Log.
   *
   * DNS Protection is the one that must not flatter. It reads Active only when
   * the backend reports the gateway running; a gateway that is switched off in
   * this deployment says Disabled, and one that tried to bind and failed says
   * Unavailable. Those are three different facts and the operator needs the
   * difference. */
  function renderSysbar(health) {
    var host = $("sysbar");
    if (!host) return;
    host.innerHTML = "";
    var c = (health && health.components) || {};

    function cell(key, text, level, note) {
      var box = el("div", "sysbar-cell");
      box.appendChild(el("div", "sysbar-k", key));
      var v = el("div", "sysbar-v " + level);
      v.appendChild(el("span", "sysbar-led"));
      v.appendChild(el("span", null, text));
      box.appendChild(v);
      if (note) box.appendChild(el("div", "sysbar-note", note));
      host.appendChild(box);
    }

    var reachable = health && health.status;
    if (!reachable) {
      cell("System", "Offline", "down", "Cannot reach the service");
      return;
    }
    cell("System", health.status === "ok" ? "Online" : "Degraded",
         health.status === "ok" ? "up" : "warn");

    var gw = c.dns_gateway;
    if (gw) {
      if (gw.status === "ok") {
        cell("DNS Protection", "Active", "up", "Filtering DNS queries");
      } else if (gw.status === "disabled") {
        cell("DNS Protection", "Disabled", "off",
             "DNS gateway is not available in this deployment");
      } else {
        cell("DNS Protection", "Unavailable", "down",
             "DNS gateway is not filtering traffic");
      }
    }

    // Operational only if every part that does the analysing reports healthy.
    var parts = [c.risk_engine, c.threat_intelligence, c.dga_detector,
                 c.tunnel_detector, c.behavioral_analyzer].filter(Boolean);
    var healthy = parts.length && parts.every(function (p) {
      return p.status === undefined || p.status === "ok";
    });
    cell("Analysis Engine", healthy ? "Operational" : "Degraded",
         healthy ? "up" : "warn");
  }

  /* -- risk gauge -------------------------------------------------------- */

  var GAUGE_ARC = Math.PI * 72;   // semicircle of radius 72

  function riskGauge(score) {
    var wrap = el("div", "gauge-wrap");
    var colour = scoreColor(score);
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 168 96");

    function arc(cls) {
      var path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", "M 12 88 A 72 72 0 0 1 156 88");
      path.setAttribute("class", cls);
      return path;
    }
    svg.appendChild(arc("gauge-track"));
    var fill = arc("gauge-fill");
    fill.style.stroke = colour;
    fill.style.strokeDasharray = GAUGE_ARC + " " + GAUGE_ARC;
    // start empty, then let the CSS transition run it up to the real value
    fill.style.strokeDashoffset = GAUGE_ARC;
    svg.appendChild(fill);
    wrap.appendChild(svg);

    var num = el("div", "gauge-num", score);
    num.style.color = colour;
    wrap.appendChild(num);
    wrap.appendChild(el("div", "gauge-den", "/ 100"));

    window.requestAnimationFrame(function () {
      window.requestAnimationFrame(function () {
        fill.style.strokeDashoffset = GAUGE_ARC * (1 - Math.max(0, Math.min(100, score)) / 100);
      });
    });
    return wrap;
  }

  /* The decision, at the size it deserves. Same numbers as the old verdict
     block - risk_score, classification, decision, recommended_action - laid
     out so the verdict is the first thing read from across a room. */
  function renderHero(result) {
    var host = el("div", "hero");
    var grid = el("div", "hero-grid");

    var left = el("div", "gauge-cell");
    left.appendChild(el("div", "gauge-label", "Risk Score"));
    left.appendChild(riskGauge(result.risk_score));

    var dec = el("div", "gauge-decision");
    var verdict = el("div", "gauge-verdict");
    verdict.style.color = STATUS[result.decision] || "var(--text)";
    verdict.appendChild(el("span", "led"));
    verdict.appendChild(el("span", null, result.decision));
    dec.appendChild(verdict);
    dec.appendChild(el("div", "gauge-class", result.classification));
    left.appendChild(dec);
    grid.appendChild(left);

    var body = el("div", "hero-body");
    body.appendChild(el("div", "hero-domain", result.domain));

    var meta = el("div", "hero-meta");
    function fact(k, v) {
      var d = el("div");
      d.appendChild(el("b", null, k + " "));
      d.appendChild(document.createTextNode(v));
      meta.appendChild(d);
    }
    fact("REGISTRABLE", result.registrable_domain || "-");
    fact("ELAPSED", result.analysis_time_ms + " ms");
    if (result.confidence !== undefined) {
      fact("EVIDENCE COVERAGE", (result.confidence * 100).toFixed(0) + "%");
    }
    body.appendChild(meta);

    var action = el("div", "action");
    action.appendChild(el("b", null, "Recommended action"));
    action.appendChild(document.createTextNode(result.recommended_action));
    body.appendChild(action);

    grid.appendChild(body);
    host.appendChild(grid);
    return host;
  }

  /* -- evidence pipeline ------------------------------------------------- */

  /* One node per stage the backend actually runs, in the order it runs them.
     `state` is derived only from what the payload says: a detector that
     abstained is IDLE and grey, never green - "found nothing" is not
     evidence of safety, which is the rule the whole engine is built on. */
  function pipelineStages(result) {
    var t = result.stage_timings_ms || {};
    var ti = result.threat_intelligence || {};
    var dga = result.dga_analysis || {};
    var tun = result.tunnel_analysis || {};
    var beh = result.behavioral_analysis || {};
    var nc = (result.domain_features || {}).name_classification;

    function sigState(name, hitText, quietText) {
      var s = signalOf(result, name);
      if (!s || !s.used_in_fusion) return { state: "idle", text: "ABSTAINED" };
      if (s.score >= 70) return { state: "hit", text: hitText };
      if (s.score >= 30) return { state: "warn", text: hitText };
      return { state: "active", text: quietText };
    }

    var tiState = ti.verdict === "MALICIOUS" ? { state: "hit", text: "MALICIOUS" }
      : ti.verdict === "SUSPICIOUS" ? { state: "warn", text: "SUSPICIOUS" }
      : ti.verdict === "TRUSTED" ? { state: "clear", text: "TRUSTED" }
      : { state: "idle", text: "NO MATCH" };

    var dgaS = sigState("dga", "DGA LIKELY", "LOW SUSPICION");
    var lexS = sigState("lexical", "SUSPICIOUS", "NORMAL");
    var tunS = (tun.indicators && tun.indicators.length)
      ? { state: "hit", text: "DETECTED" } : { state: "idle", text: "NONE" };
    var behS = (beh.indicators && beh.indicators.length)
      ? { state: "hit", text: "ANOMALY" } : { state: "idle", text: "NONE" };

    var used = (result.signals || []).filter(function (s) { return s.used_in_fusion; });

    return [
      { name: "DNS Query", state: "active", text: "PARSED", ms: (t.normalize || 0) + (t.features || 0),
        detail: nc ? (KIND_LABEL[nc.kind] || nc.kind) : result.registrable_domain },
      { name: "Threat Intelligence", state: tiState.state, text: tiState.text, ms: t.threat_intel,
        detail: ti.matched_indicator
          ? "matched " + ti.matched_indicator + " (" + (ti.match_type || "match") + ")"
          : (ti.description || "") },
      { name: "DGA Analysis", state: dgaS.state, text: dgaS.text, ms: t.dga,
        detail: dga.score !== undefined
          ? "suspicion " + dga.score.toFixed(2) + " · " + (dga.model || "model") : "" },
      { name: "Lexical Analysis", state: lexS.state, text: lexS.text, ms: t.lexical,
        detail: (function () {
          var s = signalOf(result, "lexical");
          return s ? "signal " + s.score.toFixed(0) + " / 100" : "";
        })() },
      { name: "DNS Tunnelling", state: tunS.state, text: tunS.text, ms: t.tunnel,
        detail: (tun.indicators && tun.indicators.length)
          ? tun.indicators.join(", ") : (tun.method || "") },
      { name: "Behavioural Analysis", state: behS.state, text: behS.text, ms: t.behavioral,
        detail: (beh.indicators && beh.indicators.length)
          ? beh.indicators.join(", ")
          : (beh.observations && beh.observations.queries_in_window !== undefined
             ? beh.observations.queries_in_window + " queries in the last "
               + beh.observations.window_minutes + " min" : "") },
      { name: "Risk Fusion", state: "active", text: used.length + " / " + (result.signals || []).length + " SIGNALS",
        ms: t.risk_engine,
        detail: "confidence-weighted average of the signals that reported"
          + (result.overrides_applied && result.overrides_applied.length
             ? " · overrides: " + result.overrides_applied.join(", ") : "") },
      { name: "Final Decision",
        state: result.decision === "BLOCK" ? "hit"
             : result.decision === "MONITOR" ? "warn" : "clear",
        text: result.decision, ms: null,
        detail: "score " + result.risk_score + " / 100 → " + result.classification }
    ];
  }

  function renderEvidencePipeline(result) {
    var p = panel("Detection Pipeline");
    var pipe = el("div", "evpipe");

    pipelineStages(result).forEach(function (stage, i) {
      if (i) pipe.appendChild(el("div", "evrail", "↓"));
      var node = el("div", "evnode is-" + stage.state);

      // Every cell is emitted even when empty, so all eight rows keep the
      // same five columns and the strip stays aligned down the page.
      node.appendChild(el("span", "evdot"));
      node.appendChild(el("div", "evname", stage.name));
      var detail = el("div", "evdetail", stage.detail || "");
      if (stage.detail) detail.title = stage.detail;   // full text on hover
      node.appendChild(detail);
      node.appendChild(el("div", "evtime",
        stage.ms === null || stage.ms === undefined ? "" : stage.ms.toFixed(3) + " ms"));
      node.appendChild(el("div", "evstate " + stage.state, stage.text));

      pipe.appendChild(node);
    });

    p.appendChild(pipe);
    p.appendChild(el("div", "note",
      "Stage timings are the backend's own perf_counter measurements from "
      + "stage_timings_ms. A grey node means the detector abstained: it "
      + "reported no usable information and was removed from the weighted "
      + "average entirely, which is not the same as reporting safety."));
    return p;
  }

  /* -- evidence cards ---------------------------------------------------- */

  function evidenceCard(key, state, text, sub) {
    var card = el("div", "evcard is-" + state);
    card.appendChild(el("div", "evcard-k", key));
    var v = el("div", "evcard-v");
    v.style.color = state === "hit" ? "#e26a6a"
      : state === "warn" ? "#dda32e"
      : state === "clear" ? "#35bf35" : "#94a3b8";
    v.appendChild(el("span", "led"));
    v.appendChild(el("span", null, text));
    card.appendChild(v);
    if (sub) card.appendChild(el("div", "evcard-sub", sub));
    return card;
  }

  function renderEvidenceCards(result) {
    var p = panel("Evidence Summary");
    var wrap = el("div", "evcards");

    var ti = result.threat_intelligence || {};
    wrap.appendChild(evidenceCard("Threat Intelligence",
      ti.verdict === "MALICIOUS" ? "hit" : ti.verdict === "SUSPICIOUS" ? "warn"
        : ti.verdict === "TRUSTED" ? "clear" : "idle",
      ti.verdict || "UNKNOWN",
      ti.matched_indicator
        ? ti.matched_indicator + (ti.categories && ti.categories.length
            ? " · " + ti.categories.join(", ") : "")
        : "no indicator match in " + (ti.source || "the dataset")));

    // DETECTED means the signal actually entered the fusion as evidence.
    // A detector that abstained says ABSTAINED, never "not detected" - the
    // two are different claims and the engine treats them differently.
    var dga = result.dga_analysis || {};
    var dgaSig = signalOf(result, "dga");
    var dgaUsed = !!(dgaSig && dgaSig.used_in_fusion);
    wrap.appendChild(evidenceCard("DGA Analysis",
      dgaUsed ? (dgaSig.score >= 70 ? "hit" : "warn") : "idle",
      dgaUsed ? "DETECTED" : "ABSTAINED",
      (dga.score !== undefined ? "suspicion " + dga.score.toFixed(2) + " / 1.00" : "")
        + (dga.model ? " · " + dga.model : "")));

    var tun = result.tunnel_analysis || {};
    var tunHit = !!(tun.indicators && tun.indicators.length);
    wrap.appendChild(evidenceCard("DNS Tunnelling",
      tunHit ? "hit" : "idle",
      tunHit ? "DETECTED" : "NOT DETECTED",
      tunHit ? tun.indicators.join(", ")
        : (tun.method || "heuristic") + " found no indicator"));

    var lex = signalOf(result, "lexical");
    wrap.appendChild(evidenceCard("Lexical Analysis",
      lex && lex.used_in_fusion ? (lex.score >= 70 ? "hit" : lex.score >= 30 ? "warn" : "active")
        : "idle",
      lex && lex.used_in_fusion ? lex.score.toFixed(0) + " / 100" : "ABSTAINED",
      lex ? "weight " + lex.weight.toFixed(2) + " · confidence "
        + lex.confidence.toFixed(2) : ""));

    var beh = result.behavioral_analysis || {};
    var behHit = !!(beh.indicators && beh.indicators.length);
    var behSig = signalOf(result, "behavioral");
    wrap.appendChild(evidenceCard("Behavioural",
      behHit ? "hit" : "idle",
      behHit ? "ANOMALY" : (behSig && behSig.used_in_fusion ? "NORMAL" : "ABSTAINED"),
      behHit ? beh.indicators.join(", ")
        : (beh.observations
            ? beh.observations.queries_in_window + " queries seen in "
              + beh.observations.window_minutes + " min"
            : "")));

    p.appendChild(wrap);
    return p;
  }

  /* -- why this decision ------------------------------------------------- */

  /* Reads risk_factors, which IS the computation: the contributions sum to
     the score. Positive contributors are listed first, largest first; the
     zero-contribution INFO factors are the detectors that looked and found
     nothing, and they are listed too, because "we checked and there was
     nothing" is part of the explanation. Nothing here is written by hand. */
  function renderWhy(result) {
    var factors = (result.risk_factors || []).slice();
    if (!factors.length) return null;

    var contributing = factors.filter(function (f) { return f.contribution > 0; })
      .sort(function (a, b) { return b.contribution - a.contribution; });
    var quiet = factors.filter(function (f) { return f.contribution <= 0; });

    var p = panel("Why This Decision?");
    var list = el("div", "why");

    contributing.forEach(function (f) {
      var row = el("div", "why-row " + (f.severity === "CRITICAL" || f.severity === "HIGH"
        ? "why-crit" : "why-add"));
      row.appendChild(el("div", "why-mark", "+"));
      row.appendChild(el("div", "why-pts", f.contribution.toFixed(1)));
      var body = el("div");
      body.appendChild(el("div", "why-text", f.label));
      if (f.detail) body.appendChild(el("div", "why-sub", f.detail));
      row.appendChild(body);
      list.appendChild(row);
    });

    quiet.forEach(function (f) {
      var row = el("div", "why-row why-none");
      row.appendChild(el("div", "why-mark", "✓"));
      row.appendChild(el("div", "why-pts", f.contribution ? f.contribution.toFixed(1) : "0.0"));
      var body = el("div");
      body.appendChild(el("div", "why-text", f.label));
      if (f.detail) body.appendChild(el("div", "why-sub", f.detail));
      row.appendChild(body);
      list.appendChild(row);
    });

    p.appendChild(list);

    var sum = factors.reduce(function (a, f) { return a + f.contribution; }, 0);
    var final = el("div", "why-final");
    var k = el("div");
    k.appendChild(el("div", "why-final-k", "Final Decision"));
    k.appendChild(el("div", "evtime",
      "contributions sum to " + sum.toFixed(1) + " = risk score " + result.risk_score));
    final.appendChild(k);

    var v = el("div", "why-final-v");
    v.style.color = STATUS[result.decision] || "var(--text)";
    v.appendChild(el("span", "led"));
    v.appendChild(el("span", null, result.decision));
    final.appendChild(v);
    p.appendChild(final);
    return p;
  }

  /* Panel order on the Analyse view. Every detector appears for every
     result, including the ones that abstained - a detector that vanishes
     tells an analyst nothing about whether it ran. */
  var PANELS = [
    renderHero, renderEvidencePipeline, renderEvidenceCards, renderWhy,
    renderClassification, renderFactors, renderSignals,
    renderIntel, renderDGA, renderTunnel, renderBehavioral, renderFeatures
  ];

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
        // Render each panel in isolation. A panel that throws must never
        // blank the page or be reported as a failure to reach the backend -
        // the analysis in hand succeeded, and the rest of it is still worth
        // showing. The broken panel names itself instead.
        PANELS.forEach(function (render) {
          var node;
          try {
            node = render(result);
          } catch (panelError) {
            console.error("panel render failed:", render.name, panelError);
            node = el("div", "panel error");
            node.appendChild(el("div", "error-code", "PANEL_ERROR"));
            node.appendChild(el("div", null,
              "The analysis succeeded; this one panel failed to display it."));
            node.appendChild(el("div", "muted", render.name + ": " + panelError));
          }
          if (node) host.appendChild(node);
        });
        loadStats();     // the event this created is now part of the numbers
      })
      .catch(function (err) {
        button.disabled = false;
        // This catch covers BOTH a failed request and a crash while rendering
        // a successful one. Reporting the second as "could not reach the
        // analysis engine" sent us hunting a backend that was answering 200
        // perfectly well. Name the two cases apart.
        var reachedServer = err && err.name === "TypeError"
          && String(err).indexOf("fetch") === -1;
        renderError(reachedServer ? {
          code: "RENDER_ERROR",
          message: "The analysis completed, but this page failed to display it.",
          detail: String(err) + " - the API response is fine; this is a "
            + "frontend bug. Check the browser console."
        } : {
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

  // Health drives the product-state strip only. The build/model detail this
  // used to print across the masthead now lives in Diagnostics, under the
  // Activity Log tab, where an engineer can find it and a user is not made to
  // read it.
  request("/api/health").then(function (response) {
    renderSysbar(response.ok ? response.data : null);
  }).catch(function () {
    renderSysbar(null);
  });

  loadStats();
})();
