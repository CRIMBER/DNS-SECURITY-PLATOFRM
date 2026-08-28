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
               "activity", "dns", "analytics"];

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

  /* Panel order on the Analyse view. Every detector appears for every
     result, including the ones that abstained - a detector that vanishes
     tells an analyst nothing about whether it ran. */
  var PANELS = [
    renderVerdict, renderClassification, renderFactors, renderSignals,
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
