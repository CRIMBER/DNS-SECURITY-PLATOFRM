/* DNS Security view.
 *
 * Distinguishes a DNS REQUEST - a real query that entered the gateway - from an
 * ANALYSIS REQUEST, where someone typed a domain into the console. Both are
 * real events; conflating them would misrepresent what the gateway has
 * actually handled, so this view reads /api/dns/* exclusively.
 *
 *   GET /api/dns/status   live gateway state and in-process counters
 *   GET /api/dns/stats    aggregates over stored DNS events
 *   GET /api/dns/events   the DNS event log
 *
 * Shared rendering helpers come from window.UI, defined in app.js.
 */

(function () {
  "use strict";

  var U = window.UI;
  var $ = U.$;
  var el = U.el;

  function renderStatus(status) {
    var host = $("dnsStatus");
    host.innerHTML = "";

    var state = !status.enabled ? "disabled"
              : status.running ? "running" : "not running";
    var color = status.running ? "var(--safe)"
              : status.enabled ? "var(--critical)" : "var(--info)";

    var head = el("div");
    head.style.cssText = "display:flex;align-items:center;gap:10px;margin-bottom:14px";
    var dot = el("span");
    dot.style.cssText = "width:9px;height:9px;border-radius:50%;flex:none;background:" + color;
    head.appendChild(dot);
    var label = el("span", null, "Gateway " + state);
    label.style.cssText = "font-weight:650;color:" + color;
    head.appendChild(label);
    host.appendChild(head);

    if (status.bind_error) {
      var box = el("div", "error");
      box.appendChild(el("div", "error-code", "BIND_FAILED"));
      box.appendChild(el("div", null, status.bind_error));
      host.appendChild(box);
      return;
    }
    if (!status.running) {
      host.appendChild(el("div", "note", status.enabled
        ? "The gateway is enabled but not bound. It starts with the server "
          + "process — restart with: python run.py"
        : "Set DNS_ENABLED=true and restart to run the gateway."));
      return;
    }

    var dl = el("dl", "kv");
    function row(k, v) {
      dl.appendChild(el("dt", null, k));
      dl.appendChild(el("dd", null, v));
    }
    row("Listening on", status.listen_address + "/" + status.protocol);
    row("Upstream resolver", status.upstream ? status.upstream.address : "-");
    row("Block policy", status.block_policy);
    row("Available policies", status.available_block_policies.join(", "));
    row("Queries received", status.stats.queries_received);
    row("Queries answered", status.stats.queries_answered);
    row("Blocked", status.stats.blocked);
    row("Upstream queries", status.stats.upstream_queries);
    row("Upstream failures", status.stats.upstream_failures);
    row("Malformed packets", status.stats.malformed_packets);
    if (status.cache) {
      row("Cache", status.cache.enabled
        ? status.cache.entries + " entries · " + status.cache.hits + " hits ("
          + Math.round(status.cache.hit_rate * 100) + "%)"
        : "disabled");
    }
    host.appendChild(dl);

    var planned = Object.keys(status.unimplemented_block_policies || {});
    if (planned.length) {
      host.appendChild(el("div", "note",
        "Declared but not implemented: " + planned.join(", ") +
        ". Listed so the gap stays visible rather than silent."));
    }
    if (status.cache) host.appendChild(el("div", "note", status.cache.note));
  }

  function renderTiles(stats) {
    var host = $("dnsTiles");
    host.innerHTML = "";
    var total = stats.total_dns_requests;
    function pct(n) {
      return total ? Math.round((n / total) * 100) + "% of DNS traffic"
                   : "no DNS queries yet";
    }
    host.appendChild(U.tile("Total DNS requests", total, "queries through the gateway"));
    host.appendChild(U.tile("Allowed", stats.allowed, pct(stats.allowed), "var(--safe)"));
    host.appendChild(U.tile("Monitored", stats.monitored, pct(stats.monitored), "var(--warning)"));
    host.appendChild(U.tile("Blocked", stats.blocked, pct(stats.blocked), "var(--critical)"));
    host.appendChild(U.tile("Cache hits", stats.cache_hits, "served without upstream"));
  }

  function renderCharts(stats) {
    Charts.horizontalBars($("dnsDecisionChart"), [
      { label: "Allowed",   value: stats.allowed,   color: "var(--safe)" },
      { label: "Monitored", value: stats.monitored, color: "var(--warning)" },
      { label: "Blocked",   value: stats.blocked,   color: "var(--critical)" }
    ], {
      labelWidth: 110,
      legend: U.STATUS_LEGEND,
      emptyMessage: "No DNS queries yet. Send one to the gateway to populate this."
    });

    // Magnitude by record type: ONE hue, because this encodes counts, not
    // identity. A categorical ramp here would imply the types are series.
    var types = Object.keys(stats.by_query_type).map(function (key) {
      return { label: key, value: stats.by_query_type[key], color: "var(--accent)" };
    });
    Charts.horizontalBars($("dnsTypeChart"), types.slice(0, 8), {
      labelWidth: 90,
      emptyMessage: "No DNS queries yet."
    });
  }

  function renderActivity(stats) {
    var buckets = (stats.activity || []).map(function (row) {
      return {
        label: (row.hour || "").slice(11, 16),
        segments: [
          { key: "allowed", value: row.ALLOW || 0, color: "var(--safe)" },
          { key: "monitored", value: row.MONITOR || 0, color: "var(--warning)" },
          { key: "blocked", value: row.BLOCK || 0, color: "var(--critical)" }
        ]
      };
    });
    Charts.stackedColumns($("dnsActivityChart"), buckets, {
      legend: U.STATUS_LEGEND,
      emptyMessage: "No DNS activity in the last 24 hours."
    });
  }

  function renderBlocked(stats) {
    var host = $("dnsBlocked");
    host.innerHTML = "";
    if (!stats.blocked_domains.length) {
      return Charts.empty(host, "No DNS query has been blocked yet.");
    }
    var wrap = el("div", "table-scroll");
    var table = el("table");
    var head = el("tr");
    ["Domain", "Type", "Risk", "Reason", "Policy", "Hits"].forEach(function (h) {
      head.appendChild(el("th", null, h));
    });
    table.appendChild(head);

    stats.blocked_domains.forEach(function (row) {
      var tr = el("tr");
      tr.appendChild(el("td", "mono", row.domain));
      tr.appendChild(el("td", "mono", row.query_type || "-"));
      var score = el("td", "num", row.risk_score);
      score.style.color = U.scoreColor(row.risk_score);
      tr.appendChild(score);
      tr.appendChild(el("td", null, row.reason));
      tr.appendChild(el("td", "mono", row.policy || "-"));
      tr.appendChild(el("td", "num", row.hits));
      table.appendChild(tr);
    });
    wrap.appendChild(table);
    host.appendChild(wrap);
  }

  function renderPerformance(stats) {
    var host = $("dnsPerformance");
    host.innerHTML = "";
    var p = stats.performance;
    var grid = el("div", "features");
    [
      ["analysis mean", p.mean_analysis_time_ms],
      ["upstream mean", p.mean_upstream_time_ms],
      ["end-to-end mean", p.mean_total_gateway_time_ms],
      ["end-to-end p95", p.p95_total_gateway_time_ms],
      ["end-to-end slowest", p.slowest_total_gateway_time_ms]
    ].forEach(function (pair) {
      var cell = el("div", "feature");
      cell.appendChild(el("div", "feature-k", pair[0]));
      cell.appendChild(el("div", "feature-v", pair[1] + " ms"));
      grid.appendChild(cell);
    });
    host.appendChild(grid);
    host.appendChild(el("div", "note", p.note));
  }

  function renderEvents(data) {
    $("dnsEventCount").textContent =
      "(" + data.events.length + " of " + data.total + ")";
    var host = $("dnsEventsTable");
    host.innerHTML = "";
    if (!data.events.length) {
      return Charts.empty(host,
        "No DNS requests recorded. Point a DNS client at the gateway to populate this.");
    }

    var wrap = el("div", "table-scroll");
    var table = el("table");
    var head = el("tr");
    ["Time", "Domain", "Type", "Risk", "Decision", "Response", "Upstream", "Latency"]
      .forEach(function (h) { head.appendChild(el("th", null, h)); });
    table.appendChild(head);
    $("dnsEventCount").textContent += "  ·  click a row for the reasoning";

    data.events.forEach(function (event) {
      var tr = el("tr", "expandable");
      tr.appendChild(el("td", "mono", U.shortTime(event.timestamp)));
      tr.appendChild(el("td", "mono", event.domain));
      tr.appendChild(el("td", "mono", event.query_type || "-"));

      var score = el("td", "num", event.risk_score);
      score.style.color = U.scoreColor(event.risk_score);
      tr.appendChild(score);

      var dec = el("td");
      dec.appendChild(el("span", "badge badge-" + event.decision, event.decision));
      tr.appendChild(dec);

      tr.appendChild(el("td", "mono", event.response_code || "-"));
      tr.appendChild(el("td", "mono",
        event.cache_hit ? "cache" : event.upstream_used ? "yes" : "no"));
      tr.appendChild(el("td", "num",
        event.total_gateway_time_ms != null
          ? event.total_gateway_time_ms.toFixed(2) + " ms" : "-"));
      table.appendChild(tr);

      // A click reveals why the gateway decided what it decided.
      var detail = el("tr", "detail-row hidden");
      var cell = el("td");
      cell.setAttribute("colspan", "8");
      cell.appendChild(buildDetail(event));
      detail.appendChild(cell);
      table.appendChild(detail);

      tr.addEventListener("click", function () {
        detail.classList.toggle("hidden");
      });
    });
    wrap.appendChild(table);
    host.appendChild(wrap);
  }

  function buildDetail(event) {
    var box = el("div");
    var grid = el("div", "detail-grid");

    function pair(key, value) {
      var line = el("div");
      line.appendChild(el("b", null, key + ": "));
      line.appendChild(document.createTextNode(value));
      grid.appendChild(line);
    }
    pair("threat intel", event.threat_intelligence_verdict);
    if (event.matched_indicator) pair("indicator", event.matched_indicator);
    pair("DGA suspicion", event.dga_score);
    pair("lexical", event.lexical_score);
    pair("confidence", event.confidence);
    pair("analysis", (event.analysis_time_ms || 0).toFixed(2) + " ms");
    if (event.dns_upstream_time_ms) {
      pair("upstream", event.dns_upstream_time_ms.toFixed(2) + " ms");
    }
    if (event.block_policy) pair("block policy", event.block_policy);
    if (event.client_address) pair("client", event.client_address);
    if (event.overrides_applied && event.overrides_applied.length) {
      pair("overrides", event.overrides_applied.join(", "));
    }
    box.appendChild(grid);

    if (event.top_factors && event.top_factors.length) {
      var factors = el("div", "detail-factors");
      factors.appendChild(el("b", null, "Why:"));
      event.top_factors.forEach(function (factor) {
        var line = el("div", "sev-" + factor.severity);
        line.textContent = "+" + factor.contribution.toFixed(1) + "  " + factor.label;
        factors.appendChild(line);
      });
      box.appendChild(factors);
    }
    return box;
  }

  function load() {
    U.request("/api/dns/status").then(function (r) {
      if (r.ok) renderStatus(r.data);
    });
    U.request("/api/dns/stats").then(function (r) {
      if (!r.ok) return;
      renderTiles(r.data);
      renderCharts(r.data);
      renderBlocked(r.data);
      renderActivity(r.data);
      renderPerformance(r.data);
    });
    U.request("/api/dns/events?limit=100").then(function (r) {
      if (r.ok) renderEvents(r.data);
    });
  }

  window.DNSView = { load: load };
})();
