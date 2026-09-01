/* Activity log.
 *
 * There is no second logging system behind this view. Every line comes from
 * the event store the rest of the console already reads - /api/events - plus
 * the two status endpoints that describe the running service. Nothing here is
 * generated, buffered or duplicated client-side; reload the page and the same
 * rows come back, because they are rows, not console output.
 *
 * Severity is DERIVED from what the backend already decided, never invented:
 *
 *     decision BLOCK            -> BLOCKED
 *     response_code SERVFAIL    -> ERROR    (upstream could not answer)
 *     decision MONITOR          -> WARNING
 *     decision ALLOW            -> INFO
 *
 * Client addresses are shown only when the event actually carries one. The
 * gateway applies DNS_LOG_CLIENT_IP before anything is stored, so a withheld
 * address is absent here for the same reason it is absent everywhere else -
 * it was never recorded. This view does not go looking for it.
 */

(function () {
  "use strict";

  var UI = window.UI;
  var $ = UI.$, el = UI.el, request = UI.request, shortTime = UI.shortTime;

  var LEVELS = ["ALL", "INFO", "WARNING", "BLOCKED", "ERROR"];

  var LEVEL_CLASS = {
    INFO: "lg-info",
    WARNING: "lg-warn",
    BLOCKED: "lg-blocked",
    ERROR: "lg-error"
  };

  var state = { level: "ALL", search: "", limit: 100 };

  /* -- severity ---------------------------------------------------------- */

  function severityOf(event) {
    if (event.decision === "BLOCK") return "BLOCKED";
    if (event.response_code === "SERVFAIL") return "ERROR";
    if (event.decision === "MONITOR") return "WARNING";
    return "INFO";
  }

  /* -- one-line summary -------------------------------------------------- */

  function reasonFor(event) {
    /* The shortest true statement about why this decision happened. Prefer
       the verdict the engine recorded over re-deriving anything here. */
    if (event.threat_intelligence_verdict === "MALICIOUS") {
      return "known malicious domain";
    }
    var codes = (event.top_factors || []).map(function (f) { return f.code; });
    if (codes.indexOf("DNS_TUNNEL_INDICATORS") >= 0) return "possible DNS tunnelling";
    if (codes.indexOf("BEHAVIORAL_ANOMALY") >= 0) return "anomalous query behaviour";
    if (codes.indexOf("DGA_HIGH") >= 0) return "algorithmically generated name";
    if (codes.indexOf("BRAND_IMPERSONATION") >= 0) return "brand impersonation";
    if (event.threat_intelligence_verdict === "SUSPICIOUS") return "suspicious reputation";
    return "risk threshold exceeded";
  }

  function messageFor(event, severity) {
    if (severity === "ERROR") {
      return "Upstream resolution failed — no answer was invented";
    }
    if (severity === "BLOCKED") {
      return "Risk " + event.risk_score + " — blocked, " + reasonFor(event);
    }
    if (severity === "WARNING") {
      return "Risk " + event.risk_score + " — flagged for monitoring, "
        + reasonFor(event);
    }
    if (event.cache_hit) return "Allowed — served from cache";
    if (event.upstream_used) return "Allowed — resolved upstream";
    return "Allowed — analysis completed";
  }

  function categoryFor(event) {
    return event.event_type === "dns" ? "DNS query" : "Domain analysis";
  }

  /* -- expandable detail ------------------------------------------------- */

  function detailRows(event) {
    var rows = [
      ["Decision", event.decision],
      ["Classification", event.classification],
      ["Risk score", event.risk_score],
      ["Threat intelligence", event.threat_intelligence_verdict]
    ];
    if (event.matched_indicator) rows.push(["Matched indicator", event.matched_indicator]);
    if ((event.threat_categories || []).length) {
      rows.push(["Categories", event.threat_categories.join(", ")]);
    }
    if (event.event_type === "dns") {
      rows.push(["Query type", event.query_type]);
      rows.push(["Response", event.response_code]);
      rows.push(["Upstream contacted", event.upstream_used ? "yes" : "no"]);
      rows.push(["Served from cache", event.cache_hit ? "yes" : "no"]);
      // Only when the privacy policy actually recorded one.
      if (event.client_address) rows.push(["Client", event.client_address]);
    }
    if ((event.overrides_applied || []).length) {
      rows.push(["Policy overrides", event.overrides_applied.join(", ")]);
    }
    rows.push(["Analysis time", (event.analysis_time_ms || 0) + " ms"]);
    return rows;
  }

  function entry(event) {
    var severity = severityOf(event);
    var row = el("details", "logrow " + LEVEL_CLASS[severity]);
    row.setAttribute("data-level", severity);
    row.setAttribute("data-domain", event.domain || "");

    var head = el("summary", "logrow-head");
    head.appendChild(el("span", "logrow-time", "[" + shortTime(event.timestamp) + "]"));
    head.appendChild(el("span", "logrow-sev", severity));

    var body = el("span", "logrow-body");
    body.appendChild(el("span", "logrow-subject", event.domain || categoryFor(event)));
    body.appendChild(el("span", "logrow-msg", messageFor(event, severity)));
    head.appendChild(body);
    head.appendChild(el("span", "logrow-cat", categoryFor(event)));
    row.appendChild(head);

    var detail = el("div", "logrow-detail");
    var table = el("table", "kv");
    detailRows(event).forEach(function (pair) {
      if (pair[1] === null || pair[1] === undefined || pair[1] === "") return;
      var tr = el("tr");
      tr.appendChild(el("th", null, pair[0]));
      tr.appendChild(el("td", "mono", String(pair[1])));
      table.appendChild(tr);
    });
    detail.appendChild(table);

    var factors = event.top_factors || [];
    if (factors.length) {
      detail.appendChild(el("div", "logrow-detail-h", "Contributing evidence"));
      var list = el("ul", "logrow-factors");
      factors.forEach(function (f) {
        list.appendChild(el("li", null, f.label + " (+" + f.contribution + ")"));
      });
      detail.appendChild(list);
    }
    row.appendChild(detail);
    return row;
  }

  /* -- standing conditions ----------------------------------------------- */

  /* Not events: current facts about the service. They carry no timestamp
     because nothing happened at a particular moment - inventing one would be
     the easy lie here. They are pinned above the timeline instead. */
  function conditions(health, dnsStatus) {
    var out = [];
    var gateway = (health.components || {}).dns_gateway || {};

    if (gateway.status === "disabled") {
      out.push({
        level: "WARNING",
        subject: "DNS Protection",
        message: "DNS gateway is not available in this deployment"
      });
    } else if (gateway.status === "error") {
      out.push({
        level: "ERROR",
        subject: "DNS Protection",
        message: "DNS gateway could not start and is not filtering traffic"
      });
    } else if (gateway.status === "ok") {
      out.push({
        level: "INFO",
        subject: "DNS Protection",
        message: "DNS gateway active and filtering queries"
      });
    }

    var stats = (dnsStatus && dnsStatus.stats) || {};
    if (stats.upstream_failures) {
      out.push({
        level: "WARNING",
        subject: "Upstream resolver",
        message: stats.upstream_failures
          + " upstream lookup(s) failed since the gateway started"
      });
    }
    if (health.status !== "ok") {
      out.push({
        level: "ERROR",
        subject: "System",
        message: "One or more components are not reporting healthy"
      });
    }
    return out;
  }

  function conditionRow(item) {
    var row = el("div", "logrow logrow-condition " + LEVEL_CLASS[item.level]);
    row.setAttribute("data-level", item.level);
    row.setAttribute("data-domain", "");
    var head = el("div", "logrow-head");
    head.appendChild(el("span", "logrow-time", "current"));
    head.appendChild(el("span", "logrow-sev", item.level));
    var body = el("span", "logrow-body");
    body.appendChild(el("span", "logrow-subject", item.subject));
    body.appendChild(el("span", "logrow-msg", item.message));
    head.appendChild(body);
    head.appendChild(el("span", "logrow-cat", "System state"));
    row.appendChild(head);
    return row;
  }

  /* -- diagnostics (engineering metadata, deliberately out of the way) ---- */

  function renderDiagnostics(health) {
    var host = $("logDiagnostics");
    if (!host) return;
    host.innerHTML = "";
    var c = health.components || {};
    var ti = c.threat_intelligence || {};
    var dga = c.dga_detector || {};
    var engine = c.risk_engine || {};
    var gateway = c.dns_gateway || {};

    var rows = [
      ["Build", health.version],
      ["Risk policy", "v" + health.risk_config_version],
      ["Threat-intel dataset", ti.source + " — " + ti.indicators_total
        + " indicators, " + ti.trusted_domains + " trusted"],
      ["Dataset updated", ti.last_updated],
      ["DGA model", dga.model + " (" + dga.model_type + ", "
        + dga.corpus_size + "-label corpus, no accuracy claimed)"],
      ["Fusion method", engine.fusion],
      ["DNS gateway", gateway.status
        + (gateway.listen_address ? " on " + gateway.listen_address : "")
        + (gateway.reason ? " — " + gateway.reason : "")]
    ];

    var table = el("table", "kv");
    rows.forEach(function (pair) {
      if (!pair[1]) return;
      var tr = el("tr");
      tr.appendChild(el("th", null, pair[0]));
      tr.appendChild(el("td", "mono", String(pair[1])));
      table.appendChild(tr);
    });
    host.appendChild(table);
  }

  /* -- rendering --------------------------------------------------------- */

  function applyFilter() {
    var rows = document.querySelectorAll("#logList .logrow");
    var shown = 0;
    Array.prototype.forEach.call(rows, function (row) {
      var levelOk = state.level === "ALL"
        || row.getAttribute("data-level") === state.level;
      row.classList.toggle("hidden", !levelOk);
      if (levelOk) shown += 1;
    });
    var count = $("logCount");
    if (count) {
      count.textContent = shown + " entr" + (shown === 1 ? "y" : "ies")
        + (state.level === "ALL" ? "" : " at " + state.level)
        + (state.search ? ' matching "' + state.search + '"' : "");
    }
  }

  function render(events, health, dnsStatus) {
    var host = $("logList");
    host.innerHTML = "";

    conditions(health, dnsStatus).forEach(function (item) {
      host.appendChild(conditionRow(item));
    });

    if (!events.length) {
      host.appendChild(el("div", "note",
        state.search
          ? 'No stored activity matches "' + state.search + '".'
          : "No activity recorded yet. Analyse a domain, or send a query "
            + "through the DNS gateway, and it will appear here."));
    } else {
      events.forEach(function (event) { host.appendChild(entry(event)); });
    }
    renderDiagnostics(health);
    applyFilter();
  }

  function load() {
    var path = "/api/events?limit=" + state.limit;
    if (state.search) path += "&q=" + encodeURIComponent(state.search);

    Promise.all([
      request(path),
      request("/api/health"),
      request("/api/dns/status")
    ]).then(function (responses) {
      var events = responses[0].ok ? (responses[0].data.events || []) : [];
      var health = responses[1].ok ? responses[1].data : { status: "unreachable" };
      var dnsStatus = responses[2].ok ? responses[2].data : null;
      render(events, health, dnsStatus);
    }).catch(function () {
      $("logList").innerHTML = "";
      $("logList").appendChild(el("div", "note",
        "Could not reach the service to read activity."));
    });
  }

  /* -- wiring ------------------------------------------------------------ */

  function init() {
    var filters = $("logFilters");
    if (filters) {
      LEVELS.forEach(function (level) {
        var button = el("button", "chip" + (level === "ALL" ? " active" : ""), level);
        button.setAttribute("data-level", level);
        button.addEventListener("click", function () {
          state.level = level;
          Array.prototype.forEach.call(filters.querySelectorAll(".chip"), function (c) {
            c.classList.toggle("active", c === button);
          });
          applyFilter();
        });
        filters.appendChild(button);
      });
    }

    var search = $("logSearch");
    if (search) {
      search.addEventListener("keydown", function (e) {
        if (e.key === "Enter") { state.search = search.value.trim(); load(); }
      });
    }
    var searchBtn = $("logSearchBtn");
    if (searchBtn) {
      searchBtn.addEventListener("click", function () {
        state.search = ($("logSearch").value || "").trim();
        load();
      });
    }
    var clearBtn = $("logClearSearch");
    if (clearBtn) {
      clearBtn.addEventListener("click", function () {
        $("logSearch").value = "";
        state.search = "";
        load();
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  window.LogsView = { load: load };
})();
