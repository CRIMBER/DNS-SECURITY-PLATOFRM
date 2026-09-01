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

  function actionFor(event, severity) {
    if (severity === "ERROR") return "Upstream lookup failed";
    if (severity === "BLOCKED") return "Blocked — " + reasonFor(event);
    if (severity === "WARNING") return "Flagged — " + reasonFor(event);
    if (event.cache_hit) return "Allowed — served from cache";
    if (event.upstream_used) return "Allowed — resolved upstream";
    return "Allowed — analysis completed";
  }

  /* Where the entry came from. A client address is used only when the event
     carries one; otherwise the honest answer is which surface produced it. */
  function sourceFor(event) {
    if (event.client_address) return event.client_address;
    return event.event_type === "dns" ? "DNS gateway" : "Dashboard";
  }

  /* -- expandable detail ------------------------------------------------- */

  function detailRows(event) {
    var rows = [
      ["Classification", event.classification],
      ["Threat intelligence", event.threat_intelligence_verdict]
    ];
    if (event.matched_indicator) rows.push(["Matched indicator", event.matched_indicator]);
    if ((event.threat_categories || []).length) {
      rows.push(["Categories", event.threat_categories.join(", ")]);
    }
    if (event.event_type === "dns") {
      rows.push(["Query type", event.query_type]);
      rows.push(["Response", event.response_code]);
      rows.push(["Upstream contacted", event.upstream_used ? "Yes" : "No"]);
      rows.push(["Served from cache", event.cache_hit ? "Yes" : "No"]);
      // Only when the privacy policy actually recorded one.
      if (event.client_address) rows.push(["Client", event.client_address]);
    }
    if ((event.overrides_applied || []).length) {
      rows.push(["Policy overrides", event.overrides_applied.join(", ")]);
    }
    rows.push(["Analysis time", (event.analysis_time_ms || 0) + " ms"]);
    return rows;
  }

  function detailCell(event) {
    var box = el("div", "log-detail");
    var grid = el("div", "log-detail-grid");
    detailRows(event).forEach(function (pair) {
      if (pair[1] === null || pair[1] === undefined || pair[1] === "") return;
      var item = el("div", "log-detail-item");
      item.appendChild(el("div", "log-detail-k", pair[0]));
      item.appendChild(el("div", "log-detail-v", String(pair[1])));
      grid.appendChild(item);
    });
    box.appendChild(grid);

    var factors = event.top_factors || [];
    if (factors.length) {
      box.appendChild(el("div", "log-detail-h", "Contributing evidence"));
      var list = el("ul", "log-factors");
      factors.forEach(function (f) {
        var li = el("li");
        li.appendChild(el("span", null, f.label));
        li.appendChild(el("span", "log-factor-n", "+" + f.contribution));
        list.appendChild(li);
      });
      box.appendChild(list);
    }
    return box;
  }

  /* -- table rows -------------------------------------------------------- */

  function eventRows(event, index) {
    var severity = severityOf(event);
    var detailId = "logdetail-" + index;

    var tr = el("tr", "logrow " + LEVEL_CLASS[severity]);
    tr.setAttribute("data-level", severity);

    tr.appendChild(el("td", "log-time", shortTime(event.timestamp)));

    var domain = el("td", "log-domain");
    var toggle = el("button", "log-toggle", event.domain || "—");
    toggle.setAttribute("type", "button");
    toggle.setAttribute("aria-expanded", "false");
    toggle.setAttribute("aria-controls", detailId);
    domain.appendChild(toggle);
    tr.appendChild(domain);

    tr.appendChild(el("td", "log-action", actionFor(event, severity)));

    var risk = el("td", "log-risk", String(event.risk_score));
    risk.style.color = UI.scoreColor(event.risk_score);
    tr.appendChild(risk);

    var decision = el("td");
    decision.appendChild(el("span", "badge badge-" + event.decision, event.decision));
    tr.appendChild(decision);

    tr.appendChild(el("td", "log-source", sourceFor(event)));

    var detailTr = el("tr", "logrow-detail hidden");
    detailTr.id = detailId;
    var cell = el("td");
    cell.setAttribute("colspan", "6");
    cell.appendChild(detailCell(event));
    detailTr.appendChild(cell);

    toggle.addEventListener("click", function () {
      var open = detailTr.classList.toggle("hidden");
      toggle.setAttribute("aria-expanded", open ? "false" : "true");
      tr.classList.toggle("is-open", !open);
    });

    return [tr, detailTr];
  }

  /* -- standing conditions ----------------------------------------------- */

  /* Not events: current facts about the service. They carry no timestamp
     because nothing happened at a particular moment - inventing one would be
     the easy lie here. They sit above the table as notices instead. */
  function conditions(health, dnsStatus) {
    var out = [];
    var gateway = (health.components || {}).dns_gateway || {};

    if (gateway.status === "disabled") {
      out.push({
        level: "WARNING",
        subject: "DNS protection",
        message: "DNS protection is not available in this deployment."
      });
    } else if (gateway.status === "error") {
      out.push({
        level: "ERROR",
        subject: "DNS protection",
        message: "The DNS gateway could not start, so queries are not being filtered."
      });
    } else if (gateway.status === "ok") {
      out.push({
        level: "INFO",
        subject: "DNS protection",
        message: "The DNS gateway is active and filtering queries."
      });
    }

    var stats = (dnsStatus && dnsStatus.stats) || {};
    if (stats.upstream_failures) {
      out.push({
        level: "WARNING",
        subject: "Upstream resolver",
        message: stats.upstream_failures
          + " upstream lookup(s) have failed since the gateway started."
      });
    }
    if (health.status !== "ok") {
      out.push({
        level: "ERROR",
        subject: "System",
        message: "One or more components are not reporting healthy."
      });
    }
    return out;
  }

  function noticeRow(item) {
    var row = el("div", "log-notice " + LEVEL_CLASS[item.level]);
    row.setAttribute("data-level", item.level);
    row.appendChild(el("span", "log-notice-dot"));
    var body = el("div", "log-notice-body");
    body.appendChild(el("span", "log-notice-subject", item.subject));
    body.appendChild(el("span", "log-notice-msg", item.message));
    row.appendChild(body);
    row.appendChild(el("span", "log-notice-tag", "current"));
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

    var grid = el("div", "log-detail-grid");
    rows.forEach(function (pair) {
      if (!pair[1]) return;
      var item = el("div", "log-detail-item");
      item.appendChild(el("div", "log-detail-k", pair[0]));
      item.appendChild(el("div", "log-detail-v", String(pair[1])));
      grid.appendChild(item);
    });
    host.appendChild(grid);
  }

  /* -- empty state ------------------------------------------------------- */

  /* An empty log is a normal condition, not a failure, and must not be drawn
     as one. What it says depends on WHY it is empty. */
  function emptyState(health) {
    var gateway = (health.components || {}).dns_gateway || {};
    var box = el("div", "log-empty");
    box.appendChild(el("div", "log-empty-title",
      state.search ? "No matching activity" : "No activity yet"));

    var message;
    if (state.search) {
      message = "Nothing recorded so far matches “" + state.search + "”.";
    } else if (gateway.status === "disabled") {
      message = "DNS protection is currently unavailable in this deployment. "
        + "Connect the gateway to begin collecting DNS activity, or analyse a "
        + "domain to see results here.";
    } else {
      message = "Analyse a domain, or send a query through the DNS gateway, "
        + "and it will appear here.";
    }
    box.appendChild(el("div", "log-empty-msg", message));
    return box;
  }

  /* -- rendering --------------------------------------------------------- */

  function applyFilter() {
    var rows = document.querySelectorAll("#logList tr.logrow");
    var shown = 0;
    Array.prototype.forEach.call(rows, function (row) {
      var levelOk = state.level === "ALL"
        || row.getAttribute("data-level") === state.level;
      row.classList.toggle("hidden", !levelOk);
      var detail = row.nextElementSibling;
      if (detail && detail.classList.contains("logrow-detail") && !levelOk) {
        detail.classList.add("hidden");
        row.classList.remove("is-open");
      }
      if (levelOk) shown += 1;
    });
    Array.prototype.forEach.call(
      document.querySelectorAll("#logNotices .log-notice"), function (row) {
        row.classList.toggle("hidden", state.level !== "ALL"
          && row.getAttribute("data-level") !== state.level);
      });
    var count = $("logCount");
    if (count) {
      count.textContent = shown + (shown === 1 ? " event" : " events")
        + (state.level === "ALL" ? "" : " at " + state.level)
        + (state.search ? " matching “" + state.search + "”" : "");
    }
  }

  function render(events, health, dnsStatus) {
    var notices = $("logNotices");
    notices.innerHTML = "";
    conditions(health, dnsStatus).forEach(function (item) {
      notices.appendChild(noticeRow(item));
    });

    var host = $("logList");
    host.innerHTML = "";

    if (!events.length) {
      $("logCount").textContent = "";
      host.appendChild(emptyState(health));
    } else {
      var wrap = el("div", "table-scroll");
      var table = el("table", "log-table");
      var head = el("tr");
      ["Time", "Domain", "Action", "Risk", "Decision", "Source"]
        .forEach(function (h) { head.appendChild(el("th", null, h)); });
      table.appendChild(head);
      events.forEach(function (event, index) {
        eventRows(event, index).forEach(function (row) { table.appendChild(row); });
      });
      wrap.appendChild(table);
      host.appendChild(wrap);
      applyFilter();
    }
    renderDiagnostics(health);
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
        var button = el("button", "chip" + (level === "ALL" ? " active" : ""),
                        level === "ALL" ? "All" : level.charAt(0)
                          + level.slice(1).toLowerCase());
        button.setAttribute("type", "button");
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
