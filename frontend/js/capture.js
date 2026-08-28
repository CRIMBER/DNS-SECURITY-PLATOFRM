/* Capture Analysis view: PCAP and Zeek dns.log.
 *
 * The file is POSTed as a raw body to /api/capture/pcap or /api/capture/zeek.
 * The backend parses it for real - libpcap/pcapng framing, IP and UDP/TCP
 * headers, then dnspython on the DNS payload - and runs every unique name
 * through the same pipeline that serves /api/analyze. Nothing on this page
 * invents a number; if the upload fails, the reason from the parser is shown
 * instead of a report.
 */

(function () {
  "use strict";

  var UI = window.UI;
  var $ = UI.$, el = UI.el, request = UI.request;

  var STEPS = ["CAPTURE FILE", "PARSE DNS TRAFFIC", "EXTRACT QUERIES",
               "THREAT INTELLIGENCE", "DETECTION PIPELINE", "THREAT REPORT"];

  function renderPipeline() {
    var host = $("capturePipeline");
    if (host.childNodes.length) return;
    var row = el("div", "flow");
    STEPS.forEach(function (step, i) {
      row.appendChild(el("div", "flow-step", step));
      if (i < STEPS.length - 1) row.appendChild(el("div", "flow-arrow", "→"));
    });
    host.appendChild(row);
  }

  function renderSupport() {
    return request("/api/capture/support").then(function (response) {
      var host = $("captureSupport");
      host.innerHTML = "";
      if (!response.ok) return;
      var d = response.data;
      var row = el("div", "support-row");
      [
        ["PCAP / PCAPNG", d.pcap.status, d.pcap.formats.join(", ")],
        ["Zeek dns.log", d.zeek.status, d.zeek.formats.join(", ")]
      ].forEach(function (item) {
        var box = el("div", "support-item");
        var head = el("div");
        head.appendChild(el("span", "proto-name", item[0]));
        head.appendChild(el("span", "badge badge-ALLOW", item[1]));
        box.appendChild(head);
        box.appendChild(el("div", "proto-detail", item[2]));
        row.appendChild(box);
      });
      host.appendChild(row);
      host.appendChild(el("div", "note",
        d.analysis.engine.charAt(0).toUpperCase() + d.analysis.engine.slice(1)
        + ". Up to " + d.analysis.max_unique_domains + " unique names per "
        + "capture. " + d.analysis.note));
    });
  }

  function tile(label, value, sub, color) {
    var t = el("div", "tile");
    t.appendChild(el("div", "tile-k", label));
    var v = el("div", "tile-v", value);
    if (color) v.style.color = color;
    t.appendChild(v);
    if (sub) t.appendChild(el("div", "tile-sub", sub));
    return t;
  }

  function renderReport(report) {
    var host = $("captureResult");
    host.innerHTML = "";

    var summary = el("div", "panel");
    summary.appendChild(el("h2", null, "Threat Report"
      + (report.origin === "zeek" ? " — Zeek dns.log" : " — packet capture")));
    var tiles = el("div", "tiles");
    tiles.appendChild(tile("DNS Queries", report.total_dns_queries));
    tiles.appendChild(tile("Unique Domains", report.unique_domains));
    tiles.appendChild(tile("Source IPs", report.source_ip_count));
    tiles.appendChild(tile("Malicious", report.malicious_domains, null,
                           report.malicious_domains ? "var(--critical)" : null));
    tiles.appendChild(tile("Suspicious", report.suspicious_domains, null,
                           report.suspicious_domains ? "var(--warning)" : null));
    tiles.appendChild(tile("DGA", report.dga_detections, "detections",
                           report.dga_detections ? "var(--critical)" : null));
    tiles.appendChild(tile("Tunnelling", report.tunnelling_detections, "detections",
                           report.tunnelling_detections ? "var(--critical)" : null));
    tiles.appendChild(tile("Block Advised", report.block_recommendations, null,
                           report.block_recommendations ? "var(--critical)" : null));
    summary.appendChild(tiles);

    var facts = [];
    if (report.capture_bytes) facts.push((report.capture_bytes / 1024).toFixed(1) + " KB read");
    if (report.dns_packets_seen !== undefined) facts.push(report.dns_packets_seen + " DNS packets");
    if (report.log_rows !== undefined) facts.push(report.log_rows + " log rows");
    facts.push(report.domains_analysed + " names analysed in " + report.processing_time_ms + " ms");
    if (report.threat_intel_hits) facts.push(report.threat_intel_hits + " threat-intel matches");
    if (report.rejected_count) facts.push(report.rejected_count + " names rejected as invalid");
    summary.appendChild(el("div", "note", facts.join("   ·   ")));
    if (report.truncation_note) {
      summary.appendChild(el("div", "note", report.truncation_note));
    }
    host.appendChild(summary);

    if (report.source_ips && report.source_ips.length) {
      var sources = el("div", "panel");
      sources.appendChild(el("h2", null, "Source IPs in this capture"));
      var wrap = el("div", "table-scroll");
      var table = el("table");
      var head = el("tr");
      ["Source IP", "Queries", "Unique Domains", "Blocked", "Monitored", "Threat Rate"]
        .forEach(function (h) { head.appendChild(el("th", null, h)); });
      table.appendChild(head);
      report.source_ips.forEach(function (s) {
        var tr = el("tr");
        tr.appendChild(el("td", null, s.source_ip));
        tr.appendChild(el("td", "num", s.queries));
        tr.appendChild(el("td", "num", s.unique_domains));
        tr.appendChild(el("td", "num", s.blocked));
        tr.appendChild(el("td", "num", s.monitored));
        var rate = el("td", "num", s.threat_rate + "%");
        rate.style.color = s.threat_rate >= 25 ? "var(--critical)"
          : s.threat_rate > 0 ? "var(--warning)" : "var(--text-dim)";
        tr.appendChild(rate);
        table.appendChild(tr);
      });
      wrap.appendChild(table);
      sources.appendChild(wrap);
      sources.appendChild(el("div", "note",
        "Attributed from the capture itself, so every row is a host that "
        + "actually appeared in the traffic."));
      host.appendChild(sources);
    }

    var findings = el("div", "panel");
    findings.appendChild(el("h2", null, "Findings, highest risk first"));
    var fwrap = el("div", "table-scroll");
    var ftable = el("table");
    var fhead = el("tr");
    ["Domain", "Kind", "Risk", "Verdict", "Intel", "DGA", "Tunnel", "Reason"]
      .forEach(function (h) { fhead.appendChild(el("th", null, h)); });
    ftable.appendChild(fhead);
    (report.findings || []).forEach(function (f) {
      var tr = el("tr");
      tr.appendChild(el("td", null, f.domain));
      tr.appendChild(el("td", null, f.name_kind || "-"));
      var risk = el("td", "num", f.risk_score);
      risk.style.color = UI.scoreColor(f.risk_score);
      tr.appendChild(risk);
      var verdict = el("td");
      verdict.appendChild(el("span", "badge badge-" + f.decision, f.decision));
      tr.appendChild(verdict);
      tr.appendChild(el("td", null, f.threat_intel));
      tr.appendChild(el("td", null, f.dga_detected ? "YES (" + f.dga_score + ")" : "no"));
      tr.appendChild(el("td", null, f.tunnel_detected
        ? "YES (" + f.tunnel_indicators.join(", ") + ")" : "no"));
      tr.appendChild(el("td", null, f.reason));
      ftable.appendChild(tr);
    });
    fwrap.appendChild(ftable);
    findings.appendChild(fwrap);
    findings.appendChild(el("div", "note",
      "Every verdict here was produced by the same engine that serves the "
      + "Domain Analysis view. Analysing one of these names there gives the "
      + "same score."));
    host.appendChild(findings);

    if (report.rejected && report.rejected.length) {
      var bad = el("div", "panel");
      bad.appendChild(el("h2", null, "Names the parser could not accept"));
      report.rejected.forEach(function (r) {
        bad.appendChild(el("div", "proto-detail",
          r.domain + " — " + r.code + ": " + r.message));
      });
      host.appendChild(bad);
    }
  }

  function upload(file, endpoint, kind) {
    $("captureFileName").textContent = file.name + " (" + (file.size / 1024).toFixed(1) + " KB)";
    var host = $("captureResult");
    host.innerHTML = "";
    host.appendChild(el("div", "panel muted",
      "Reading " + kind + " and analysing every unique name…"));

    request(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: file
    }).then(function (response) {
      if (!response.ok) {
        var e = (response.data && response.data.error) || {};
        host.innerHTML = "";
        var box = el("div", "panel error");
        box.appendChild(el("div", "error-code", e.code || "UPLOAD_FAILED"));
        box.appendChild(el("div", null, e.message || "The file could not be read."));
        host.appendChild(box);
        return;
      }
      renderReport(response.data);
    }).catch(function (err) {
      host.innerHTML = "";
      var box = el("div", "panel error");
      box.appendChild(el("div", "error-code", "UPLOAD_ERROR"));
      box.appendChild(el("div", null, String(err)));
      host.appendChild(box);
    });
  }

  $("pcapInput").addEventListener("change", function (e) {
    if (e.target.files[0]) upload(e.target.files[0], "/api/capture/pcap", "the capture");
  });
  $("zeekInput").addEventListener("change", function (e) {
    if (e.target.files[0]) upload(e.target.files[0], "/api/capture/zeek", "the Zeek log");
  });

  window.CaptureView = { load: function () { renderPipeline(); renderSupport(); } };
})();
