/* Threat Intelligence view.
 *
 * Feed state is whatever /api/intel/summary reports, which is whatever the
 * backend actually has. The bundled dataset is local and synthetic and says
 * so; STIX/TAXII and commercial feeds are shown as NOT CONNECTED because no
 * client for either exists in this build. A green dot next to a feed nobody
 * wired up is the one thing this page must never draw.
 */

(function () {
  "use strict";

  var UI = window.UI;
  var $ = UI.$, el = UI.el, request = UI.request;

  var STATE_CLASS = {
    ACTIVE: "ALLOW",
    NOT_CONNECTED: "UNKNOWN",
    ERROR: "BLOCK"
  };

  function renderFeeds(data) {
    var host = $("intelFeeds");
    host.innerHTML = "";
    data.feeds.forEach(function (feed) {
      var row = el("div", "feed-row");
      var left = el("div", "feed-main");
      left.appendChild(el("span", "feed-name", feed.name));
      left.appendChild(el("span", "badge badge-" + (STATE_CLASS[feed.state] || "UNKNOWN"),
                          feed.state.replace(/_/g, " ")));
      row.appendChild(left);
      var right = el("div", "feed-meta");
      if (feed.indicators) right.appendChild(el("span", null, feed.indicators + " indicators"));
      if (feed.last_updated) right.appendChild(el("span", "muted", " · updated " + feed.last_updated));
      row.appendChild(right);
      host.appendChild(row);
      host.appendChild(el("div", "proto-detail", feed.detail));
    });
    host.appendChild(el("div", "note", data.honesty_note));
  }

  function renderIndicators(data) {
    var host = $("intelIndicators");
    host.innerHTML = "";
    var p = data.provider || {};
    var tiles = el("div", "tiles");
    [
      ["Indicators", p.indicators_total || 0, "malicious + suspicious"],
      ["Trusted", p.trusted_total || 0, "allowlisted domains"],
      ["Source", null, null]
    ].forEach(function (item) {
      if (item[1] === null) return;
      var t = el("div", "tile");
      t.appendChild(el("div", "tile-k", item[0]));
      t.appendChild(el("div", "tile-v", item[1]));
      if (item[2]) t.appendChild(el("div", "tile-sub", item[2]));
      tiles.appendChild(t);
    });
    host.appendChild(tiles);

    var dl = el("dl", "kv");
    dl.style.marginTop = "15px";
    function row(k, v) {
      if (v === undefined || v === null) return;
      dl.appendChild(el("dt", null, k));
      dl.appendChild(el("dd", null, v));
    }
    row("Dataset", p.source);
    row("Last updated", p.last_updated);
    row("Match types", "exact domain, and parent-domain for subdomains");
    host.appendChild(dl);
    host.appendChild(el("div", "note",
      "An indicator match sets a floor on the score rather than deciding the "
      + "verdict alone, and an allowlist entry is set aside when tunnelling or "
      + "behavioural evidence contradicts it."));
  }

  function renderCategories(data) {
    var host = $("intelCategories");
    host.innerHTML = "";
    var categories = (data.provider || {}).categories || {};
    var entries = Object.keys(categories).map(function (k) {
      return { label: k, value: categories[k], color: "var(--critical)" };
    }).sort(function (a, b) { return b.value - a.value; });
    if (!entries.length) {
      return Charts.empty(host, "No categorised indicators in the dataset.");
    }
    Charts.horizontalBars(host, entries.slice(0, 12));
  }

  function load() {
    request("/api/intel/summary").then(function (response) {
      if (!response.ok) return;
      renderFeeds(response.data);
      renderIndicators(response.data);
      renderCategories(response.data);
      $("intelRefreshed").textContent =
        "re-read from the provider at " + new Date().toTimeString().slice(0, 8);
    });
  }

  /* Re-queries the provider and redraws. It does NOT pull from an external
     feed, because there is no external feed connected - see the NOT CONNECTED
     rows above. When one is wired in behind the same provider interface, this
     button refreshes it too without changing. */
  $("refreshFeedsBtn").addEventListener("click", load);

  window.IntelView = { load: load };
})();
