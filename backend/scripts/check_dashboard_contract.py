"""Render the dashboard in a real browser and check what it actually shows.

The frontend/API contract has a half that no Python test can reach: whether
``frontend/js/app.js`` survives the response it is handed. It did not, for
every name whose detectors legitimately abstain - it threw mid-render and
reported a perfectly good 200 as "Could not reach the analysis engine". The
suite could not see it, because the suite never ran the JavaScript.

This script does. It drives Chrome over the DevTools protocol, analyses each
name through the real UI, and fails if the page reports an error, logs a
console error, or hides a detector that abstained.

Usage
-----
  1. start a browser with remote debugging, e.g.
        chrome.exe --remote-debugging-port=9222 --user-data-dir=%TEMP%\\cdp
  2. start an instance to check. Prefer an isolated one, so that verifying
     the dashboard does not become history the behavioural detector reads
     back during a demo:

        set DNSSEC_PORT=8001
        set DNSSEC_DB_PATH=%TEMP%\\verify-events.db
        set DNS_ENABLED=0
        python run.py

  3. python -m backend.scripts.check_dashboard_contract --base http://127.0.0.1:8001

Checking the demo instance (the default, port 8000) is fine as a one-off:
eight analyses is well under the behavioural evidence threshold. Repeated
runs against it are what turn verification into history.

Exits non-zero on any failure. Requires ``websocket-client`` from
requirements-dev.txt; it is a development tool, not a runtime dependency.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000"
CDP_PORT = 9222

VIEWS = ["overview", "analyse", "activity", "dns", "analytics"]

# (name, must the Analyse view show at least one ABSTAINED detector?)
CASES = [
    ("192.168.1.10", True),
    ("8.8.8.8", True),
    ("42.1.168.192.in-addr.arpa", True),
    ("1.0.0.127.in-addr.arpa", True),
    ("Brother-MFC.local", True),
    ("github.com", True),                    # clean name: DGA/lexical abstain
    ("d1a2b3c4e5f6g7.cloudfront.net", True),  # provider host, TI abstains
    ("malware-c2-panel.test", True),
]

# Text the results pane must never contain for a request the API answered.
FORBIDDEN = ["NETWORK_ERROR", "Could not reach the analysis engine",
             "RENDER_ERROR", "PANEL_ERROR", "undefined", "NaN"]


class Browser(object):
    """The few DevTools calls this check needs."""

    def __init__(self, url):
        import websocket  # imported here so --help works without the dev extra

        request = urllib.request.Request(
            "http://127.0.0.1:%d/json/new?%s" % (CDP_PORT, url), method="PUT")
        target = json.loads(urllib.request.urlopen(request, timeout=10).read())
        self.target_id = target["id"]
        self.ws = websocket.create_connection(
            target["webSocketDebuggerUrl"], timeout=30, suppress_origin=True)
        self._id = 0
        self.console = []
        self.failed_requests = []
        self.last_analyze_request = None
        self.request_urls = {}

    def cmd(self, method, **params):
        self._id += 1
        self.ws.send(json.dumps({"id": self._id, "method": method, "params": params}))
        while True:
            message = json.loads(self.ws.recv())
            if message.get("id") == self._id:
                if "error" in message:
                    raise RuntimeError(method + ": " + json.dumps(message["error"]))
                return message.get("result", {})
            self._note(message)

    def _note(self, message):
        method = message.get("method")
        params = message.get("params", {})
        if method == "Network.requestWillBeSent":
            # loadingFailed carries no URL, so remember what each id was for.
            # Without this a browser-initiated favicon fetch reads as an
            # unattributable application failure.
            self.request_urls[params.get("requestId")] = params.get(
                "request", {}).get("url", "")
        if method == "Network.responseReceived":
            url = params.get("response", {}).get("url", "")
            if "/api/analyze" in url:
                self.last_analyze_request = params.get("requestId")
        if method == "Runtime.consoleAPICalled" and params.get("type") == "error":
            self.console.append(" ".join(
                str(a.get("value", a.get("description", "?")))
                for a in params.get("args", [])))
        elif method == "Runtime.exceptionThrown":
            detail = params.get("exceptionDetails", {})
            self.console.append("uncaught: " + str(detail.get("text"))
                                + " " + str(detail.get("url")))
        elif method == "Network.responseReceived":
            response = params.get("response", {})
            if response.get("status", 0) >= 400:
                self.failed_requests.append(
                    "%s %s" % (response.get("status"), response.get("url")))
        elif method == "Network.loadingFailed":
            self.failed_requests.append(
                "failed %s %s" % (params.get("errorText"),
                                  self.request_urls.get(params.get("requestId"), "?")))

    def drain(self, seconds):
        """Collect events for a while without issuing a command."""
        deadline = time.time() + seconds
        self.ws.settimeout(0.4)
        try:
            while time.time() < deadline:
                try:
                    self._note(json.loads(self.ws.recv()))
                except Exception:
                    pass
        finally:
            self.ws.settimeout(30)

    def js(self, expression):
        result = self.cmd("Runtime.evaluate", expression=expression,
                          returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in result:
            raise RuntimeError("page threw: "
                               + json.dumps(result["exceptionDetails"])[:400])
        return result["result"].get("value")

    def analyze_response(self):
        """The body of the last /api/analyze response the page received."""
        if self.last_analyze_request is None:
            return None
        body = self.cmd("Network.getResponseBody",
                        requestId=self.last_analyze_request)
        return json.loads(body["body"])

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass
        try:
            urllib.request.urlopen(
                "http://127.0.0.1:%d/json/close/%s" % (CDP_PORT, self.target_id),
                timeout=5).read()
        except Exception:
            pass


def main(argv=None):
    global BASE, CDP_PORT

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default=BASE,
                        help="platform to check (default %(default)s). Point "
                             "this at an isolated instance to keep "
                             "verification traffic out of the demo event log.")
    parser.add_argument("--cdp-port", type=int, default=CDP_PORT,
                        help="Chrome DevTools port (default %(default)s)")
    args = parser.parse_args(argv)
    BASE = args.base.rstrip("/")
    CDP_PORT = args.cdp_port

    failures = []
    print("checking %s via CDP port %d" % (BASE, CDP_PORT))

    try:
        urllib.request.urlopen(BASE + "/api/health", timeout=5).read()
    except Exception as exc:
        print("the platform is not running on %s (%s). Start it with "
              "'python run.py'." % (BASE, exc))
        return 2

    try:
        browser = Browser(BASE + "/")
    except Exception as exc:
        print("no browser on CDP port %d (%s). Start Chrome with "
              "--remote-debugging-port=%d." % (CDP_PORT, exc, CDP_PORT))
        return 2

    try:
        browser.cmd("Page.enable")
        browser.cmd("Runtime.enable")
        browser.cmd("Network.enable")
        # Without this the browser serves the previous app.js from cache and
        # the check silently verifies the bug it was written to catch.
        browser.cmd("Network.setCacheDisabled", cacheDisabled=True)
        browser.cmd("Page.reload", ignoreCache=True)
        browser.drain(5)

        print("=" * 92)
        print("ANALYSE VIEW - what the dashboard displays vs what the API returned")
        print("=" * 92)
        print("%-32s %5s %5s %-9s %-9s %s"
              % ("NAME", "UI", "API", "VERDICT", "ABSTAINED", "RESULT"))

        for domain, expect_abstention in CASES:
            browser.js("""(function () {
              document.querySelector('.tab[data-tab="analyse"]').click();
              var input = document.getElementById('domainInput');
              input.value = %s;
              input.dispatchEvent(new Event('input', {bubbles: true}));
              document.getElementById('analyzeBtn').click();
            })()""" % json.dumps(domain))
            browser.drain(2.6)

            shown = browser.js("""(function () {
              var root = document.getElementById('results');
              var score = root.querySelector('.verdict-score');
              var badges = [];
              var nodes = root.querySelectorAll('.badge');
              for (var i = 0; i < nodes.length; i++) {
                badges.push(nodes[i].innerText.trim());
              }
              // textContent, not innerText: the stylesheet uppercases these
              // headings and innerText would return what CSS painted.
              var titles = [];
              var heads = root.querySelectorAll('h2');
              for (var j = 0; j < heads.length; j++) {
                titles.push(heads[j].textContent.trim());
              }
              var name = root.querySelector('.domain-name');
              return {
                score: score ? parseInt(score.childNodes[0].nodeValue.trim(), 10) : null,
                badges: badges,
                titles: titles,
                domain: name ? name.innerText.trim() : null,
                text: root.innerText
              };
            })()""")

            # The behavioural detector reads this domain's query history, so
            # asking the API the same question a second time is a different
            # question with a legitimately different answer. Compare against
            # the exact bytes the page was handed instead.
            expected = browser.analyze_response()
            if expected is None:
                failures.append((domain, ["the page never received a response"]))
                continue
            problems = []
            if shown["score"] != expected["risk_score"]:
                problems.append("score %s != API %s"
                                % (shown["score"], expected["risk_score"]))
            if expected["decision"] not in shown["badges"]:
                problems.append("verdict %s not shown" % expected["decision"])
            if shown["domain"] != expected["domain"]:
                problems.append("domain %r != API %r"
                                % (shown["domain"], expected["domain"]))
            for banned in FORBIDDEN:
                if banned in shown["text"]:
                    problems.append("page shows %r" % banned)

            abstained = shown["badges"].count("ABSTAINED")
            if expect_abstention and not abstained:
                problems.append("no detector reported ABSTAINED")

            # The recommendation sits directly above the factor list. It must
            # not deny evidence the reader can see beneath it.
            action = (expected.get("recommended_action") or "").lower()
            contributed = [f for f in expected["risk_factors"]
                           if f["contribution"] > 0]
            if contributed:
                for denial in ("no signal reported", "no signal had",
                               "reported no risk indicators"):
                    if denial in action:
                        problems.append(
                            "recommendation says %r while %s contributed %+.1f"
                            % (denial, contributed[0]["code"],
                               contributed[0]["contribution"]))
            if action not in shown["text"].lower():
                problems.append("recommended action not displayed")

            # Every detector must appear, abstaining or not. A panel that
            # disappears tells an analyst nothing about whether it ran.
            for panel in ("Name Classification", "Signal Fusion",
                          "DGA / Suspicion Analysis", "DNS Tunnelling Analysis",
                          "Behavioural Analysis"):
                if panel not in shown["titles"]:
                    problems.append("missing panel: " + panel)

            print("%-32s %5s %5s %-9s %-9s %s"
                  % (domain[:32], shown["score"], expected["risk_score"],
                     expected["decision"], abstained,
                     "ok" if not problems else "; ".join(problems)))
            if problems:
                failures.append((domain, problems))

        print()
        print("=" * 92)
        print("ALL FIVE VIEWS")
        print("=" * 92)
        for view in VIEWS:
            before = len(browser.console)
            browser.js("""document.querySelector('.tab[data-tab="%s"]').click()"""
                       % view)
            browser.drain(1.6)
            state = browser.js("""(function () {
              var root = document.getElementById('view-%s');
              return {
                visible: !root.classList.contains('hidden'),
                panels: root.querySelectorAll('.panel').length,
                chars: root.innerText.trim().length,
                sideways: document.documentElement.scrollWidth
                          > document.documentElement.clientWidth + 1
              };
            })()""" % view)
            errors = len(browser.console) - before
            problems = []
            if not state["visible"]:
                problems.append("view did not become visible")
            if state["chars"] < 40:
                problems.append("view rendered empty")
            if state["sideways"]:
                problems.append("page scrolls sideways")
            if errors:
                problems.append("%d console errors" % errors)
            print("%-10s panels=%-3s chars=%-6s %s"
                  % (view, state["panels"], state["chars"],
                     "ok" if not problems else "; ".join(problems)))
            if problems:
                failures.append((view, problems))

        # Event drill-down still toggles.
        browser.js("""document.querySelector('.tab[data-tab="dns"]').click()""")
        browser.drain(2.5)
        toggle = browser.js("""(function () {
          var rows = document.querySelectorAll('#dnsEventsTable tr.expandable');
          if (!rows.length) return {rows: 0};
          var detail = rows[0].nextSibling;
          var before = detail.classList.contains('hidden');
          rows[0].click();
          var opened = detail.classList.contains('hidden');
          rows[0].click();
          var closed = detail.classList.contains('hidden');
          return {rows: rows.length, before: before, opened: opened, closed: closed};
        })()""")
        print()
        print("event drill-down: rows=%s hidden before/open/reclosed = %s/%s/%s"
              % (toggle.get("rows"), toggle.get("before"),
                 toggle.get("opened"), toggle.get("closed")))
        if not toggle.get("rows"):
            # An isolated verification instance has no gateway history. Say so
            # rather than reporting a broken control that was never shown.
            print("   no DNS events in this instance - drill-down not exercised "
                  "here; run against an instance with gateway history to cover it")
        elif not (toggle.get("before") is True and toggle.get("opened") is False
                  and toggle.get("closed") is True):
            failures.append(("event drill-down", ["row did not toggle open/closed"]))

        # /favicon.ico is requested by the browser itself, not by the page.
        app_failures = [f for f in browser.failed_requests if "favicon" not in f]
        print()
        print("console errors      :", len(browser.console))
        for line in browser.console[:10]:
            print("   ", line[:160])
        print("failed requests     :", len(app_failures),
              "(browser-initiated favicon requests excluded:",
              len(browser.failed_requests) - len(app_failures), ")")
        for line in app_failures[:10]:
            print("   ", line[:160])
        if browser.console:
            failures.append(("console", browser.console[:5]))
        if app_failures:
            failures.append(("requests", app_failures[:5]))
    finally:
        browser.close()

    print()
    print("=" * 92)
    if failures:
        print("FAILED")
        for where, problems in failures:
            print("  %s: %s" % (where, "; ".join(problems)))
        return 1
    print("PASSED - every detector rendered, abstentions shown as abstentions, "
          "no network error for a successful analysis")
    return 0


if __name__ == "__main__":
    sys.exit(main())
