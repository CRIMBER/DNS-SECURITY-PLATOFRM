"""The Activity Log view, and the status strip above it.

Two things are being protected here.

The first is a contract: the log view renders entirely from ``/api/events``,
``/api/health`` and ``/api/dns/status``. There is no second log store, so if a
field the view reads stops being returned, the log quietly loses information
rather than failing loudly. These tests pin the fields it reads.

The second is honesty. The status strip has exactly one dangerous state - it
must never say DNS Protection is Active unless the backend reports the gateway
running. A green light over a resolver that is switched off is worse than no
light at all, and it is the kind of thing that survives review because it looks
tidy. The source checks below exist so that it cannot be introduced quietly.

The JavaScript assertions are source checks, for the reason already recorded in
``test_frontend_contract.py``: this project has no JS runtime in its toolchain.
They catch a regression written in the obvious way, not one written to evade
them.
"""

import io
import os

import pytest
from fastapi.testclient import TestClient

from backend.app.main import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOGS_JS = os.path.join(ROOT, "frontend", "js", "logs.js")
APP_JS = os.path.join(ROOT, "frontend", "js", "app.js")
INDEX_HTML = os.path.join(ROOT, "frontend", "index.html")
CSS = os.path.join(ROOT, "frontend", "css", "styles.css")


def _strip_comments(source):
    """Executable JavaScript only, so a comment cannot fail a source check."""
    out, i, n = [], 0, len(source)
    while i < n:
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            i = n if end == -1 else end + 2
        elif source.startswith("//", i):
            end = source.find(chr(10), i)
            i = n if end == -1 else end
        else:
            out.append(source[i]); i += 1
    return "".join(out)


def read(path):
    return io.open(path, encoding="utf-8").read()


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app(), raise_server_exceptions=False)


@pytest.fixture(scope="module")
def logs_js():
    return read(LOGS_JS)


@pytest.fixture(scope="module")
def app_js():
    return read(APP_JS)


@pytest.fixture(scope="module")
def index_html():
    return read(INDEX_HTML)


@pytest.fixture(scope="module")
def css():
    return read(CSS)


# -- 1. the log renders from the existing event store ------------------------


class TestLogDataContract:
    def test_events_endpoint_supplies_every_field_the_log_renders(self, client):
        client.post("/api/analyze", json={"domain": "malware-c2-panel.test"})
        body = client.get("/api/events?limit=1").json()
        assert body["events"], "the log has nothing to render"
        event = body["events"][0]

        for field in (
            "timestamp",          # [10:42:18]
            "domain",             # the subject line
            "decision",           # severity is derived from this
            "risk_score",         # the message
            "classification",
            "event_type",         # the category column
            "threat_intelligence_verdict",
            "top_factors",        # expandable evidence
            "overrides_applied",
            "analysis_time_ms",
        ):
            assert field in event, "log row reads {!r}".format(field)

    def test_dns_events_carry_the_extra_fields_the_detail_panel_reads(self, client):
        body = client.get("/api/events?limit=1").json()
        event = body["events"][0]
        # Present on every row; populated only for gateway events.
        for field in ("query_type", "response_code", "upstream_used",
                      "cache_hit", "client_address"):
            assert field in event

    def test_domain_search_is_served_by_the_existing_api(self, client):
        """The search box uses ?q= rather than filtering in the browser."""
        client.post("/api/analyze", json={"domain": "github.com"})
        body = client.get("/api/events?q=github&limit=50").json()
        assert body["events"]
        assert all("github" in e["domain"] for e in body["events"])

    def test_health_supplies_the_three_status_cells(self, client):
        body = client.get("/api/health").json()
        assert "status" in body
        components = body["components"]
        assert "dns_gateway" in components and "status" in components["dns_gateway"]
        assert "risk_engine" in components


# -- 2. severity is derived, never invented ----------------------------------


class TestSeverityIsDerivedFromRecordedFacts:
    def test_severity_keys_only_off_fields_the_backend_records(self, logs_js):
        block = logs_js.index("function severityOf")
        body = logs_js[block:logs_js.index("}", logs_js.index("return \"INFO\""))]
        assert 'event.decision === "BLOCK"' in body
        assert 'event.response_code === "SERVFAIL"' in body
        assert 'event.decision === "MONITOR"' in body

    def test_blocked_severity_exists_for_blocked_decisions(self, logs_js):
        assert '"BLOCKED"' in logs_js

    def test_log_does_not_invent_a_timestamp_for_standing_conditions(self, logs_js):
        """A current condition is not an event and gets no clock time."""
        assert "Date.now()" not in logs_js
        assert "new Date()" not in logs_js
        assert '"current"' in logs_js


# -- 3. privacy: the log does not widen what is shown ------------------------


class TestLogRespectsClientPrivacy:
    def test_client_address_is_shown_only_when_present(self, logs_js):
        assert "if (event.client_address) rows.push" in logs_js

    def test_log_does_not_reach_for_the_privacy_policy(self, logs_js):
        """Prose about the policy is fine; code that consults it is not.

        The view must take the address the event carries and nothing else -
        it has no business asking what the policy is, still less widening it.
        """
        code = _strip_comments(logs_js)
        assert "DNS_LOG_CLIENT_IP" not in code
        assert "log_client_ip" not in code
        assert "/api/sources" not in code, (
            "per-client telemetry is a different view; the log reads events"
        )


# -- 4. the status strip cannot flatter --------------------------------------


class TestStatusStripHonesty:
    def test_active_requires_the_gateway_to_be_running(self, app_js):
        start = app_js.index("function renderSysbar")
        end = app_js.index("/* -- risk gauge", start)
        sysbar = app_js[start:end]
        active = sysbar.index('"Active"')
        guard = sysbar.rindex('gw.status === "ok"', 0, active)
        between = sysbar[guard:active]
        assert "else" not in between, (
            "DNS Protection must read Active only inside the gateway-ok branch"
        )

    def test_disabled_and_unavailable_are_distinct_states(self, app_js):
        assert '"Disabled"' in app_js
        assert '"Unavailable"' in app_js

    def test_disabled_state_explains_itself(self, app_js):
        assert "not available in this deployment" in app_js


# -- 5. implementation detail left the dashboard -----------------------------


class TestDashboardCarriesNoImplementationDetail:
    NOISE = [
        "risk policy",
        "indicators, ",
        "-label corpus",
        "no accuracy claimed",
        "confidence_weighted_average",
        "bigram_llr_v1",
    ]

    def test_masthead_no_longer_prints_engine_internals(self, app_js):
        assert "statusLine" not in app_js, "the internal status line is gone"
        start = app_js.index("function renderSysbar")
        end = app_js.index("/* -- risk gauge", start)
        sysbar = app_js[start:end]
        for term in self.NOISE:
            assert term not in sysbar, "{!r} belongs in Diagnostics".format(term)

    def test_status_line_element_is_removed_from_the_page(self, index_html):
        assert 'id="statusLine"' not in index_html

    def test_diagnostics_exists_and_is_collapsed_by_default(self, index_html):
        assert 'id="logDiagnostics"' in index_html
        block = index_html[index_html.index('class="panel diagnostics"'):]
        opening = block[: block.index(">")]
        assert " open" not in opening, "diagnostics must start collapsed"

    def test_engineering_detail_is_still_available_somewhere(self, logs_js):
        """Removed from the dashboard, not destroyed."""
        assert "renderDiagnostics" in logs_js
        assert "corpus_size" in logs_js
        assert "fusion" in logs_js


# -- 6. the log is a view, not a second source of truth ----------------------


class TestNoCompetingLogStore:
    def test_log_reads_the_existing_endpoints(self, logs_js):
        assert "/api/events" in logs_js
        assert "/api/health" in logs_js
        assert "/api/dns/status" in logs_js

    def test_log_does_not_write_anything(self, logs_js):
        for verb in ('method: "POST"', 'method: "DELETE"', "localStorage",
                     "sessionStorage"):
            assert verb not in logs_js

    def test_viewing_the_log_does_not_change_a_verdict(self, client):
        """Rendering must not perturb scoring - the log is read-only."""
        first = client.post("/api/analyze", json={"domain": "kq3v9z7jx1p8w.info"}).json()
        client.get("/api/events?limit=100")
        client.get("/api/health")
        second = client.post("/api/analyze", json={"domain": "kq3v9z7jx1p8w.info"}).json()
        assert first["risk_score"] == second["risk_score"]
        assert first["decision"] == second["decision"]


# -- 7. Phase 5B: the product surface ----------------------------------------


class TestActivityFeedPresentation:
    """The log is a product activity table, not a console dump."""

    def test_table_has_the_named_columns(self, logs_js):
        for column in ("Time", "Domain", "Action", "Risk", "Decision", "Source"):
            assert '"%s"' % column in logs_js

    def test_decision_is_shown_as_a_badge(self, logs_js):
        assert 'badge badge-" + event.decision' in logs_js

    def test_source_falls_back_to_a_surface_not_a_fake_address(self, logs_js):
        """No client address means "which surface", never an invented client."""
        block = logs_js[logs_js.index("function sourceFor"):]
        block = block[: block.index("\n  }")]
        assert "event.client_address" in block
        assert '"DNS gateway"' in block and '"Dashboard"' in block

    def test_domain_cell_is_not_uppercased(self, css):
        """A regression that shipped once: the domain cell is a <button>, and
        the global button rule was uppercasing every domain name."""
        import re
        rule = css[css.index(".log-toggle {"):]
        rule = rule[: rule.index("}")]
        applied = re.search(r"text-transform:\s*([a-z-]+)", rule)
        assert applied is None or applied.group(1) == "none", (
            "the domain cell must not transform the case of a domain name"
        )
        button_rule = css[css.index("\nbutton {"):]
        button_rule = button_rule[: button_rule.index("}")]
        assert "uppercase" not in button_rule, (
            "the domain cell is a <button>; uppercasing it uppercases domains"
        )


class TestEmptyStateIsNotAnError:
    def test_empty_state_explains_the_disabled_gateway(self, logs_js):
        block = logs_js[logs_js.index("function emptyState"):]
        block = block[: block.index("\n  /* -- rendering")]
        assert 'gateway.status === "disabled"' in block
        assert "Connect the gateway" in block

    def test_empty_state_uses_no_failure_language(self, logs_js):
        block = logs_js[logs_js.index("function emptyState"):]
        block = block[: block.index("\n  /* -- rendering")]
        for word in ("error", "Error", "failed", "Failed", "problem", "wrong"):
            assert word not in block, "an empty log is a normal state"


class TestStatusPaletteStaysValidated:
    """The three verdict colours must keep passing the project validator.

    Re-stepping them for the light ground was the point of Phase 5B; this
    fails if someone later picks a red that a red-green viewer cannot tell
    from the amber.
    """

    def test_status_colours_pass_the_palette_validator(self, css):
        import re
        import subprocess
        import sys

        wanted = {}
        for name in ("safe", "warning", "critical"):
            m = re.search(r"--%s:\s*(#[0-9a-fA-F]{6});" % name, css)
            assert m, "--%s missing from the token block" % name
            wanted[name] = m.group(1)

        script = os.path.join(ROOT, "backend", "scripts", "validate_palette.py")
        result = subprocess.run(
            [sys.executable, script,
             ",".join([wanted["safe"], wanted["warning"], wanted["critical"]]),
             "--mode", "light", "--surface", "#ffffff"],
            capture_output=True, text=True)
        assert "RESULT: PASS" in result.stdout, result.stdout

    def test_surfaces_are_light(self, css):
        """A dark --bg would make every light-ground contrast claim false."""
        import re
        m = re.search(r"--bg:\s*(#[0-9a-fA-F]{6});", css)
        assert m
        r, g, b = (int(m.group(1)[i:i + 2], 16) for i in (1, 3, 5))
        assert (r + g + b) / 3 > 200, "the page ground is meant to be light"
