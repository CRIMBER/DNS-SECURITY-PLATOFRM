"""The contract the dashboard renders against.

A detector that abstains returns a 200 with a complete body. The dashboard
used to read a measurement that an abstaining detector never took, throw
mid-render, and report the whole thing as "Could not reach the analysis
engine" - blaming the network for a backend that had answered perfectly, on
exactly the names the classification layer exists to handle.

These tests pin both halves of that contract:

  * the API always describes an abstention well enough to render it - the
    signal accounting is present, and some factor carries the reason;
  * ``frontend/js/app.js`` never dereferences an optional measurement
    without a guard, and never reports a successful analysis as a network
    failure.

The second half is a source check rather than a DOM test: this project has
no JavaScript runtime in its toolchain, and adding one to assert a handful
of invariants would cost more than it proves. What it cannot catch is
stated in the class docstring rather than papered over.
"""

import io
import os
import re

import pytest
from fastapi.testclient import TestClient

from backend.app.main import create_app

FRONTEND = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "frontend", "js", "app.js",
)

# The names that must render an abstention, plus the ones that exercise the
# other side of each branch. Every one of these must render.
ABSTAINING_NAMES = [
    "192.168.1.10",                 # private IPv4 literal
    "8.8.8.8",                      # public IPv4 literal
    "42.1.168.192.in-addr.arpa",    # reverse DNS, private target
    "1.0.0.127.in-addr.arpa",       # reverse DNS, loopback target
    "Brother-MFC.local",            # mDNS device name
]

CONTRIBUTING_NAMES = [
    "github.com",                     # ordinary registrable domain
    "d1a2b3c4e5f6g7.cloudfront.net",  # provider namespace
    "malware-c2-panel.test",          # known malicious
]

ALL_NAMES = ABSTAINING_NAMES + CONTRIBUTING_NAMES

SIGNAL_NAMES = ["threat_intel", "dga", "lexical", "tunnel", "behavioral"]

# Mirrors FACTOR_PREFIX in app.js. If a signal is renamed on one side and not
# the other the dashboard silently loses its reason text, so assert it here.
FACTOR_PREFIX = {
    "threat_intel": "TI_",
    "dga": "DGA_",
    "lexical": "LEXICAL_",
    "tunnel": "DNS_TUNNEL_",
    "behavioral": "BEHAVIORAL_",
}


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app(), raise_server_exceptions=False)


@pytest.fixture(scope="module")
def app_js():
    return io.open(FRONTEND, encoding="utf-8").read()


def analyse(client, domain):
    response = client.post("/api/analyze",
                           json={"domain": domain, "source": "contract-test"})
    assert response.status_code == 200, (domain, response.status_code, response.text)
    return response.json()


class TestAbstentionIsASuccessfulResponse:
    """An abstaining detector is a 200 with a full body, never an error."""

    @pytest.mark.parametrize("domain", ALL_NAMES)
    def test_analysis_succeeds(self, client, domain):
        body = analyse(client, domain)
        assert "error" not in body
        assert body["decision"] in {"ALLOW", "MONITOR", "BLOCK"}

    @pytest.mark.parametrize("domain", ABSTAINING_NAMES)
    def test_at_least_one_detector_abstains(self, client, domain):
        body = analyse(client, domain)
        abstaining = [s for s in body["signals"] if not s["used_in_fusion"]]
        assert abstaining, "expected an abstention to render for " + domain

    @pytest.mark.parametrize("domain", ABSTAINING_NAMES)
    def test_name_shape_detectors_abstain_where_there_is_no_label(self, client, domain):
        """None of these names has a registrant-chosen label to read."""
        body = analyse(client, domain)
        by_name = {s["name"]: s for s in body["signals"]}
        assert by_name["dga"]["used_in_fusion"] is False, domain
        assert by_name["lexical"]["used_in_fusion"] is False, domain


class TestEveryAbstentionCanBeRendered:
    """Whatever the dashboard needs to draw an abstention must be present."""

    @pytest.mark.parametrize("domain", ALL_NAMES)
    def test_every_signal_reports_full_accounting(self, client, domain):
        body = analyse(client, domain)
        names = [s["name"] for s in body["signals"]]
        assert names == SIGNAL_NAMES, domain
        for signal in body["signals"]:
            # Score, confidence and weight are shown for abstaining signals
            # too - that is the whole point of the panel.
            for field in ("score", "confidence", "weight", "weighted_contribution"):
                assert isinstance(signal[field], (int, float)), (domain, signal["name"])
            assert isinstance(signal["used_in_fusion"], bool)

    @pytest.mark.parametrize("domain", ALL_NAMES)
    def test_every_abstaining_signal_carries_a_reason(self, client, domain):
        body = analyse(client, domain)
        codes = [f["code"] for f in body["risk_factors"] if f["detail"]]
        for signal in body["signals"]:
            if signal["used_in_fusion"]:
                continue
            prefix = FACTOR_PREFIX[signal["name"]]
            assert any(code.startswith(prefix) for code in codes), (
                "no factor explains why %s abstained on %s; the dashboard "
                "would have nothing to show" % (signal["name"], domain))

    @pytest.mark.parametrize("domain", ABSTAINING_NAMES)
    def test_dga_abstention_is_distinguishable_from_a_measured_zero(
            self, client, domain):
        """Empty components is how the UI knows no measurement happened.

        The dashboard branches on exactly this to choose between printing a
        number and saying "not measured". A change that filled the components
        in with zeros would make the UI claim a measurement that never
        happened.
        """
        dga = analyse(client, domain)["dga_analysis"]
        assert dga["components"] == {}, domain
        assert dga["notes"], "an abstaining detector must say why: " + domain
        assert dga["model"] and dga["model_type"], domain

    @pytest.mark.parametrize("domain", CONTRIBUTING_NAMES)
    def test_a_measured_dga_result_still_carries_its_components(self, client, domain):
        dga = analyse(client, domain)["dga_analysis"]
        assert "bigram_llr" in dga["components"], domain

    @pytest.mark.parametrize("domain", ALL_NAMES)
    def test_tunnel_and_behavioral_always_describe_themselves(self, client, domain):
        body = analyse(client, domain)
        for key in ("tunnel_analysis", "behavioral_analysis"):
            block = body[key]
            assert block, (domain, key)
            assert block["method"] and block["method_type"], (domain, key)
            assert isinstance(block["indicators"], list), (domain, key)
            assert isinstance(block["confidence"], (int, float)), (domain, key)

    def test_tunnel_says_when_there_was_nothing_to_measure(self, client):
        """An IP literal has no span that could carry a payload.

        The dashboard shows measurements for "examined, found nothing" and
        withholds them for "never ran". It tells the two apart by this flag.
        """
        body = analyse(client, "192.168.1.10")
        assert body["tunnel_analysis"]["measurements"]["not_applicable"] is True

        body = analyse(client, "github.com")
        assert not body["tunnel_analysis"]["measurements"].get("not_applicable")


class TestNameClassificationIsExposed:
    """The classification panel renders what the pipeline already returns."""

    @pytest.mark.parametrize("domain", ALL_NAMES)
    def test_classification_is_present_and_complete(self, client, domain):
        nc = analyse(client, domain)["domain_features"]["name_classification"]
        assert nc, domain
        for field in ("kind", "suffix_kind", "scopes",
                      "scope_is_registrant_chosen", "reason"):
            assert field in nc, (domain, field)
        assert nc["reason"], domain
        assert isinstance(nc["scopes"], dict), domain

    def test_dashboard_labels_every_kind_the_backend_can_emit(self, app_js):
        from backend.app.core.classification import NameKind

        block = app_js[app_js.index("var KIND_LABEL"):app_js.index("var SCOPE_LABEL")]
        for kind in NameKind:
            assert kind.value in block, (
                "app.js has no label for NameKind." + kind.name)

    def test_reverse_dns_target_is_decoded_for_display(self, client):
        nc = analyse(client, "42.1.168.192.in-addr.arpa")[
            "domain_features"]["name_classification"]
        assert nc["is_reverse_dns"] is True
        assert nc["reverse_target"] == "192.168.1.42"

    def test_ip_literal_carries_what_the_panel_prints(self, client):
        nc = analyse(client, "192.168.1.10")["domain_features"]["name_classification"]
        assert nc["ip_address"] == "192.168.1.10"
        assert nc["ip_version"] == 4
        assert nc["ip_is_private"] is True


class TestDashboardCannotReportSuccessAsANetworkError:
    """Source-level guards in app.js.

    These are string checks over the frontend, not a rendering test: there is
    no JS runtime in this project's toolchain. They catch a reintroduced
    unguarded read or a re-merged panel-order regression. They cannot catch a
    brand-new crash in a differently-written line - the browser check in
    ``backend/scripts/check_dashboard_contract.py`` covers that by actually
    rendering every one of these names in Chrome.
    """

    def test_dga_components_are_never_read_unguarded(self, app_js):
        """``c.bigram_llr.toFixed()`` on an abstaining result was the bug."""
        block = app_js[app_js.index("function renderDGA"):
                       app_js.index("function renderTunnel")]
        guard = block.index("var measured = c.bigram_llr !== undefined;")
        first_use = block.index("c.bigram_llr.toFixed")
        assert guard < first_use, "the guard must precede the dereference"
        assert "if (!measured) {" in block
        assert 'abstentionPanel("DGA / Suspicion Analysis"' in block

    def test_no_detector_panel_disappears_when_it_abstains(self, app_js):
        """Returning null hid the detector instead of reporting abstention."""
        for name in ("renderTunnel", "renderBehavioral"):
            start = app_js.index("function " + name)
            end = app_js.index("  function ", start + 10)
            body = app_js[start:end]
            assert "return null;" not in body, (
                name + " still hides itself instead of saying it abstained")
            assert "abstentionPanel(" in body, name

    def test_every_panel_is_rendered_in_isolation(self, app_js):
        """One panel throwing must not blank the page or blame the network."""
        block = app_js[app_js.index("PANELS.forEach"):
                       app_js.index("loadStats();     //")]
        assert "try {" in block and "catch (panelError)" in block
        assert "PANEL_ERROR" in block
        assert "NETWORK_ERROR" not in block

    def test_a_render_failure_is_named_a_render_failure(self, app_js):
        block = app_js[app_js.index(".catch(function (err)"):]
        assert "RENDER_ERROR" in block
        assert "NETWORK_ERROR" in block
        # The render case must be tested first, or it is all a network error
        # again.
        assert block.index("RENDER_ERROR") < block.index("NETWORK_ERROR")

    def test_abstention_is_not_painted_as_a_safe_verdict(self, app_js):
        """A green SAFE badge on an abstention states the very thing the
        abstention exists to avoid saying."""
        block = app_js[app_js.index("function abstentionPanel"):
                       app_js.index("var KIND_LABEL")]
        assert "badge badge-ABSTAIN" in block
        assert "badge-SAFE" not in block

    def test_abstention_does_not_print_an_unmeasured_zero(self, app_js):
        block = app_js[app_js.index("function abstentionPanel"):
                       app_js.index("var KIND_LABEL")]
        assert "not measured" in block
        assert "measured, not used as evidence" in block

    def test_signal_prefixes_match_the_backend(self, app_js):
        block = app_js[app_js.index("var FACTOR_PREFIX"):
                       app_js.index("function signalOf")]
        for name, prefix in FACTOR_PREFIX.items():
            pattern = re.escape(name) + r'\s*:\s*"' + re.escape(prefix) + r'"'
            assert re.search(pattern, block), name
