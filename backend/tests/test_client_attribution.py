"""Client-aware behavioural attribution (Phase 4).

Attribution, not scoring. The behavioural signal that reaches risk fusion is
still computed from DOMAIN-WIDE history exactly as before; the client-scoped
view added here answers a different question - *which device* produced the
behaviour - and is carried alongside for display.

The tests are therefore split in two: one half pins the new client-scoped
selection, and the other half pins that nothing the old path returns has
moved. If a later change makes the client-scoped history feed fusion, the
Phase 3 regression cases below are what will fail.

An unattributed event is never guessed at. Rows with no client address, and
analysis events that never had a client to begin with, stay out of every
client-scoped answer and are reported separately.
"""

import asyncio

import dns.flags
import dns.message
import dns.rdatatype
import pytest
from fastapi.testclient import TestClient

from backend.app.core.pipeline import get_pipeline
from backend.app.main import create_app
from backend.app.detection import HistoryBehavioralAnalyzer
from backend.app.dns_gateway import (
    DNSCache,
    DNSRequestHandler,
    StubUpstreamResolver,
    get_policy,
)
from backend.app.dns_gateway.models import DNSContext
from backend.app.storage.db import connect
from backend.app.storage.events import EventRepository, set_event_repository

TUNNEL_NAME = (
    "mfrggzdfmztwq2lknnwg23tpobyxg43u.nnwg23tpobyxg43u.mfrggzdfmztwq2lk."
    "obyxg43uom.grsxg5a.tunnel-demo.invalid"
)


def make_answer(query_wire: bytes) -> bytes:
    query = dns.message.from_wire(query_wire)
    response = dns.message.make_response(query)
    response.flags |= dns.flags.RA
    return response.to_wire()


def seed(
    repository,
    domain,
    client_address=None,
    times=1,
    response_code="NOERROR",
    blocked=False,
    as_analysis=False,
):
    """Write real events for a domain, as either a DNS query or an analysis."""
    pipeline = get_pipeline()
    for _ in range(times):
        result = pipeline.analyse(domain)
        if as_analysis:
            repository.log(result, source="api")
        else:
            repository.log(
                result,
                source="dns",
                dns=DNSContext(
                    query_type="A",
                    client_address=client_address,
                    response_code=response_code,
                    blocked=blocked,
                ),
            )


@pytest.fixture
def repository(tmp_path):
    return EventRepository(path=tmp_path / "attribution.db")


@pytest.fixture
def analyzer(repository):
    return HistoryBehavioralAnalyzer(repository=repository)


# -- 1. the existing domain-wide path is untouched ---------------------------


class TestBackwardCompatibility:
    def test_domain_history_without_client_spans_every_client(self, repository):
        """No client filter: the domain-wide slice still crosses all clients.

        This test used to assert that the slice counted every stored row, six
        of six. That pin was deliberately relaxed in Phase 5C, and the reason
        is a security property rather than a tidy-up: counting each repeated
        ANALYSIS row let repetition manufacture behavioural evidence, and
        because a query burst scores lower than a strong verdict, joining the
        weighted average pulled BLOCK down to MONITOR. Re-inspecting a name
        already seen is not new evidence, so an analysis event now counts once
        per distinct name while every DNS event still counts - beaconing is
        repetition and must keep counting. See ``_HISTORY_COLUMNS``.

        What this test was really protecting - that the domain-wide slice is
        not narrowed to one client - is asserted below and is unchanged.
        """
        seed(repository, "mixed-demo.test", client_address="10.0.0.1", times=2)
        seed(repository, "mixed-demo.test", client_address=None, times=1)
        seed(repository, "mixed-demo.test", as_analysis=True, times=3)

        history = repository.domain_history("mixed-demo.test")
        # 3 DNS events across two different clients (one of them unrecorded),
        # plus 3 identical analyses of one name, which are one observation.
        assert history["total_queries"] == 4

    def test_repeated_analysis_of_one_name_is_one_observation(self, repository):
        """The idempotency property, at the storage layer."""
        seed(repository, "repeat-demo.test", as_analysis=True, times=1)
        once = repository.domain_history("repeat-demo.test")["total_queries"]
        seed(repository, "repeat-demo.test", as_analysis=True, times=24)
        many = repository.domain_history("repeat-demo.test")["total_queries"]
        assert once == many == 1, (
            "re-analysing the same name must not accumulate history"
        )

    def test_repeated_dns_queries_still_accumulate(self, repository):
        """Beaconing is repetition, and repetition is the evidence."""
        seed(repository, "beacon-demo.test", client_address="10.0.0.9", times=25)
        assert repository.domain_history("beacon-demo.test")["total_queries"] == 25

    def test_positional_window_argument_still_works(self, repository):
        """The one existing call site passes window_minutes; keep it valid."""
        seed(repository, "legacy-demo.test", times=4)
        assert repository.domain_history("legacy-demo.test", 60)[
            "total_queries"
        ] == 4

    def test_analyser_still_reads_domain_wide_history(self, analyzer, repository):
        """The signal that reaches fusion must not become client-scoped."""
        seed(repository, "fanout-wide.test", client_address="10.0.0.1", times=5)
        seed(repository, "fanout-wide.test", client_address="10.0.0.2", times=5)

        from backend.app.core.features import extract_features
        from backend.app.core.normalizer import normalize

        result = analyzer.analyse(extract_features(normalize("fanout-wide.test")))
        assert result.observations["queries_in_window"] == 10, (
            "fusion must still see every client's traffic, not one client's"
        )


# -- 2. client-scoped selection ----------------------------------------------


class TestClientScopedHistory:
    def test_excludes_unattributed_rows(self, repository):
        seed(repository, "alpha-demo.test", client_address="10.0.0.1", times=2)
        seed(repository, "alpha-demo.test", client_address=None, times=5)

        history = repository.domain_history("alpha-demo.test", client_address="10.0.0.1")
        assert history["total_queries"] == 2

    def test_excludes_analysis_events_even_when_addressed(self, repository):
        """The event_type filter must do work of its own.

        Analysis rows normally carry no client address, so forcing one on is
        the only way to prove they are excluded for being analyses rather than
        for being unattributed.
        """
        seed(repository, "charlie-demo.test", client_address="10.0.0.1", times=2)
        seed(repository, "charlie-demo.test", as_analysis=True, times=4)
        with connect(repository.path) as connection:
            connection.execute(
                "UPDATE events SET client_address = '10.0.0.1' "
                "WHERE registrable_domain = 'charlie-demo.test' "
                "AND event_type = 'analysis'"
            )

        history = repository.domain_history("charlie-demo.test", client_address="10.0.0.1")
        assert history["total_queries"] == 2

    def test_two_clients_have_independent_histories(self, repository):
        seed(repository, "shared-demo.test", client_address="10.0.0.1", times=3)
        seed(repository, "shared-demo.test", client_address="10.0.0.2", times=7)

        assert repository.domain_history(
            "shared-demo.test", client_address="10.0.0.1"
        )["total_queries"] == 3
        assert repository.domain_history(
            "shared-demo.test", client_address="10.0.0.2"
        )["total_queries"] == 7
        assert repository.domain_history("shared-demo.test")["total_queries"] == 10

    def test_single_pass_pair_agrees_with_two_separate_queries(self, repository):
        """The hot-path optimisation must not become a second answer.

        analyse() reads both slices in one scan for speed; if that ever
        disagrees with the plain queries, attribution and scoring would drift
        apart silently.
        """
        seed(repository, "pair-demo.test", client_address="10.0.0.1", times=4)
        seed(repository, "n1.pair-demo.test", client_address="10.0.0.1",
             response_code="NXDOMAIN")
        seed(repository, "pair-demo.test", client_address="10.0.0.2", times=3)
        seed(repository, "pair-demo.test", client_address=None, times=2)
        seed(repository, "pair-demo.test", as_analysis=True, times=2)

        wide, scoped = repository.domain_history_pair("pair-demo.test", "10.0.0.1")
        assert wide == repository.domain_history("pair-demo.test")
        assert scoped == repository.domain_history(
            "pair-demo.test", client_address="10.0.0.1"
        )

    def test_unknown_client_abstains(self, analyzer, repository):
        seed(repository, "busy-demo.test", client_address="10.0.0.1", times=25)

        result = analyzer.analyse_client("busy-demo.test", "10.0.0.99")
        assert result.confidence == 0.0
        assert result.score == 0.0
        assert result.indicators == []

    def test_thin_client_history_abstains(self, analyzer, repository):
        """Two sightings is not behaviour - the same rule as the domain path."""
        seed(repository, "thin-demo.test", client_address="10.0.0.1", times=2)

        result = analyzer.analyse_client("thin-demo.test", "10.0.0.1")
        assert result.confidence == 0.0
        assert result.indicators == []

    def test_client_scoped_indicators_use_the_same_rules(self, analyzer, repository):
        for index in range(10):
            seed(
                repository,
                "n{}.client-fanout.test".format(index),
                client_address="10.0.0.1",
                response_code="NXDOMAIN",
            )

        result = analyzer.analyse_client("client-fanout.test", "10.0.0.1")
        assert "subdomain_fanout" in result.indicators
        assert result.confidence > 0.0
        assert result.observations["client_address"] == "10.0.0.1"

    def test_one_clients_behaviour_is_not_attributed_to_another(
        self, analyzer, repository
    ):
        for index in range(10):
            seed(
                repository,
                "n{}.split-fanout.test".format(index),
                client_address="10.0.0.1",
                response_code="NXDOMAIN",
            )
        seed(repository, "quiet.split-fanout.test", client_address="10.0.0.2", times=3)

        noisy = analyzer.analyse_client("split-fanout.test", "10.0.0.1")
        quiet = analyzer.analyse_client("split-fanout.test", "10.0.0.2")
        assert "subdomain_fanout" in noisy.indicators
        assert quiet.indicators == [], "the quiet device must not inherit the noise"


# -- 3. unattributed traffic stays visible and separate ----------------------


class TestUnattributedTraffic:
    def test_unattributed_queries_are_never_merged_into_a_client(self, repository):
        seed(repository, "delta-demo.test", client_address="10.0.0.1", times=2)
        seed(repository, "delta-demo.test", client_address=None, times=4)

        stats = repository.source_ip_stats()
        rows = {s["source_ip"]: s for s in stats["sources"]}
        assert set(rows) == {"10.0.0.1"}
        assert rows["10.0.0.1"]["queries"] == 2
        assert stats["queries_without_client_address"] == 4

    def test_source_rows_carry_behavioural_attribution(self, repository):
        for index in range(10):
            seed(
                repository,
                "n{}.attributed-fanout.test".format(index),
                client_address="10.0.0.1",
                response_code="NXDOMAIN",
            )

        rows = {s["source_ip"]: s for s in repository.source_ip_stats()["sources"]}
        behaviour = rows["10.0.0.1"]["behaviour"]
        assert behaviour["verdict"] == "ANOMALOUS"
        assert behaviour["subdomain_fanout"] is True
        assert behaviour["registrable_domain"] == "attributed-fanout.test"
        assert behaviour["used_in_scoring"] is False

    def test_quiet_source_reports_insufficient_history(self, repository):
        seed(repository, "quiet-demo.test", client_address="10.0.0.7", times=2)

        rows = {s["source_ip"]: s for s in repository.source_ip_stats()["sources"]}
        behaviour = rows["10.0.0.7"]["behaviour"]
        assert behaviour["verdict"] == "INSUFFICIENT_HISTORY"
        assert behaviour["indicators"] == []


# -- 4. fusion is numerically unchanged (Phase 3 evidence) -------------------


class TestFusionUnchanged:
    """The five cases recorded in the Phase 3 audit, to the exact integer."""

    @pytest.fixture
    def clean_store(self, tmp_path):
        import backend.app.storage.events as events_module

        previous = events_module._repository
        repository = EventRepository(path=tmp_path / "fusion.db")
        set_event_repository(repository)
        try:
            yield repository
        finally:
            set_event_repository(previous)

    @pytest.mark.parametrize(
        "domain,score,decision",
        [
            ("malware-c2-panel.test", 85, "BLOCK"),
            ("malware-c2-panel.invalid", 18, "ALLOW"),
            ("kq3v9z7jx1p8w.info", 95, "BLOCK"),
            (TUNNEL_NAME, 96, "BLOCK"),
        ],
    )
    def test_phase3_scores_are_unchanged(self, clean_store, domain, score, decision):
        assessment = get_pipeline().analyse(domain).assessment
        assert assessment.score == score
        assert assessment.decision == decision

    def test_phase3_behavioural_case_is_unchanged(self, clean_store):
        for index in range(1, 10):
            seed(
                clean_store,
                "host{:02d}.behaviour-demo.invalid".format(index),
                client_address="127.0.0.1",
                response_code="NXDOMAIN",
            )

        assessment = get_pipeline().analyse("host10.behaviour-demo.invalid").assessment
        assert assessment.score == 46
        assert assessment.decision == "MONITOR"


# -- 5. through the real request handler -------------------------------------


class TestHandlerAttribution:
    def test_two_client_addresses_produce_separate_histories(self, repository):
        handler = DNSRequestHandler(
            pipeline=get_pipeline(),
            resolver=StubUpstreamResolver(responder=make_answer),
            policy=get_policy("NXDOMAIN"),
            cache=DNSCache(enabled=False),
            repository=repository,
            log_client_ip="always",
        )

        loop = asyncio.new_event_loop()
        try:
            for index in range(4):
                query = dns.message.make_query(
                    "n{}.two-clients.test".format(index), dns.rdatatype.A
                )
                loop.run_until_complete(
                    handler.handle(query.to_wire(), ("10.1.1.1", 5300))
                )
            for index in range(2):
                query = dns.message.make_query(
                    "m{}.two-clients.test".format(index), dns.rdatatype.A
                )
                loop.run_until_complete(
                    handler.handle(query.to_wire(), ("10.2.2.2", 5300))
                )
        finally:
            loop.close()

        first = repository.domain_history("two-clients.test", client_address="10.1.1.1")
        second = repository.domain_history(
            "two-clients.test", client_address="10.2.2.2"
        )
        assert first["total_queries"] == 4
        assert second["total_queries"] == 2
        assert repository.domain_history("two-clients.test")["total_queries"] == 6

        rows = {s["source_ip"]: s for s in repository.source_ip_stats()["sources"]}
        assert set(rows) == {"10.1.1.1", "10.2.2.2"}

    def test_client_address_reaches_the_pipeline_context(self, repository):
        """The handler must forward the address it already captured."""
        seen = {}
        pipeline = get_pipeline()
        original = pipeline.analyse

        def spy(raw_domain, context=None):
            seen["context"] = dict(context or {})
            return original(raw_domain, context)

        pipeline.analyse = spy
        handler = DNSRequestHandler(
            pipeline=pipeline,
            resolver=StubUpstreamResolver(responder=make_answer),
            policy=get_policy("NXDOMAIN"),
            cache=DNSCache(enabled=False),
            repository=repository,
            log_client_ip="always",
        )
        loop = asyncio.new_event_loop()
        try:
            query = dns.message.make_query("ctx.two-clients.test", dns.rdatatype.A)
            loop.run_until_complete(handler.handle(query.to_wire(), ("10.3.3.3", 5300)))
        finally:
            loop.close()
            pipeline.analyse = original

        assert seen["context"]["client_address"] == "10.3.3.3"
        assert seen["context"]["query_type"] == "A"

    def test_withheld_address_is_not_forwarded_as_a_client(self, repository):
        """Under loopback_only a LAN address is dropped - and stays dropped."""
        seen = {}
        pipeline = get_pipeline()
        original = pipeline.analyse

        def spy(raw_domain, context=None):
            seen["context"] = dict(context or {})
            return original(raw_domain, context)

        pipeline.analyse = spy
        handler = DNSRequestHandler(
            pipeline=pipeline,
            resolver=StubUpstreamResolver(responder=make_answer),
            policy=get_policy("NXDOMAIN"),
            cache=DNSCache(enabled=False),
            repository=repository,
            log_client_ip="loopback_only",
        )
        loop = asyncio.new_event_loop()
        try:
            query = dns.message.make_query("priv.two-clients.test", dns.rdatatype.A)
            loop.run_until_complete(handler.handle(query.to_wire(), ("192.168.1.9", 53)))
        finally:
            loop.close()
            pipeline.analyse = original

        assert seen["context"]["client_address"] is None
        assert repository.source_ip_stats()["queries_without_client_address"] == 1


# -- 6. the attribution snapshot hazard --------------------------------------


class TestAttributionSnapshotHazard:
    """A device does not become clean by making one clean query.

    /api/sources computes behaviour over a rolling window at read time. The
    per-query ``client_observations`` snapshot answers a narrower question -
    this client, on the domain of THIS query - so after an ordinary lookup it
    reports nothing at all. The two are easy to mistake for duplicates of each
    other, and swapping the read-time calculation for the cheaper snapshot
    would make a fanned-out device read as clean the moment it resolved
    github.com.

    That is a false negative on the one screen built to catch it, and no test
    caught it before this one. Nothing here asserts the snapshot is wrong: it
    answers its own question correctly. What is asserted is that the two
    answers differ, so a future optimisation cannot quietly substitute one for
    the other.
    """

    CLIENT = "10.55.0.1"

    @pytest.fixture
    def api(self, tmp_path):
        """A TestClient and repository sharing one temporary store.

        The endpoint reads the process-wide repository, so the global has to
        point at the same database the test seeds.
        """
        import backend.app.storage.events as events_module

        previous = events_module._repository
        store = EventRepository(path=tmp_path / "hazard.db")
        set_event_repository(store)
        try:
            yield TestClient(create_app(), raise_server_exceptions=False), store
        finally:
            set_event_repository(previous)

    def test_a_clean_query_does_not_erase_prior_anomalous_behaviour(self, api):
        client, store = api

        # 1. Enough suspicious activity to be called anomalous: one device
        #    fanning out across ten names that never resolve.
        for index in range(10):
            seed(
                store,
                "n{:02d}.hazard-fanout.test".format(index),
                client_address=self.CLIENT,
                response_code="NXDOMAIN",
            )

        # 2. The same device then makes one ordinary lookup elsewhere.
        seed(store, "github.com", client_address=self.CLIENT)

        # 3. Read the attribution the dashboard reads.
        body = client.get("/api/sources").json()
        rows = {row["source_ip"]: row for row in body["sources"]}
        behaviour = rows[self.CLIENT]["behaviour"]

        # 4. The rolling window still indicts the device.
        assert behaviour["verdict"] == "ANOMALOUS"
        assert "subdomain_fanout" in behaviour["indicators"]
        assert behaviour["score"] > 0

        # 5. The clean query neither erased nor replaced that history.
        assert behaviour["registrable_domain"] == "hazard-fanout.test"

        # 6. ...and the clean query is not itself blamed for the anomaly.
        assert behaviour["registrable_domain"] != "github.com"
        github = store.domain_history("github.com", client_address=self.CLIENT)
        assert github["total_queries"] == 1
        assert github["nxdomain_count"] == 0

        # The hazard itself, made explicit. The per-query snapshot for that
        # last clean lookup reports nothing - which is correct for the question
        # it answers, and wrong for this one.
        signal = [
            s
            for s in get_pipeline()
            .analyse(
                "github.com",
                {"query_type": "A", "client_address": self.CLIENT},
            )
            .signals
            if s.name == "behavioral"
        ][0]
        snapshot = signal.metadata["client_observations"]
        assert snapshot["indicators"] == []
        assert behaviour["indicators"] != snapshot["indicators"], (
            "read-time rolling-window attribution must not be replaced by the "
            "per-query client_observations snapshot"
        )
