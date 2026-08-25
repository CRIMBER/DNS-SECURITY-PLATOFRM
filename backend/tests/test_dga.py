"""DGA detector tests.

Assertions are about *relative separation* and about honesty of labelling, not
about exact score values, so retuning the model parameters in the config file
does not break the suite.
"""

import pytest

from backend.app.config import get_risk_config
from backend.app.core.features import extract_features
from backend.app.core.normalizer import normalize
from backend.app.detection import BigramDGADetector, dga_to_signal, get_dga_detector

LEGITIMATE = [
    "github.com",
    "wikipedia.org",
    "stackoverflow.com",
    "cloudflare.com",
    "bankofbaroda.in",
    "flipkart.com",
    "hdfcbank.com",
]

DGA_LIKE = [
    "kq3v9z7jx1p8w.info",
    "xkzqmwvbtrn.xyz",
    "vhwnxkzptqrjmb.top",
    "zxqvbnmkljhgfd.tk",
    "p9x2m7k4q1w8z3.buzz",
    "jdkfhsuwyeb.com",
    "qwrtzpxvbn.net",
]


@pytest.fixture(scope="module")
def detector():
    return get_dga_detector()


def suspicion(detector, domain: str) -> float:
    return detector.analyse(extract_features(normalize(domain))).score


class TestSeparation:
    @pytest.mark.parametrize("domain", LEGITIMATE)
    def test_legitimate_domains_score_low(self, detector, domain):
        assert suspicion(detector, domain) < 0.5, domain

    @pytest.mark.parametrize("domain", DGA_LIKE)
    def test_dga_like_domains_score_high(self, detector, domain):
        assert suspicion(detector, domain) > 0.8, domain

    def test_random_clearly_exceeds_legitimate(self, detector):
        assert suspicion(detector, "xkzqmwvbtrn.xyz") > suspicion(detector, "github.com") + 0.5

    def test_score_is_a_bounded_probability(self, detector):
        for domain in LEGITIMATE + DGA_LIKE:
            assert 0.0 <= suspicion(detector, domain) <= 1.0


class TestBigramStatistic:
    def test_english_like_label_scores_above_random(self, detector):
        assert detector.log_likelihood_ratio("microsoft") > detector.log_likelihood_ratio("xkzqmwvb")

    def test_empty_label_is_handled(self, detector):
        assert detector.log_likelihood_ratio("") == 0.0

    def test_z_score_direction(self, detector):
        """Higher z means less like a legitimate domain."""
        legit = detector.analyse(extract_features(normalize("cloudflare.com")))
        dga = detector.analyse(extract_features(normalize("xkzqmwvbtrn.xyz")))
        assert dga.components["z_score"] > legit.components["z_score"]


class TestLengthShrinkage:
    """Short labels offer fewer transitions, so their evidence is discounted."""

    def test_short_label_gets_reduced_length_factor(self, detector):
        short = detector.analyse(extract_features(normalize("drdo.gov.in")))
        long = detector.analyse(extract_features(normalize("vhwnxkzptqrjmb.top")))
        assert short.components["length_factor"] < 1.0
        assert long.components["length_factor"] == 1.0

    def test_short_acronyms_are_not_flagged(self, detector):
        for domain in ["irctc.co.in", "drdo.gov.in", "csir.res.in", "nptel.ac.in"]:
            assert suspicion(detector, domain) < 0.6, domain

    def test_short_labels_report_lower_confidence(self, detector):
        short = detector.analyse(extract_features(normalize("bbc.co.uk")))
        long = detector.analyse(extract_features(normalize("stackoverflow.com")))
        assert short.confidence < long.confidence


class TestHonestLabelling:
    """The model must never overstate what it is."""

    def test_model_type_is_declared_as_prototype(self, detector):
        result = detector.analyse(extract_features(normalize("github.com")))
        assert result.model_type == "PROTOTYPE_STATISTICAL"

    def test_no_accuracy_is_claimed(self, detector):
        info = detector.info()
        assert info["accuracy_claimed"] is None
        assert "no accuracy" in info["note"].lower()

    def test_result_explains_its_basis(self, detector):
        result = detector.analyse(extract_features(normalize("xkzqmwvbtrn.xyz")))
        assert "not a trained classifier" in result.notes.lower()
        assert result.components["bigram_llr"] is not None


class TestSignalConversion:
    def test_high_suspicion_emits_high_factor(self, detector):
        signal = dga_to_signal(
            detector.analyse(extract_features(normalize("xkzqmwvbtrn.xyz"))),
            get_risk_config(),
        )
        assert signal.factors[0].code == "DGA_HIGH"
        assert signal.score > 80

    def test_low_suspicion_emits_info_factor(self, detector):
        signal = dga_to_signal(
            detector.analyse(extract_features(normalize("github.com"))),
            get_risk_config(),
        )
        assert signal.factors[0].code == "DGA_LOW"

    def test_signal_score_is_percentage_of_probability(self, detector):
        result = detector.analyse(extract_features(normalize("xkzqmwvbtrn.xyz")))
        signal = dga_to_signal(result, get_risk_config())
        assert abs(signal.score - result.score * 100) < 0.001

    def test_every_factor_explains_itself(self, detector):
        for domain in LEGITIMATE + DGA_LIKE:
            signal = dga_to_signal(
                detector.analyse(extract_features(normalize(domain))), get_risk_config()
            )
            for factor in signal.factors:
                assert factor.label and factor.detail


class TestDetectorContract:
    def test_detector_is_swappable(self):
        """The seam a trained model plugs into."""

        class AlwaysSuspicious(BigramDGADetector):
            name = "stub_v0"

            def analyse(self, features, config=None):
                result = super().analyse(features, config)
                result.score = 1.0
                return result

        stub = AlwaysSuspicious()
        assert stub.analyse(extract_features(normalize("github.com"))).score == 1.0

    def test_model_can_be_constructed_from_injected_data(self):
        """Proves the model file is data, not code."""
        tiny = BigramDGADetector(
            model={
                "log_probs": {"^": {"a": -1.0}, "a": {"$": -1.0}},
                "alphabet": "abcdefghijklmnopqrstuvwxyz0123456789-",
                "uniform_logp": -3.6,
                "calibration": {"mean": 1.0, "std": 0.3},
                "corpus_size": 1,
                "version": "unit_test",
            }
        )
        assert tiny.info()["version"] == "unit_test"

    def test_info_reports_provenance(self, detector):
        info = detector.info()
        assert info["corpus_size"] > 100
        assert info["model_type"] == "PROTOTYPE_STATISTICAL"


class TestKnownBlindSpot:
    """A weakness we document rather than hide."""

    def test_dictionary_word_dga_is_not_detected(self, detector):
        """suppobox/matsnu-style DGAs concatenate real words and are invisible
        to any character-frequency model. Asserting the limitation keeps it
        visible; closing it needs a different class of model."""
        assert suspicion(detector, "summerbridge.com") < 0.5
        assert suspicion(detector, "windowmarket.net") < 0.5
