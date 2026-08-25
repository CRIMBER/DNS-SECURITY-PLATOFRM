"""Statistical DGA detector: character-bigram likelihood ratio.

How it works
------------
A character-bigram language model is trained (offline, by
``backend/scripts/build_bigram_model.py``) on the registrable labels of
hundreds of legitimate domains. For a candidate label we compute the mean
per-character log-likelihood ratio between two hypotheses:

    H_legit  : the label was drawn from the legitimate-domain language model
    H_random : the label was drawn uniformly at random over the alphabet

Legitimate names score high - English-like transitions such as ``th``, ``on``
and ``er`` are common in the corpus. Algorithmically generated names score near
zero, because their transitions are no more likely under the language model
than under uniform randomness.

That raw ratio is then expressed as a z-score against the measured distribution
of the same statistic across the training corpus, and combined with two further
independent signals - dictionary-word coverage and digit density - through a
logistic function to produce a 0-1 suspicion value.

What this is and is not
-----------------------
This is a **transparent statistical model with measured calibration**. It is
not a trained discriminative classifier, and the value it returns is a
calibrated suspicion score rather than a classifier's posterior probability.
Every response labels it ``PROTOTYPE_STATISTICAL``, and ``info()`` reports
``accuracy_claimed: None``.

``backend/scripts/evaluate_dga.py`` retrains on 80% of the corpus and measures
separation on the held-out 20% against locally generated DGA-style strings.
**Those numbers are a synthetic benchmark, not a real-world accuracy figure**,
and must never be quoted as one: the malicious class is generated rather than
observed, and the corpus is small. The script also documents a genuine blind
spot - dictionary-word DGAs (suppobox/matsnu style) are invisible to any
character-frequency model, and are detected at roughly 0.5%.
"""

import math
import re
from typing import Any, Dict, List, Tuple

from ..config import RiskConfig, get_risk_config, load_json_data
from ..core.features import DomainFeatures
from .base import DGADetector, DGAResult

START = "^"
END = "$"


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    exp_x = math.exp(x)
    return exp_x / (1.0 + exp_x)


class BigramDGADetector(DGADetector):
    """Bigram-likelihood suspicion scorer."""

    name = "bigram_llr_v1"
    model_type = "PROTOTYPE_STATISTICAL"

    def __init__(self, model: Dict[str, Any] = None) -> None:
        data = model if model is not None else load_json_data(
            "detection", "data", "bigrams.json"
        )
        self._log_probs: Dict[str, Dict[str, float]] = data["log_probs"]
        self._alphabet: str = data.get("alphabet", "abcdefghijklmnopqrstuvwxyz0123456789-")
        self._uniform_logp: float = float(data.get("uniform_logp", math.log(1.0 / 38)))
        calibration = data.get("calibration", {})
        self._mean = float(calibration.get("mean", 0.96))
        self._std = float(calibration.get("std", 0.28)) or 1e-6
        self._corpus_size = int(data.get("corpus_size", 0))
        self._version = data.get("version", "bigram_v1")

    # -- core statistic -----------------------------------------------------

    def log_likelihood_ratio(self, label: str) -> float:
        """Mean per-character log-likelihood ratio, legitimate vs uniform."""
        cleaned = "".join(ch for ch in label.lower() if ch in self._alphabet)
        if not cleaned:
            return 0.0
        padded = START + cleaned + END
        total = 0.0
        steps = 0
        for i in range(len(padded) - 1):
            row = self._log_probs.get(padded[i])
            if row is None:
                continue
            total += row.get(padded[i + 1], self._uniform_logp)
            steps += 1
        if steps == 0:
            return 0.0
        return (total / steps) - self._uniform_logp

    # -- scoring ------------------------------------------------------------

    def analyse(
        self, features: DomainFeatures, config: RiskConfig = None
    ) -> DGAResult:
        cfg = config or get_risk_config()
        params = cfg.get("dga.model_parameters", {}) or {}

        label = features.sld or features.domain
        letters_and_digits = re.sub(r"[^a-z0-9-]", "", label.lower())

        llr = self.log_likelihood_ratio(label)
        z_score = (self._mean - llr) / self._std

        z_clamp = float(params.get("z_clamp", 6.0))
        z_clamped = max(-3.0, min(z_clamp, z_score))

        # Shrink the bigram term for short labels. A five-character acronym
        # offers only six character transitions to judge, so its z-score is
        # genuinely noisier evidence than a fourteen-character label's - the
        # model should be correspondingly less willing to act on it. Without
        # this, ordinary short acronyms (irctc, drdo, nptel) false-positive.
        shrink_length = float(params.get("shrinkage_length", 10.0))
        length_factor = min(1.0, len(letters_and_digits) / shrink_length)

        # Three independent, centred terms.
        term_bigram = z_clamped * length_factor
        term_dictionary = (1.0 - features.dictionary_word_coverage) - float(
            params.get("dictionary_centre", 0.5)
        )
        term_digits = features.digit_ratio - float(params.get("digit_centre", 0.10))

        w_bigram = float(params.get("weight_bigram", 1.1))
        w_dictionary = float(params.get("weight_dictionary", 2.0))
        w_digits = float(params.get("weight_digits", 3.0))
        bias = float(params.get("bias", -2.2))

        logit = (
            w_bigram * term_bigram
            + w_dictionary * term_dictionary
            + w_digits * term_digits
            + bias
        )
        score = _sigmoid(logit)

        # Which terms actually pushed the score up.
        weighted: List[Tuple[str, float]] = [
            ("bigram_implausibility", w_bigram * term_bigram),
            ("no_dictionary_words", w_dictionary * term_dictionary),
            ("digit_density", w_digits * term_digits),
        ]
        top = [name for name, value in sorted(weighted, key=lambda p: -p[1]) if value > 0]

        # Confidence: a very short label carries little statistical evidence.
        min_length = int(params.get("min_confident_length", 8))
        length = len(letters_and_digits)
        if length >= min_length:
            confidence = float(params.get("confidence_full", 0.80))
        elif length >= 5:
            confidence = float(params.get("confidence_short", 0.55))
        else:
            confidence = float(params.get("confidence_very_short", 0.30))

        # ABSENCE OF ANOMALY IS NOT EVIDENCE OF SAFETY - the same rule that
        # governs a threat-intelligence miss (UNKNOWN) and a clean lexical
        # result. A low score means "I found no algorithmic generation", which
        # says nothing about whether the domain is phishing, being tunnelled
        # through, or behaving anomalously.
        #
        # This used to merely *reduce* confidence (x0.45). That was not enough,
        # because confidence is only a RELATIVE weight: when a signal is the
        # only one reporting, the fused score equals its score no matter how
        # low its confidence. A near-zero DGA score at 0.36 confidence
        # therefore still dragged a strong behavioural finding down to ALLOW,
        # and still flagged short legitimate acronyms on its own.
        #
        # Abstaining removes it from BOTH sums instead, so a null finding
        # neither raises nor lowers the score. A positive finding is untouched
        # and still contributes at full score/confidence/weight.
        moderate = float(cfg.get("dga.factor_thresholds.moderate", 0.5))
        if score < moderate:
            confidence = float(params.get("null_finding_confidence", 0.0))

        return DGAResult(
            score=score,
            model=self.name,
            model_type=self.model_type,
            components={
                "bigram_llr": llr,
                "z_score": z_score,
                "dictionary_word_coverage": features.dictionary_word_coverage,
                "digit_ratio": features.digit_ratio,
                "label_length": float(length),
                "length_factor": length_factor,
                "logit": logit,
            },
            top_contributors=top,
            confidence=confidence,
            notes=(
                "Calibrated statistical score from a character-bigram language "
                "model trained on {} legitimate domain labels. Not a trained "
                "classifier; no accuracy is claimed.".format(self._corpus_size)
            ),
        )

    # -- provenance ---------------------------------------------------------

    def info(self) -> Dict[str, Any]:
        return {
            "model": self.name,
            "model_type": self.model_type,
            "version": self._version,
            "corpus_size": self._corpus_size,
            "calibration_mean": round(self._mean, 4),
            "calibration_std": round(self._std, 4),
            "accuracy_claimed": None,
            "note": "No labelled held-out evaluation has been performed, so no "
            "accuracy figure is reported.",
        }
