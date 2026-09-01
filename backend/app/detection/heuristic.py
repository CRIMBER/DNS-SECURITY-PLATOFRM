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
from typing import Any, Dict, List, Optional, Tuple

from ..config import RiskConfig, get_risk_config, load_json_data
from ..core.classification import REGISTRANT_LABEL, NameKind
from ..core.features import DomainFeatures
from .base import DGADetector, DGAResult

START = "^"
END = "$"


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    exp_x = math.exp(x)
    return exp_x / (1.0 + exp_x)


def _scope_abstention(features: DomainFeatures) -> Optional[str]:
    """Why this model cannot speak about this name, or None if it can.

    Returns the reason so it can be reported rather than silently swallowed:
    an abstaining signal still has to explain itself.
    """
    classification = features.classification
    if classification is None:
        return None

    kind = classification.kind
    if kind is NameKind.IP_LITERAL:
        return (
            "An IP address literal has no label to analyse. Scoring the "
            "octets as text measures digit density of an address, not "
            "algorithmic name generation."
        )
    if kind is NameKind.INFRASTRUCTURE:
        return (
            "Labels under {} are operator-defined or encode an address; "
            "nobody chose them as a name.".format(
                classification.public_suffix or "this zone")
        )
    if kind is NameKind.LOCAL_NAME:
        return (
            "Names in the special-use zone .{} are device or host names that "
            "were never registered, so registrant-label analysis does not "
            "apply.".format(classification.special_use or "local")
        )
    if not classification.has_scope(REGISTRANT_LABEL):
        return "This name has no registrant-chosen label to analyse."

    # A punycode label is an encoding of a name, not the name. The corpus is
    # registrant-chosen labels written as themselves, so `xn--mnchen-3ya`
    # is outside the training distribution no matter what it decodes to - and
    # a model that reports "random" for every internationalised domain is not
    # detecting anything, it is failing in one direction.
    #
    # The test is whether the label is ENCODED, not which script it decodes to:
    # keying it on script let every Latin-script IDN through, and muenchen.de
    # scored 99.5 on its punycode.
    if classification.unicode_form is not None:
        scripts = "/".join(sorted(classification.scripts)) or "non-ASCII"
        return (
            "Label is punycode-encoded ({} name). The model would be scoring "
            "the encoding rather than the name.".format(scripts)
        )
    return None


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
        """Mean per-character log-likelihood ratio, legitimate vs uniform.

        DIGITS ARE EXCLUDED from the chain. They are already scored twice over
        - by this model's own ``term_digits`` and by the lexical digit-ratio
        rule - so letting them into the character chain counted the same
        evidence a third time, and did it badly: the corpus is built from
        words, so any digit transition looks maximally improbable regardless
        of what it means. cdn77 scored z=7.24, as implausible as a real DGA,
        purely because "n7" and "77" are unseen bigrams.

        Removing them sharpens the signal in both directions. The measure
        becomes what it claims to be - the plausibility of the LETTER sequence
        - and the generated names it exists to catch score higher without
        their digits diluting the letters: p9x2m7k4q1w8z3 goes from z=7.73 to
        z=10.28, kq3v9z7jx1p8w from 7.93 to 8.36.
        """
        cleaned = "".join(
            ch for ch in label.lower()
            if ch in self._alphabet and not ch.isdigit()
        )
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

    def _abstain(self, reason: str) -> DGAResult:
        """A null result carrying confidence 0.0 and the reason why."""
        return DGAResult(
            score=0.0,
            model=self.name,
            model_type=self.model_type,
            components={},
            top_contributors=[],
            confidence=0.0,
            notes="Abstained: " + reason,
        )


    def analyse(
        self, features: DomainFeatures, config: RiskConfig = None
    ) -> DGAResult:
        cfg = config or get_risk_config()
        params = cfg.get("dga.model_parameters", {}) or {}

        # SCOPE: this model answers one question - "was this label generated
        # rather than chosen by a person?" - and it can only answer it about a
        # label a person might have chosen, written in the script its corpus
        # was built from. The classifier says whether such a label exists here.
        # Where it does not, the honest answer is no answer at all.
        abstention = _scope_abstention(features)
        if abstention is not None:
            return self._abstain(abstention)

        label = features.scope(REGISTRANT_LABEL) or features.sld or features.domain
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
        # The reporting bar rises when the evidence is thin. Below
        # min_confident_length the model already says it is unsure - that is
        # what confidence_short means - but confidence is only a RELATIVE
        # weight, so a lone reporting signal sets the fused score no matter
        # how little it claims to know. scribd.com is the case in point: six
        # letters, seven transitions, a moderate z of 2.79, and the resulting
        # 0.58 became the entire 58/MONITOR verdict on an ordinary English-
        # looking name. On a label that short the model cannot separate a
        # slightly unusual real word from a generated one, so a MODERATE
        # finding there is not evidence and it abstains; a STRONG finding
        # still reports, which is why short random labels are unaffected.
        moderate = float(cfg.get("dga.factor_thresholds.moderate", 0.5))
        strong = float(cfg.get("dga.factor_thresholds.high", 0.8))
        bar = moderate if length >= min_length else strong
        if score < bar:
            confidence = float(params.get("null_finding_confidence", 0.0))

        # WORD-COMPOSED LABELS: the question is already answered.
        #
        # This model asks one thing - "was this label GENERATED rather than
        # chosen by a person?" - and dictionary coverage answers it directly
        # and independently of the character statistics. Measured over the
        # corpus the separation is total: every generated name scores 0.000,
        # while the legitimate infrastructure names this model misfires on
        # score 0.375 to 1.000. netdna-cdn.com is 0.667 - "netdna" plus "cdn" -
        # and was blocked at 92 on a bigram z-score inflated by the hyphen.
        #
        # A label that demonstrably decomposes into known words is positive
        # evidence that it was CHOSEN, so the character-statistics reading is
        # not evidence of generation and the model abstains rather than
        # reporting. This is scoped strictly to this model's own question: it
        # does not touch fusion, enforcement, behavioural, threat-intelligence
        # or brand evidence, which is what separates it from the blanket DGA
        # discount rejected in Phase 5E.
        #
        # It also costs nothing against word-composed phishing, because the
        # bigram model never caught those anyway - dictionary-word DGAs are a
        # documented blind spot of any character model, and names such as
        # secure-login-bank-verify.tk are carried by keyword, TLD and brand
        # evidence instead. Measured: unchanged or stronger in every case.
        rule = params.get("word_composed_abstention") or {}
        if rule.get("enabled", False) and confidence > 0.0:
            threshold = float(rule.get("coverage_threshold", 0.5))
            if features.dictionary_word_coverage > threshold:
                confidence = float(params.get("null_finding_confidence", 0.0))
                abstained_as_word_composed = True
            else:
                abstained_as_word_composed = False
        else:
            abstained_as_word_composed = False

        return DGAResult(
            score=score,
            model=self.name,
            model_type=self.model_type,
            components={
                "bigram_llr": llr,
                "z_score": z_score,
                "dictionary_word_coverage": features.dictionary_word_coverage,
                "word_composed_abstention": abstained_as_word_composed,
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
