"""Lexical suspicion scorer.

Converts the measured features into a 0-100 sub-score plus the list of reasons
that produced it. Every threshold and point value comes from
``config/risk_config.json`` - nothing is hardcoded here, so the policy can be
retuned after testing without editing code.

This is a transparent rule-based scorer, not a machine-learning model, and it
is labelled as such everywhere it surfaces.

The signal is **asymmetric**, in line with every other signal in the engine:
a lexical anomaly is positive evidence and contributes at its full
score/confidence/weight, while the absence of any anomaly is an absence of
evidence and reports confidence 0.0, abstaining from the fusion instead of
voting a zero score against what the other signals observed.
"""

from typing import List

from ..config import RiskConfig, get_risk_config
from .classification import REGISTRANT_LABEL, NameKind
from .features import DomainFeatures
from .signals import RiskFactor, Severity, Signal, clamp

SIGNAL_NAME = "lexical"

# Kinds where no label was chosen by anyone, so "does this look like a name a
# human picked?" has no meaning. Shape rules measure entropy, digit density,
# vowel ratio and dictionary coverage - all of which answer that question.
_NO_CHOSEN_LABEL = frozenset({
    NameKind.IP_LITERAL, NameKind.INFRASTRUCTURE, NameKind.LOCAL_NAME,
})

# Rules that answer "does this look like a name a person chose?". They only
# mean something when somebody actually chose the label.
_SHAPE_CODES = frozenset({
    "ENTROPY_HIGH", "ENTROPY_VERY_HIGH", "ENTROPY_NORMALIZED_HIGH",
    "DIGIT_RATIO_HIGH", "DIGIT_RATIO_VERY_HIGH", "NO_DICTIONARY_WORDS",
    "CONSONANT_RUN_LONG", "VOWEL_RATIO_LOW", "LENGTH_LONG",
    "LENGTH_VERY_LONG", "HYPHEN_MANY", "SUBDOMAIN_DEEP", "SUSPICIOUS_TLD",
})

# Rules that read the name for MEANING rather than for shape.
_SEMANTIC_CODES = frozenset({
    "SUSPICIOUS_KEYWORD", "BRAND_IMPERSONATION", "BRAND_SUBSTRING", "PUNYCODE",
})


def _shape_applies(features: DomainFeatures) -> bool:
    """Whether the name-shape rules have a chosen label to judge."""
    classification = features.classification
    if classification is None:
        return True
    if classification.kind in _NO_CHOSEN_LABEL:
        return False
    # These rules encode Latin-script, English-language assumptions: vowel
    # ratio, consonant runs, dictionary coverage, entropy calibrated on ASCII
    # labels. Applied to a punycode string they measure the ENCODING, not the
    # name - the "29% digit ratio" of xn--80ak6aa92e is the 80 and 92 that
    # punycode inserted. Every internationalised domain therefore looked
    # machine-generated. Same limitation as the bigram model, same answer.
    if classification.scripts and classification.scripts != {"Latin"}:
        return False
    return classification.has_scope(REGISTRANT_LABEL)


def _semantics_apply(features: DomainFeatures) -> bool:
    """Whether brand/keyword matching has readable text to match against.

    Wider than the shape rules on purpose: a printer advertised as
    ``hp-laserjet.local`` was never registered, but the brand token is still
    worth seeing. An address literal and a reverse-DNS name carry no such text.
    """
    classification = features.classification
    if classification is None:
        return True
    return classification.kind not in (
        NameKind.IP_LITERAL, NameKind.INFRASTRUCTURE,
    )


def _factor(
    code: str,
    label: str,
    severity: Severity,
    detail: str,
    points: float,
) -> RiskFactor:
    return RiskFactor(
        code=code,
        label=label,
        severity=severity,
        detail=detail,
        raw_points=points,
    )


def score_lexical(
    features: DomainFeatures, config: RiskConfig = None
) -> Signal:
    """Produce the lexical ``Signal`` for a domain."""
    cfg = config or get_risk_config()
    factors: List[RiskFactor] = []
    total = 0.0

    # SCOPE: which families of rule apply to this kind of name at all. Each
    # rule below stays written as a plain measurement; the gate decides
    # whether that measurement means anything here.
    shape_applies = _shape_applies(features)
    semantics_apply = _semantics_apply(features)

    def fire(factor: RiskFactor) -> None:
        nonlocal total
        if factor.code in _SHAPE_CODES and not shape_applies:
            return
        if factor.code in _SEMANTIC_CODES and not semantics_apply:
            return
        total += factor.raw_points
        factors.append(factor)

    # -- randomness -------------------------------------------------------
    # A DGA randomises the registrable label; DNS tunnelling randomises the
    # subdomain. Take whichever is more disordered.
    effective_entropy = max(features.sld_entropy, features.entropy)
    entropy_source = "registrable label" if features.sld_entropy >= features.entropy else "full domain"

    rule = cfg.rule("entropy_high")
    if effective_entropy >= float(rule.get("threshold", 3.6)):
        fire(
            _factor(
                "ENTROPY_HIGH",
                "High character entropy ({:.2f} bits/char)".format(effective_entropy),
                Severity.MEDIUM,
                "The {} spreads its characters unusually evenly, which is "
                "characteristic of machine-generated rather than human-chosen "
                "names.".format(entropy_source),
                float(rule.get("points", 18)),
            )
        )

        rule = cfg.rule("entropy_very_high")
        if effective_entropy >= float(rule.get("threshold", 4.1)):
            fire(
                _factor(
                    "ENTROPY_VERY_HIGH",
                    "Very high character entropy",
                    Severity.HIGH,
                    "Entropy is above the level seen in almost all legitimately "
                    "registered domains.",
                    float(rule.get("points", 12)),
                )
            )

    rule = cfg.rule("normalized_entropy_high")
    # Gated on length: in a short label nearly every character is distinct, so
    # normalised entropy sits near 1.0 for perfectly ordinary names.
    if features.sld_length >= int(rule.get("min_sld_length", 12)) and (
        features.normalized_entropy >= float(rule.get("threshold", 0.82))
    ):
        fire(
            _factor(
                "ENTROPY_NORMALIZED_HIGH",
                "Near-maximal entropy for its length",
                Severity.MEDIUM,
                "Almost every character in the name is distinct, indicating "
                "little or no repeated linguistic structure.",
                float(rule.get("points", 10)),
            )
        )

    # -- digits -----------------------------------------------------------
    rule = cfg.rule("digit_ratio_high")
    if features.digit_ratio >= float(rule.get("threshold", 0.20)):
        fire(
            _factor(
                "DIGIT_RATIO_HIGH",
                "High digit ratio ({:.0%})".format(features.digit_ratio),
                Severity.MEDIUM,
                "Legitimate brand domains rarely mix this proportion of digits "
                "into the name.",
                float(rule.get("points", 14)),
            )
        )
        rule = cfg.rule("digit_ratio_very_high")
        if features.digit_ratio >= float(rule.get("threshold", 0.40)):
            fire(
                _factor(
                    "DIGIT_RATIO_VERY_HIGH",
                    "Very high digit ratio",
                    Severity.HIGH,
                    "Digit density is typical of algorithmically generated names.",
                    float(rule.get("points", 10)),
                )
            )

    # -- structure --------------------------------------------------------
    rule = cfg.rule("length_long")
    if features.length >= int(rule.get("threshold", 25)):
        fire(
            _factor(
                "LENGTH_LONG",
                "Unusually long domain ({} characters)".format(features.length),
                Severity.LOW,
                "Long names are used to pad randomised labels or to bury a "
                "brand name inside a longer string.",
                float(rule.get("points", 8)),
            )
        )
        rule = cfg.rule("length_very_long")
        if features.length >= int(rule.get("threshold", 40)):
            fire(
                _factor(
                    "LENGTH_VERY_LONG",
                    "Extremely long domain",
                    Severity.MEDIUM,
                    "Extreme length is also consistent with data being encoded "
                    "into DNS labels.",
                    float(rule.get("points", 8)),
                )
            )

    rule = cfg.rule("hyphen_many")
    if features.hyphen_count >= int(rule.get("threshold", 3)):
        fire(
            _factor(
                "HYPHEN_MANY",
                "Many hyphens ({})".format(features.hyphen_count),
                Severity.LOW,
                "Heavy hyphenation is common in phishing domains that chain "
                "brand and action words together.",
                float(rule.get("points", 10)),
            )
        )

    rule = cfg.rule("subdomain_deep")
    if features.subdomain_count >= int(rule.get("threshold", 4)):
        fire(
            _factor(
                "SUBDOMAIN_DEEP",
                "Deep subdomain nesting ({} levels)".format(features.subdomain_count),
                Severity.MEDIUM,
                "Deeply nested subdomains are used to disguise the true "
                "registrable domain and are a hallmark of DNS tunnelling.",
                float(rule.get("points", 10)),
            )
        )

    # -- pronounceability -------------------------------------------------
    rule = cfg.rule("consonant_run_long")
    if features.max_consonant_run >= int(rule.get("threshold", 5)):
        fire(
            _factor(
                "CONSONANT_RUN_LONG",
                "Unpronounceable consonant run ({} in a row)".format(
                    features.max_consonant_run
                ),
                Severity.MEDIUM,
                "Human-chosen names are usually pronounceable; long consonant "
                "runs indicate random character selection.",
                float(rule.get("points", 12)),
            )
        )

    rule = cfg.rule("vowel_ratio_low")
    if features.sld_length >= 8 and features.vowel_ratio <= float(
        rule.get("threshold", 0.20)
    ):
        fire(
            _factor(
                "VOWEL_RATIO_LOW",
                "Very low vowel ratio ({:.0%})".format(features.vowel_ratio),
                Severity.MEDIUM,
                "Natural language holds a roughly 35-40% vowel ratio; a much "
                "lower ratio suggests the name was not chosen by a person.",
                float(rule.get("points", 12)),
            )
        )

    rule = cfg.rule("no_dictionary_words")
    if features.sld_length >= int(
        rule.get("min_sld_length", 10)
    ) and features.dictionary_word_coverage <= float(rule.get("threshold", 0.20)):
        fire(
            _factor(
                "NO_DICTIONARY_WORDS",
                "Contains no recognisable words",
                Severity.MEDIUM,
                "Only {:.0%} of the registrable label can be explained as real "
                "words, so the name carries no apparent meaning.".format(
                    features.dictionary_word_coverage
                ),
                float(rule.get("points", 14)),
            )
        )

    # -- reputation-adjacent lexical signals -------------------------------
    rule = cfg.rule("suspicious_tld")
    if features.tld_is_suspicious:
        points = features.tld_risk_weight * float(rule.get("points_scale", 20))
        fire(
            _factor(
                "SUSPICIOUS_TLD",
                "Abuse-heavy TLD (.{})".format(features.tld),
                Severity.LOW if features.tld_risk_weight < 0.7 else Severity.MEDIUM,
                ".{} has a well-documented above-average abuse rate; weighting "
                "applied: {:.2f}.".format(features.tld, features.tld_risk_weight),
                points,
            )
        )

    rule = cfg.rule("suspicious_keyword")
    if features.suspicious_keywords:
        scale = float(rule.get("points_scale", 16))
        per_extra = float(rule.get("points_per_extra", 4))
        cap = float(rule.get("max_points", 20))
        # Weighted by the strongest keyword found: "suspended" is real
        # evidence, "mail" barely registers.
        points = min(
            cap,
            scale * features.keyword_max_weight
            + per_extra * (len(features.suspicious_keywords) - 1),
        )
        if points >= 1.0:
            fire(
                _factor(
                    "SUSPICIOUS_KEYWORD",
                    "Phishing-associated keywords: {}".format(
                        ", ".join(features.suspicious_keywords[:4])
                    ),
                    Severity.MEDIUM if features.keyword_max_weight >= 0.6 else Severity.LOW,
                    "These tokens are frequently used in credential-harvesting "
                    "domains. On their own they are weak evidence - many "
                    "legitimate domains contain them - so the contribution is "
                    "weighted by keyword strength and capped.",
                    points,
                )
            )

    rule = cfg.rule("brand_impersonation")
    if features.brand_impersonation:
        kind = (
            "appears as a distinct token"
            if features.brand_match_type == "token"
            else "is within two character edits"
        )
        fire(
            _factor(
                "BRAND_IMPERSONATION",
                "Possible impersonation of {}".format(features.brand_target),
                Severity.HIGH,
                "The name {} of '{}' but the domain is not owned by that "
                "brand.".format(kind, features.brand_target),
                float(rule.get("points", 25)),
            )
        )
    elif features.brand_substring_only:
        fire(
            _factor(
                "BRAND_SUBSTRING",
                "Contains the brand name {}".format(features.brand_target),
                Severity.LOW,
                "A well-known brand name appears inside this domain, which it "
                "does not own. Weak on its own.",
                float(rule.get("points", 25)) * 0.4,
            )
        )

    if features.is_punycode:
        rule = cfg.rule("punycode")
        fire(
            _factor(
                "PUNYCODE",
                "Internationalised (punycode) domain",
                Severity.MEDIUM,
                "Non-ASCII characters can be used to build homograph domains "
                "that look identical to a legitimate name.",
                float(rule.get("points", 15)),
            )
        )

    # The old IP_LITERAL rule lived here. "This is an address, not a name" is
    # now a structural fact from the classifier rather than a lexical
    # observation, and scoring the octets as text is what made 192.168.1.10
    # reach 95/BLOCK. Whether an address literal is itself suspicious is a
    # policy question - and a different one for 8.8.8.8 than for a private
    # address - so it is left to an evidenced decision rather than 20 points.

    max_score = float(cfg.get("lexical.max_score", 100))
    score = clamp(total, 0.0, max_score)

    # -- confidence -------------------------------------------------------
    # Short names simply do not carry much lexical information. Rather than
    # emit a confident-looking score from three characters, we lower the
    # confidence so the risk engine weights this signal accordingly.
    conf_cfg = cfg.get("lexical.confidence", {}) or {}
    min_len = int(conf_cfg.get("min_informative_length", 6))
    confidence = float(conf_cfg.get("base", 0.85))
    if features.sld_length < min_len:
        confidence = float(conf_cfg.get("short_domain_penalty", 0.45))

    if not factors and not shape_applies and not semantics_apply:
        # Nothing this scorer measures applies to this kind of name. That is a
        # different statement from "measured and found nothing", and it is
        # reported as its own factor so the distinction survives to the
        # dashboard instead of looking like a clean bill of health.
        kind = features.classification.kind.value if features.classification else "?"
        reason = features.classification.reason if features.classification else ""
        return Signal(
            name=SIGNAL_NAME,
            score=0.0,
            confidence=0.0,
            factors=[
                RiskFactor(
                    code="LEXICAL_NOT_APPLICABLE",
                    label="Lexical analysis does not apply to this name",
                    severity=Severity.INFO,
                    detail="Classified {}. {} No lexical rule was evaluated, so "
                    "this signal abstains.".format(kind, reason),
                    raw_points=0.0,
                )
            ],
            metadata={
                "raw_points": 0.0,
                "capped_at_max": False,
                "effective_entropy": 0.0,
                "method": "rule_based_lexical_v1",
                "method_type": "TRANSPARENT_RULE_BASED",
                "not_applicable": True,
                "name_kind": kind,
            },
            scope_key=REGISTRANT_LABEL,
        )

    if not factors:
        # Asymmetric confidence: ABSENCE OF ANOMALY IS NOT EVIDENCE OF SAFETY.
        # The same rule already governs a threat-intelligence miss (UNKNOWN ->
        # 0.0) and a null DGA finding. Finding no lexical anomaly means this
        # scorer has nothing to say - not that the domain is benign - because
        # a name can be perfectly ordinary while the *behaviour* behind it is
        # not. Reporting score 0 at full confidence made this signal cast a
        # vote for safety that diluted independent evidence: a subdomain
        # fan-out with a 100% NXDOMAIN rate scored 15/ALLOW purely because a
        # clean-looking name outweighed the behavioural finding.
        #
        # So the signal abstains: confidence 0.0 removes it from BOTH sums of
        # the weighted average, leaving the domain to be judged on the signals
        # that did observe something. A positive lexical anomaly is unaffected
        # and still contributes at its full score/confidence/weight.
        confidence = float(conf_cfg.get("null_finding_confidence", 0.0))
        factors.append(
            RiskFactor(
                code="LEXICAL_CLEAN",
                label="No lexical anomalies detected",
                severity=Severity.INFO,
                detail="Length, entropy, character mix and structure are all "
                "within the range seen in legitimate domains. This is an "
                "absence of evidence, not evidence of safety, so this signal "
                "abstains from the risk score rather than voting it down.",
                raw_points=0.0,
            )
        )

    return Signal(
        name=SIGNAL_NAME,
        score=score,
        confidence=confidence,
        factors=factors,
        metadata={
            "raw_points": round(total, 2),
            "capped_at_max": total > max_score,
            "effective_entropy": round(effective_entropy, 3),
            "method": "rule_based_lexical_v1",
            "method_type": "TRANSPARENT_RULE_BASED",
        },
        # Reads the registrant label, exactly as the DGA model does. Recorded
        # so the engine can see the two are not independent evidence.
        scope_key=REGISTRANT_LABEL,
    )
