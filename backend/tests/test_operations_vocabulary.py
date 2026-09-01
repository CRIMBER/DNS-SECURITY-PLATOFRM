"""Phase 5F: the corpus knew what a victim is shown, not what an operator runs.

THE GAP

suspicious_keywords.json was built entirely from credential-harvesting
vocabulary - verify, suspended, login, billing, airdrop. Every one of those is
a word an ATTACKER SHOWS A VICTIM. The corpus had no coverage at all of the
words an attacker uses for THEIR OWN INFRASTRUCTURE.

The consequence was measurable. A domain that states its purpose outright
produced no lexical evidence whatsoever:

    data-exfil-node.test    lexical confidence 0.00  - no rule fired at all
    exfil-gateway.com       28/ALLOW
    keylogger-panel.xyz     26/ALLOW
    ransomware-payment.top  27/ALLOW

These were visible only when some other signal happened to fire. data-exfil-
node.test scored 59/MONITOR entirely on a DGA reading that was itself a
misfire - the name is 62% dictionary words, so the model was answering
"generated?" with a false yes, and the platform was right for the wrong
reason.

THE ADDITION

Nine tokens across six semantic families, weighted by evidential strength on
the same 0.0-1.0 scale the phishing block already uses:

    exfil       0.95   data exfiltration
    botnet      1.00   command and control
    keylog      0.95   credential theft
    stealer     0.85   data theft
    rootkit     1.00   persistence
    backdoor    0.80   persistence / remote access
    webshell    0.95   remote access
    ransomware  1.00   payload delivery and extortion
    ransom      0.55   the same family, stem form

Matching is substring, so a token that also occurs inside ordinary English is
weighted DOWN rather than excluded. That is why "ransom" is 0.55 (Ransom is a
place and a surname), "backdoor" 0.80 and "stealer" 0.85 (both real English
compounds), while "exfil", "botnet", "rootkit" and "webshell" - which occur in
no dictionary word at all - carry full weight.

WHAT WAS DELIBERATELY LEFT OUT, AND WHY

  malware   moves a protected reference value: malware-c2-panel.invalid
            18/ALLOW -> 32/MONITOR. Rejected on that alone.
  dropper   changed no malicious decision and cost eyedropper.com and
            dropper-bottles.com real points. No demonstrated security value.
  payload   same, and collides with payloadcms.com, a real product.
  rat, cnc, c2, implant
            substring-unsafe to the point of uselessness: "corpo(rat)e",
            CNC machining, dental implants.

NOT ADDED TO words.txt. That file answers a different question - "was this
label CHOSEN by a person, or GENERATED?" - and teaching it this vocabulary
measurably WEAKENS detection, because it makes malicious names look more
human-chosen: data-exfil-node.test falls 59/MONITOR -> 0/ALLOW. The two
corpora are kept separate on purpose. See test_the_two_corpora_stay_separate.
"""

import pytest

from backend.app.core.features import (
    DICTIONARY,
    SUSPICIOUS_KEYWORD_WEIGHTS,
    extract_features,
)
from backend.app.core.normalizer import normalize
from backend.app.core.pipeline import get_pipeline

OPERATIONS_VOCABULARY = {
    "exfil": 0.95,
    "botnet": 1.0,
    "keylog": 0.95,
    "stealer": 0.85,
    "rootkit": 1.0,
    "backdoor": 0.8,
    "webshell": 0.95,
    "ransomware": 1.0,
    "ransom": 0.55,
}


def verdict(domain):
    a = get_pipeline().analyse(domain).assessment
    return a.score, a.decision


def keywords(domain):
    return extract_features(normalize(domain)).suspicious_keywords


# -- the vocabulary itself ---------------------------------------------------


class TestTheVocabularyIsPresentAndWeighted:
    @pytest.mark.parametrize("token,weight", sorted(OPERATIONS_VOCABULARY.items()))
    def test_token_is_registered_at_its_measured_weight(self, token, weight):
        assert SUSPICIOUS_KEYWORD_WEIGHTS.get(token) == weight

    @pytest.mark.parametrize("token", ["exfil", "botnet", "rootkit", "webshell"])
    def test_unambiguous_tokens_carry_near_full_weight(self, token):
        """No English word contains these, so nothing argues for discounting."""
        assert not [w for w in DICTIONARY if token in w]
        assert SUSPICIOUS_KEYWORD_WEIGHTS[token] >= 0.95

    @pytest.mark.parametrize("token,ceiling", [
        ("ransom", 0.6), ("backdoor", 0.85), ("stealer", 0.9),
    ])
    def test_tokens_that_occur_in_english_are_discounted(self, token, ceiling):
        """Substring matching means these will hit innocent names. Weight down."""
        assert SUSPICIOUS_KEYWORD_WEIGHTS[token] <= ceiling


class TestTheRejectedTokensStayRejected:
    """Each of these was measured and refused. The reason is asserted, not
    described, so re-adding one fails here rather than in production."""

    def test_malware_is_absent_because_it_moves_a_protected_value(self):
        assert "malware" not in SUSPICIOUS_KEYWORD_WEIGHTS
        assert verdict("malware-c2-panel.invalid") == (18, "ALLOW")

    @pytest.mark.parametrize("token,innocent", [
        ("dropper", "eyedropper.com"),
        ("payload", "payloadcms.com"),
    ])
    def test_tokens_with_no_measured_security_value_are_absent(self, token, innocent):
        assert token not in SUSPICIOUS_KEYWORD_WEIGHTS
        assert token in innocent  # the collision that ruled it out is real

    @pytest.mark.parametrize("token,collision", [
        ("rat", "corporate"), ("cnc", "cnc"), ("c2", "c2"),
    ])
    def test_substring_unsafe_tokens_are_absent(self, token, collision):
        assert token not in SUSPICIOUS_KEYWORD_WEIGHTS
        assert token in collision


class TestTheTwoCorporaStaySeparate:
    """words.txt answers "chosen or generated?"; the keyword corpus answers
    "chosen to do what?". Merging them weakens detection."""

    @pytest.mark.parametrize("token", sorted(OPERATIONS_VOCABULARY))
    def test_operations_vocabulary_is_not_in_the_dictionary(self, token):
        assert token not in DICTIONARY, (
            "adding {!r} to words.txt raises dictionary coverage for malicious "
            "names, which lowers their DGA score - measured: data-exfil-node."
            "test 59/MONITOR -> 0/ALLOW".format(token)
        )


# -- what the vocabulary actually buys ---------------------------------------


class TestNamesThatStateTheirPurposeAreNowVisible:
    """Before this corpus these produced no lexical evidence at all."""

    @pytest.mark.parametrize("domain,score,decision", [
        ("exfil-gateway.com", 43, "MONITOR"),
        ("keylogger-panel.xyz", 41, "MONITOR"),
        ("ransomware-payment.top", 38, "MONITOR"),
        ("exfil-c2.tk", 71, "BLOCK"),
        ("ransomware-decrypt.ml", 70, "BLOCK"),
    ])
    def test_the_decision_improved(self, domain, score, decision):
        assert verdict(domain) == (score, decision)

    @pytest.mark.parametrize("domain,minimum", [
        ("webshell-upload.tk", 63), ("infostealer-logs.cf", 62),
        ("rootkit-loader.com", 26), ("backdoor-access.net", 23),
        ("botnet-panel.org", 26),
    ])
    def test_the_evidence_is_recorded_even_where_the_band_does_not_change(
            self, domain, minimum):
        assert verdict(domain)[0] >= minimum

    @pytest.mark.parametrize("domain,token", [
        ("data-exfil-node.test", "exfil"),
        ("botnet-controller.test", "botnet"),
        ("keylogger-panel.xyz", "keylog"),
        ("infostealer-logs.cf", "stealer"),
        ("rootkit-loader.com", "rootkit"),
        ("backdoor-access.net", "backdoor"),
        ("webshell-upload.tk", "webshell"),
        ("ransomware-decrypt.ml", "ransomware"),
    ])
    def test_each_family_has_a_name_that_exercises_it(self, domain, token):
        assert token in keywords(domain)


# -- what it costs -----------------------------------------------------------


class TestTheCostIsBoundedAndRecorded:
    @pytest.mark.parametrize("domain,score", [
        ("robotnetwork.com", 16),   # "ro-BOTNET-work"
        ("keylogic.com", 15),       # "KEYLOG-ic"
        ("exfiltrated.org", 15),
        ("webshells.co.uk", 15),
        ("stealerswheel.com", 14),
        ("backdoorpodcast.com", 13),
        ("ransomcanyon.org", 9),
        ("ransomnote.com", 9),
    ])
    def test_innocent_substring_collisions_stay_well_inside_allow(
            self, domain, score):
        """Substring matching does hit innocent names. The keyword rule caps at
        20 points, so the worst measured collision lands at 16 - half the
        MONITOR band. That cap is what makes substring matching survivable."""
        assert verdict(domain) == (score, "ALLOW")

    def test_no_keyword_evidence_alone_can_reach_the_monitor_band(self):
        """The structural limit, asserted.

        points = min(20, 16 * max_weight + 4 * (n - 1)). A single token, even
        at weight 1.0, is worth 16 - below MONITOR at 30. This is deliberate:
        the rule was calibrated for phishing tokens that are individually weak.
        It is also why the word_composed_abstention gate still fails; see
        test_word_composed_abstention.py.
        """
        from backend.app.config import get_risk_config
        cfg = get_risk_config()
        scale = float(cfg.get("lexical.rules.suspicious_keyword.points_scale"))
        cap = float(cfg.get("lexical.rules.suspicious_keyword.max_points"))
        assert scale * 1.0 < 30 and cap < 30

    @pytest.mark.parametrize("domain,before,after,decision", [
        # Weighted fusion averages the new lexical finding against a stronger
        # signal, so adding TRUE evidence can lower the number. No decision
        # moved. botnet-controller lands exactly on ti_malicious_floor (85),
        # which is where the pinned malware-c2-panel.test already sits.
        ("data-exfil-node.test", 59, 40, "MONITOR"),
        ("botnet-controller.test", 95, 85, "BLOCK"),
    ])
    def test_fusion_dilution_is_recorded_not_hidden(
            self, domain, before, after, decision):
        assert verdict(domain) == (after, decision)
        assert after < before


# -- nothing else moved ------------------------------------------------------


class TestProtectedAndLegitimateBehaviourIsUnchanged:
    @pytest.mark.parametrize("domain,score,decision", [
        ("malware-c2-panel.test", 85, "BLOCK"),
        ("malware-c2-panel.invalid", 18, "ALLOW"),
        ("kq3v9z7jx1p8w.info", 95, "BLOCK"),
        ("apple-id-verify.xyz", 70, "BLOCK"),
    ])
    def test_protected_values_hold(self, domain, score, decision):
        assert verdict(domain) == (score, decision)

    @pytest.mark.parametrize("domain,score,decision", [
        ("secure-login-microsoft-verify.tk", 100, "BLOCK"),
        ("hdfcbank-netbanking-verify.xyz", 100, "BLOCK"),
        ("paypal-secure-verify.top", 91, "BLOCK"),
        ("amazon-account-suspended.cf", 91, "BLOCK"),
        ("github-login-security.example", 88, "BLOCK"),
        ("zxqvbnmkljhgfd.tk", 99, "BLOCK"),
        ("xjqzwvbnmk4d8f2.top", 100, "BLOCK"),
        ("paypal1.com", 60, "MONITOR"),
    ])
    def test_the_attack_matrix_is_untouched(self, domain, score, decision):
        assert verdict(domain) == (score, decision)

    @pytest.mark.parametrize("domain", [
        "google.com", "github.com", "youtube.com", "microsoft.com",
        "apple.com", "amazon.com", "paypal.com", "wikipedia.org",
        "cdn.jsdelivr.net", "node16cdn.com", "cdn77.com", "fastly.net",
    ])
    def test_legitimate_domains_are_untouched(self, domain):
        assert verdict(domain) == (0, "ALLOW") or verdict(domain)[1] == "ALLOW"
