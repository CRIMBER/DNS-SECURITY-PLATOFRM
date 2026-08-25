"""Measure the DGA detector's separation on a held-out split.

WHAT THIS IS
------------
An honest sanity check on model behaviour:

* the bigram model is retrained on 80% of the legitimate corpus
* it is evaluated on the held-out 20% it has never seen
* negatives are generated locally by emulating several DGA *string patterns*

WHAT THIS IS NOT
----------------
**This is not a real-world accuracy figure and must never be quoted as one.**
The malicious class is synthetic, the corpus is small, and real DGA traffic
differs from generated samples. It tells us whether the model separates the two
populations at all - nothing more.

The dictionary-DGA family (``suppobox``/``matsnu`` style, which concatenates
real English words) is included deliberately, because it is a known blind spot
for any character-frequency model. Reporting that weakness is the point.

Run:  python backend/scripts/evaluate_dga.py
"""

import math
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import get_risk_config, load_wordlist  # noqa: E402
from backend.app.detection.heuristic import BigramDGADetector  # noqa: E402
from backend.scripts.build_bigram_model import (  # noqa: E402
    ALPHABET,
    load_corpus,
    score as corpus_score,
    train,
)

SEED = 20260825
SAMPLES_PER_FAMILY = 200

CONSONANTS = "bcdfghjklmnpqrstvwxz"
VOWELS = "aeiou"
HEX = "0123456789abcdef"


# -- synthetic DGA families -------------------------------------------------


def gen_uniform_random(rng, n=None):
    n = n or rng.randint(10, 18)
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n))


def gen_alphanumeric(rng, n=None):
    n = n or rng.randint(10, 18)
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def gen_consonant_heavy(rng, n=None):
    n = n or rng.randint(9, 15)
    return "".join(
        rng.choice(CONSONANTS) if rng.random() < 0.82 else rng.choice(VOWELS)
        for _ in range(n)
    )


def gen_hex_like(rng, n=None):
    n = n or rng.randint(12, 20)
    return "".join(rng.choice(HEX) for _ in range(n))


def gen_dictionary_pair(rng, words=None):
    """suppobox/matsnu-style: two real words joined. A known blind spot."""
    return rng.choice(words) + rng.choice(words)


FAMILIES = [
    ("uniform_random", gen_uniform_random),
    ("alphanumeric", gen_alphanumeric),
    ("consonant_heavy", gen_consonant_heavy),
    ("hex_like", gen_hex_like),
    ("dictionary_pair", gen_dictionary_pair),
]


class _Features:
    """Minimal stand-in carrying only what the detector reads."""

    def __init__(self, label, coverage, digit_ratio):
        self.sld = label
        self.domain = label
        self.dictionary_word_coverage = coverage
        self.digit_ratio = digit_ratio


def main():
    rng = random.Random(SEED)
    config = get_risk_config()

    # -- train on 80%, hold out 20% ----------------------------------------
    labels = load_corpus()
    rng.shuffle(labels)
    split = int(len(labels) * 0.8)
    train_labels, holdout_labels = labels[:split], labels[split:]

    log_probs = train(train_labels)
    uniform_logp = math.log(1.0 / (len(ALPHABET) + 1))
    scores = [corpus_score(label, log_probs, uniform_logp) for label in train_labels]
    mean = sum(scores) / len(scores)
    std = math.sqrt(sum((s - mean) ** 2 for s in scores) / len(scores))

    detector = BigramDGADetector(
        model={
            "log_probs": log_probs,
            "alphabet": ALPHABET,
            "uniform_logp": uniform_logp,
            "calibration": {"mean": mean, "std": std},
            "corpus_size": len(train_labels),
            "version": "holdout_eval",
        }
    )

    dictionary = sorted(w for w in load_wordlist("core", "data", "words.txt") if 4 <= len(w) <= 8)

    def suspicion(label):
        from backend.app.core.features import dictionary_coverage

        digits = sum(c.isdigit() for c in label)
        features = _Features(
            label, dictionary_coverage(label), digits / max(1, len(label))
        )
        return detector.analyse(features, config).score

    # -- evaluate ----------------------------------------------------------
    print("=" * 72)
    print(" DGA detector - held-out separation check")
    print(" SYNTHETIC BENCHMARK. NOT a real-world accuracy figure.")
    print("=" * 72)
    print(" trained on {} labels, evaluated on {} unseen labels".format(
        len(train_labels), len(holdout_labels)))
    print()

    legit_scores = [suspicion(label) for label in holdout_labels]
    threshold = float(config.get("dga.factor_thresholds.moderate", 0.5))

    below = sum(1 for s in legit_scores if s < threshold)
    print(" HELD-OUT LEGITIMATE  (n={})".format(len(legit_scores)))
    print("   mean suspicion      : {:.3f}".format(sum(legit_scores) / len(legit_scores)))
    print("   median              : {:.3f}".format(sorted(legit_scores)[len(legit_scores) // 2]))
    print("   scored below {:.2f}   : {}/{}  ({:.1f}%)".format(
        threshold, below, len(legit_scores), 100.0 * below / len(legit_scores)))
    print()

    print(" SYNTHETIC DGA FAMILIES  (n={} each)".format(SAMPLES_PER_FAMILY))
    total_flagged = 0
    total_samples = 0
    for name, generator in FAMILIES:
        samples = [
            generator(rng, dictionary) if name == "dictionary_pair" else generator(rng)
            for _ in range(SAMPLES_PER_FAMILY)
        ]
        family_scores = [suspicion(s) for s in samples]
        flagged = sum(1 for s in family_scores if s >= threshold)
        total_flagged += flagged
        total_samples += len(family_scores)
        marker = "  <-- known blind spot" if name == "dictionary_pair" else ""
        print("   {:16s} mean={:.3f}  flagged>={:.2f}: {:5.1f}%{}".format(
            name,
            sum(family_scores) / len(family_scores),
            threshold,
            100.0 * flagged / len(family_scores),
            marker,
        ))

    print()
    print(" OVERALL (synthetic negatives): {:.1f}% of generated DGA samples flagged".format(
        100.0 * total_flagged / total_samples))
    print(" OVERALL (held-out legitimate): {:.1f}% correctly below threshold".format(
        100.0 * below / len(legit_scores)))
    print()
    print(" Caveats: synthetic malicious class; {} label corpus; character-".format(
        len(labels)))
    print(" frequency models cannot detect dictionary-word DGAs by design.")
    print("=" * 72)


if __name__ == "__main__":
    main()
