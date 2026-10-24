"""Combine rule hits into one of four labels.

No suspicious hit is not a clearance. With fewer than two aligning signals the
label is inconclusive. With aligning signals and still no suspicious hit the
label may be likely_benign, and the caveat says that is not proof of safety.
"""

from dataclasses import dataclass

from app.services.rules import RuleHit

MALICIOUS_SCORE = 55

CAVEAT_BENIGN = (
    "No suspicious signals were found, and aligning signals such as authentication "
    "results were present. This is not proof the message is safe. Absence of "
    "detections is not a clearance."
)
CAVEAT_INCONCLUSIVE = (
    "No reliable suspicious signals were found. The message is not declared safe. "
    "Lack of rule hits is not evidence of legitimacy."
)
CAVEAT_MALICIOUS = (
    "This label comes from deterministic heuristics and can be wrong. A human analyst "
    "must confirm it before any real response action."
)
CAVEAT_SUSPICIOUS = (
    "Signals are limited or mixed. This is not a confirmed incident and it is not a "
    "benign clearance."
)


@dataclass(frozen=True)
class Classification:
    label: str
    score: int
    caveat: str
    rationale: str


def classify(hits: list[RuleHit]) -> Classification:
    suspicious = [hit for hit in hits if hit.polarity == "suspicious"]
    benign_ids = {hit.rule_id for hit in hits if hit.polarity == "benign_support"}
    score = _score(suspicious)
    if suspicious and score >= MALICIOUS_SCORE:
        label = "likely_malicious"
        caveat = CAVEAT_MALICIOUS
        rationale = (
            f"Score {score} from {len({hit.rule_id for hit in suspicious})} suspicious rule(s) "
            f"reached the likely_malicious threshold ({MALICIOUS_SCORE})."
        )
    elif suspicious:
        label = "suspicious"
        caveat = CAVEAT_SUSPICIOUS
        rationale = (
            f"Score {score} from suspicious rule(s) "
            f"{', '.join(sorted({hit.rule_id for hit in suspicious}))}. "
            "The score is below the likely_malicious threshold."
        )
    elif len(benign_ids) >= 2:
        label = "likely_benign"
        caveat = CAVEAT_BENIGN
        rationale = (
            "No suspicious rule fired. Aligning signals were present: "
            + ", ".join(sorted(benign_ids))
            + ". Those signals are not a safety proof."
        )
    else:
        label = "inconclusive"
        caveat = CAVEAT_INCONCLUSIVE
        rationale = (
            "No suspicious rule fired, and there were not enough aligning signals "
            "to support a likely_benign label. The message is not declared safe."
        )
    return Classification(label=label, score=score, caveat=caveat, rationale=rationale)


def _score(suspicious: list[RuleHit]) -> int:
    seen: set[str] = set()
    total = 0
    for hit in suspicious:
        if hit.rule_id in seen:
            continue
        seen.add(hit.rule_id)
        total += hit.weight
    return min(100, total)
