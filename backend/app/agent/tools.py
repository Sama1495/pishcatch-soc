"""Tools the orchestrator is allowed to call.

There is no shell tool, no tool that fetches an extracted URL, and no tool that
changes a mailbox. Quarantine is a database mark only.
"""

ALLOWED_TOOLS = (
    "parse_email",
    "extract_indicators",
    "evaluate_rules",
    "lookup_reputation",
    "correlate_indicators",
    "classify_risk",
    "explain",
    "build_brief",
    "simulate_quarantine",
)
