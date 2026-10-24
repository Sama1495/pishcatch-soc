"""Wording for a human yes/no on the policy's offered action.

The policy engine chooses the action. This module only describes the outcome
after a person approves or rejects it. Nothing here touches a mailbox.
"""


def describe_action(decision: str, offered_action: str) -> tuple[bool, str]:
    """Return (simulated, message). ``simulated`` is true only for an approved quarantine."""
    if decision == "approve" and offered_action == "simulate_quarantine":
        return True, "Quarantine was simulated. No mailbox or message was modified."
    if decision == "reject":
        return False, "The offered action was not taken. No mailbox was modified."
    if offered_action == "close_no_containment":
        return False, "Case closed with no containment. No mailbox was modified."
    if offered_action == "manual_investigation":
        return False, "Marked for manual investigation. No mailbox was modified."
    return False, "Kept in analyst review. No mailbox was modified."
