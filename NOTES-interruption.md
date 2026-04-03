# Interruption as first-class state

Prompted by: NQ's own deploy cycle getting interrupted by a context window limit.
The service stopped, restarted, and the notification truncated — making it look
like it just died. Benign here, but the pattern is the trap.

## Core insight

"Controller died mid-ceremony" must be a first-class state, not an edge case.

Success and lucky partial success look almost identical unless you model
interruption explicitly. Governance by séance is not governance.

## Design rules

1. **Never let "started" imply "entitled to finish."**
   A grant to begin ≠ a grant to complete. Distinguish them.

2. **Use short-lived leases, not vibes.**
   If the agent disappears, the lease expires. The system knows:
   - completed
   - in-flight
   - abandoned
   - unknown / needs adjudication

3. **Two-phase anything destructive.**
   stop/start, rotate/promote, revoke/apply:
   - prepare
   - commit
   So "agent died after stop" doesn't become theology.

4. **Receipts need terminal states.**
   Not just "approved" or "executed":
   - began
   - commit_observed
   - rollback_observed
   - lease_expired
   - operator_recovered

5. **Recovery must be operator-legible.**
   "What was attempted, what definitely happened, what is merely presumed?"

## The general pattern

The budget/quota wall is just the budget-flavored version of "control plane
vanished mid-transaction." Any standing system needs to handle:
- network partition during grant use
- process crash between issuance and application
- identity rotation mid-lease
- policy change under live grant

All of these are "the ceremony was interrupted." Model the interruption,
don't pretend it can't happen.
