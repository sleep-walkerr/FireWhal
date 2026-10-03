# Operating rules for AI agents in this repo

## Do not file tickets without explicit approval

Creating a GitHub issue is not part of "proceeding". When a ticket seems
warranted, propose it in chat — title plus a one-line scope — and wait for
the user's explicit GO before running `gh issue create`.

Proposing is always allowed; creating is not. The same gate applies to
closing or re-scoping an issue the user has not themselves approved.

## Config formats (pre-v1)

No v1 release exists — there is **no** backward-compatibility obligation.

- Do **not** add serde-default shims to keep old file shapes parsing.
  Silent acceptance + lazy normalization on next save is forbidden: disk
  and in-memory state must not diverge invisibly.
- If an old shape must still work, **convert it explicitly**: detect the
  old shape, rewrite the file in place to the current one, and log the
  conversion. Otherwise an old-shape file is malformed and goes through the
  C1 degraded path loudly (fail-closed + alarm) — "loud, never implicitly
  green".
- Wire messages (`Encode`/`Decode`): same posture — pre-v1, breaking
  changes are fine; daemon and kernel still deploy from the same build.
