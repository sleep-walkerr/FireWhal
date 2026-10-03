# Operating rules for AI agents in this repo

## Do not file tickets without explicit approval

Creating a GitHub issue is not part of "proceeding". When a ticket seems
warranted, propose it in chat — title plus a one-line scope — and wait for
the user's explicit GO before running `gh issue create`.

Proposing is always allowed; creating is not. The same gate applies to
closing or re-scoping an issue the user has not themselves approved.

## Config formats (pre-v1)

No v1 release exists — there is **no** backward-compatibility obligation.

- A field with an unambiguously safe value **must** carry a
  **fail-closed serde default** (missing ⇒ the safe value, e.g. `Block`;
  the parse succeeds, no alarm). The point is safe-default enforcement,
  not legacy coverage: if our own code emits a file missing the key, or
  the operator deletes the line by accident, the runtime must land on the
  safe value — never fail open, and never turn the whole file into a C1
  alarm.
- File generators **must** still emit every key explicitly — the default
  is a backstop, not a substitute for complete on-disk state. The file
  normalizes to the full form on the next explicit save.
- A structurally malformed file (unparseable, wrong types, unknown
  structure) still goes through the C1 degraded path loudly (fail-closed
  + alarm) — "loud, never implicitly green".
- Wire messages (`Encode`/`Decode`): same posture — pre-v1, breaking
  changes are fine; daemon and kernel still deploy from the same build.
