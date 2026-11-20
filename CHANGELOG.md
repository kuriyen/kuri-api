# Changelog

## 0.1.1 — 2026-11-20

- Holder-signed requests: a request's time may be at most 2 seconds ahead of
  the peer's reading of the home's clock (`REQUEST_AHEAD_NS`), and still
  30 seconds behind; a peer refuses requests signed up to 4 seconds after it
  started (`START_GUARD_NS`). In 0.1.0 a request could be 30 seconds ahead,
  and one signed ahead could pass a second time at a peer that restarted
  before its time.
- Revocations last for `DEADLINE_SLACK_NS` past the longest grant lifetime,
  so a grant whose deadline overshoots by up to the slack does not outlive
  its principal's revocation.
- `Requests::check` forgets expired nonces at most once a second instead of
  on every request.
- `rust-version` is 1.88, which `sha2` 0.11.1 needs; 0.1.0 claimed 1.85.
- Documentation: a hold's id is not a secret, and a hold is bound to its
  holder; what `max_lifetime_ns` is for; method examples use
  `registry/1.Watch`. The request vectors follow the new rules.

## 0.1.0 — 2026-11-14

- Grants: `Grant`, `GrantRequest` and `GrantError`, and `Grant::check`, the
  check a provider runs offline: the issuer's Ed25519 signature over the
  signed layout `kuri-api.Grant/v1`, the node, kind and instance it names, and
  its deadline on the home's clock.
- Holder-signed requests: `HolderKey` signs a request's digest, time and
  nonce under the layout `kuri-api.HolderRequest/v1`; `Requests::check` runs
  the grant check, takes the time only within 30 seconds of the home's clock
  and not before the peer started, verifies the holder's signature, and
  refuses a nonce seen within the window.
- The home's clock: `HomeClock` from the issuer's signed answer to `Now`
  (`kuri-api.Time/v1`), kept as an offset from the node's monotonic clock;
  answers slower than a second are discarded.
- Revocations: `Revocation` (`kuri-api.Revoke/v1`), the issuer's heartbeat
  (`kuri-api.RevokeHeartbeat/v1`) and the list's answer; `Revocations` keeps
  each revoked principal until its grants have expired, and says when a
  heartbeat means the list should be asked for again. Only an answer sets how
  new the provider's list is. `Requests` refuses a revoked principal, and
  every request until the first answer.
- The registry, for readers: `NodeId`, `CapabilityKind` (with `compute`),
  `Scope`; `Announcement` with its `Capability` list, a compute capability's
  `Compute` and `Accelerator`s, and the node's `Link`s; `Health` (with
  `asleep`), `NodeState`, and `NodeEvent`, the graph as changes: `existing`
  nodes, `idle`, then `added`, `changed` and `removed`.
- Power: `PowerError` and the requests and answers of `Wake`, `Hold`,
  `Renew` and `Release`; a hold lasts at most `MAX_HOLD_NS` (ten minutes)
  unless renewed.
- CBOR maps with named keys for every type; unknown keys are ignored, and an
  unknown enum or union member reads as `Unknown`. A union is a map of `type`
  and `value`.
- Test vectors for the grant check, `tests/vectors/grants.json`, and for
  holder-signed requests, `tests/vectors/requests.json`.
- `tests/surface.json`, generated from the types: every table, struct, enum,
  union and constant this crate mirrors, with its members, for the check
  that keeps it in step with the definition. Every flexible enum lists its
  members in `ALL`.
