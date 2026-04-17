# ADR 0001: Enforce RFC 4880 "Latest Self-Signature Wins" for Key Flags

## Status

Accepted

## Date

2026-04-16

## Context

RFC 4880 section 5.2.3.3 specifies that when multiple self-signatures
exist on a User ID, the one with the latest creation timestamp
supersedes all earlier ones. This applies to all properties carried by
self-signatures, including key flags, algorithm preferences, and key
expiration.

The wecanencrypt library already followed this rule for key expiration
(via `primary_expiration_from_details`) and subkey expiration (via
`is_subkey_valid`), but key flag checks (`can_details_sign`,
`can_primary_certify`, `can_subkey_sign`) used a permissive `any()`
pattern that returned `true` if *any* self-signature — regardless of
age — had the flag set.

This mismatch created a correctness problem: if a key owner issued a
newer self-signature removing the signing capability (e.g., converting
to certify-only), the library would still report the key as
signing-capable because the older self-signature still had the flag.
After a key merge, both old and new self-signatures coexist,
making this scenario realistic.

A cross-analysis against rsop/rpgpie (the reference SOP implementation
using the same rpgp crate) confirmed that rpgpie delegates flag
evaluation to its `Checked` type which performs time-scoped validation,
achieving the same "latest wins" semantics that wecanencrypt lacked.

## Decision

We enforce "latest self-signature wins" for all policy checks
across the library:

1. **Primary key flags** (`can_details_sign`, `can_primary_certify`):
   Find the most recent self-signature per User ID (filtering to
   certification types 0x10-0x13), check flags only on that signature.

2. **Subkey signing flags** (`can_subkey_sign`): Find the most recent
   `SubkeyBinding` (0x18) signature, check flags only on that
   signature.

3. **Subkey encryption flags** (`can_subkey_encrypt`): Same pattern
   for `encrypt_comms`/`encrypt_storage` flags, replacing the old
   `any()` check in `find_valid_encryption_subkeys`.

4. **Primary key expiration** (`primary_expiration_from_details`):
   Filter to self-signature types (0x10-0x13) before selecting the
   newest `KeyExpirationTime`, so third-party certifications cannot
   override the key owner's expiry.

5. **Verification filtering**: Add `can_subkey_sign()` to all five
   verification code paths so only signing-capable subkeys are tried.

6. **Key merge**: Implement proper packet-level merge
   (matching rpgpie's algorithm) so that renewed self-signatures
   accumulate correctly and the "latest wins" consumers see the right
   data.

## Consequences

### Positive

- RFC 4880 section 5.2.3.3 compliance across all policy checks:
  key flags, encryption flags, and key expiration all use consistent
  "latest self-signature wins" semantics.
- A key owner can revoke signing or encryption capability by issuing
  a new self-signature without the corresponding flag; the library
  will respect it.
- Third-party certifications cannot override the key owner's expiry
  even if they carry a `KeyExpirationTime` subpacket with a newer
  creation timestamp.
- Key merge followed by flag evaluation produces correct
  results.
- Verification no longer wastes computation trying non-signing subkeys.

### Negative

- A self-signature without *any* key flags subpacket (theoretically
  valid but unusual) will cause `can_details_sign` to return `false`
  via `key_flags().sign()` returning false on the default. This is
  the correct conservative behavior.

## Alternatives Considered

### Keep `any()` and rely on merge to replace old sigs

The `update_primary_expiry` code path already replaces old
self-signatures rather than accumulating them. However, the merge path
(keyserver updates, third-party imports) does accumulate, so `any()`
would remain incorrect after merge.

### Filter at merge time instead of read time

Discard superseded self-signatures during merge so consumers don't
need to pick the latest. Rejected because: (a) it discards historical
data that may be useful for auditing, (b) it diverges from rpgpie's
approach which keeps all signatures and evaluates at read time, and
(c) it would require the merge layer to understand all policy rules.

## References

- RFC 4880, section 5.2.3.3: "An implementation that encounters
  multiple self-signatures on the same object may resolve the conflict
  by accepting the most recent self-signature."
- RFC 9580, section 5.2.3.5 (same semantics, updated section number)
- rpgpie `merge.rs` — reference merge implementation
- rpgpie `signature.rs:merge_signatures` — signature deduplication
