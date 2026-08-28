---
title: Structured Account Delegation
description: Separate account execution code from protocol-readable account authority.
author: Taek (@leekt)
discussions-to: https://ethereum-magicians.org/t/eip-8397-frame-authenticator-signatures/29517
status: Draft
type: Standards Track
category: Core
created: 2026-08-28
requires: 170, 2929, 3541, 3607, 7702, 8141, 8298, 8397
---

## Abstract

This proposal introduces a structured account designator whose code begins with `0xef0200`. The designator separates the account's execution implementation from a compact, protocol-readable authority list.

For frame transactions, a `VERIFY` frame targeting a structured account is evaluated directly by protocol. It resolves a signature entry to a normalized credential, checks that credential against the authority list and requested role, and applies the existing execution or payment approval effects without executing account code. Non-`VERIFY` calls execute the designated implementation in the structured account's context, following the delegation model of [EIP-7702](./eip-7702.md).

A new `CONFIGURE` frame mode replaces an existing structured descriptor after authenticating an authority entry carrying the `ADMIN` role. A separate `SETDESCRIPTOR` instruction provides a one-way migration path for senders whose accounts are not yet structured.

## Motivation

[EIP-8141](./eip-8141.md) allows arbitrary account code to validate frame transactions. This preserves account programmability, but the protocol cannot determine an account's authorization rule without executing and tracing that code. Separating expensive cryptographic authentication into a bounded pure function, as in [EIP-8397](./eip-8397.md), solves only part of this problem: the authenticated credential is still passed to stateful account code to decide whether execution or payment is authorized.

A shared external keystore can make authority protocol-readable, but it adds another account and storage path to the common validation case. It also requires the protocol or mempool to know which external storage belongs to which account and how changes to shared state invalidate pending transactions.

Most accounts are expected to use a small number of active credentials. Storing those credentials next to the account's execution pointer gives clients all common-case authorization data from the account code object itself:

```text
account
  ├── execution implementation
  └── authority entries
```

The authority list is intentionally narrow. It answers only the protocol questions required before execution:

- may this credential authorize execution;
- may it pay for this account;
- may it sponsor another account; and
- may it replace this descriptor.

Stateful spending limits, target allowlists, token hooks, session policy, recovery workflows, and other wallet-specific behavior remain execution-layer concerns.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

### Constants

| Name | Value |
|---|---:|
| `STRUCTURED_ACCOUNT_MAGIC` | `0xef02` |
| `INLINE_AUTHORITY_VERSION` | `0x00` |
| `STRUCTURED_ACCOUNT_PREFIX` | `0xef0200` |
| `STRUCTURED_ACCOUNT_HEADER_LENGTH` | `24` |
| `AUTHORITY_ENTRY_LENGTH` | `60` |
| `MAX_AUTHORITY_ENTRIES` | `8` |
| `STRUCTURED_VERIFY_BASE_GAS` | `500` |
| `STRUCTURED_VERIFY_PER_ENTRY_GAS` | `100` |
| `CONFIGURE_BASE_GAS` | `5000` |
| `ROLE_ADMIN` | `0x01` |
| `ROLE_EXECUTE` | `0x02` |
| `ROLE_SELF_PAY` | `0x04` |
| `ROLE_SPONSOR_PAY` | `0x08` |
| `ROLE_MASK` | `0x0f` |
| `STRUCTURED_VERIFY_DATA_LENGTH` | `4` |
| `CONFIGURE_MODE` | `0x03` |
| `CONFIGURE_HEADER_LENGTH` | `4` |
| `SETDESCRIPTOR_OPCODE` | `TBD` |
| `SETDESCRIPTOR_BASE_GAS` | `5000` |

`STRUCTURED_VERIFY_BASE_GAS`, `STRUCTURED_VERIFY_PER_ENTRY_GAS`, `CONFIGURE_BASE_GAS`, and `SETDESCRIPTOR_BASE_GAS` are provisional values pending client benchmarks.

### EIP-8141 structural changes

The EIP-8141 frame-mode table is extended with:

| `mode` | Name | Summary |
|---|---|---|
| `0x03` | `CONFIGURE` | Replace the sender's structured descriptor after direct admin authentication |

The static frame constraint becomes:

```python
assert frame.mode < 4
```

A `CONFIGURE` frame is subject to the additional structural rules defined below. It is never an atomic-batch frame and carries no approval flags.

During frame dispatch, code beginning with `0xef0200` is recognized before ordinary EIP-7702 delegation handling:

```python
if frame.mode == CONFIGURE:
    execute_structured_configure(frame)
elif resolved_target.code.startswith(STRUCTURED_ACCOUNT_PREFIX):
    if frame.mode == VERIFY:
        execute_structured_verify(frame)
    else:
        execute_structured_implementation(frame)
else:
    execute_eip8141_existing_dispatch(frame)
```

A `CONFIGURE` frame targeting anything other than a valid structured account is invalid.

### Structured account designator

A version-zero structured account has the following code:

```text
0xef02
|| version                         (1 byte, 0x00)
|| implementation                  (20 bytes)
|| authority_count                 (1 byte)
|| authority_entries               (60 * authority_count bytes)
```

Equivalently:

```text
0xef0200
|| implementation
|| authority_count
|| authority_entries
```

The byte offsets are:

| Bytes | Field |
|---|---|
| `0..2` | `STRUCTURED_ACCOUNT_PREFIX` |
| `3..22` | `implementation` |
| `23` | `authority_count` |
| `24..` | authority entries |

The total code length MUST be:

```text
STRUCTURED_ACCOUNT_HEADER_LENGTH
+ AUTHORITY_ENTRY_LENGTH * authority_count
```

`authority_count` MUST be at most `MAX_AUTHORITY_ENTRIES`. A count of zero is permitted and creates a structured account that cannot authorize frame execution, payment, or future descriptor replacement.

The `implementation` MUST be nonzero. It is resolved at call time and is not required to contain code when the descriptor is installed.

Resolution follows EIP-7702's one-hop behavior. A precompile or empty implementation executes as empty code, and an implementation that is itself a delegation or structured designator is not followed recursively.

The implementation address is not code-hash pinned. A future version MAY introduce a pinned implementation format.

A byte string beginning with `0xef0200` that does not satisfy every structural rule in this EIP is invalid structured account code.

Equivalent parsing logic is:

```python
def parse_structured_account(code):
    assert code[0:3] == STRUCTURED_ACCOUNT_PREFIX

    implementation = address(code[3:23])
    authority_count = code[23]

    assert implementation != address(0)
    assert authority_count <= MAX_AUTHORITY_ENTRIES
    assert len(code) == (
        STRUCTURED_ACCOUNT_HEADER_LENGTH
        + AUTHORITY_ENTRY_LENGTH * authority_count
    )

    entries = []
    for i in range(authority_count):
        start = STRUCTURED_ACCOUNT_HEADER_LENGTH + i * AUTHORITY_ENTRY_LENGTH
        entries.append(parse_authority_entry(
            code[start:start + AUTHORITY_ENTRY_LENGTH]
        ))

    assert entries are strictly sorted by (scheme, verifier, actor_id)
    return implementation, entries
```

### Authority entries

Each authority entry is encoded as:

```text
scheme                            (1 byte)
verifier                          (20 bytes)
actor_id                          (32 bytes)
roles                             (1 byte)
valid_until                       (6 bytes, uint48 big-endian)
```

The offsets within an entry are:

| Bytes | Field |
|---|---|
| `0` | `scheme` |
| `1..20` | `verifier` |
| `21..52` | `actor_id` |
| `53` | `roles` |
| `54..59` | `valid_until` |

Entries MUST be strictly increasing in lexicographic order over:

```text
scheme || verifier || actor_id
```

Duplicate credential tuples are therefore invalid.

For every entry:

- `actor_id` MUST NOT be zero.
- `roles` MUST NOT be zero.
- `roles & ~ROLE_MASK` MUST equal zero.
- `valid_until == 0` means the entry does not expire.
- otherwise, the entry is live only while `block.timestamp <= valid_until`.

The supported `scheme` values and verifier constraints are:

| `scheme` | Meaning | `verifier` |
|---|---|---|
| `0x01` | EIP-8141 `SECP256K1` | MUST be zero |
| `0x02` | EIP-8141 `P256` | MUST be zero |
| `0x03` | EIP-8397 `AUTHENTICATOR` | MUST be nonzero and equal the authenticator address |

Other scheme values are invalid in version zero. A later EIP defining another protocol-validated signature scheme MAY define its normalization into this format.

### Roles

Roles are grants:

- `ROLE_ADMIN` permits a `CONFIGURE` frame to replace the structured account descriptor.
- `ROLE_EXECUTE` permits approval of `tx.sender` for `SENDER` frame execution.
- `ROLE_SELF_PAY` permits the account to pay for a transaction where it is also `tx.sender`.
- `ROLE_SPONSOR_PAY` permits the account to pay for a transaction where it is not `tx.sender`.

Roles may be combined. `ROLE_ADMIN` does not imply any other role. An entry carrying `ROLE_ADMIN` is a root authority for the descriptor, and multiple root authorities are permitted.

This EIP does not define target allowlists, token limits, call policies, guardians, or recovery semantics. Those remain in the execution implementation or a future descriptor version.

### Credential normalization

Only protocol-validated signature entries may directly authorize a structured account. `ARBITRARY` signature entries cannot be used.

Let `sig` be a successfully validated EIP-8141 signature entry.

For `SECP256K1` or `P256`, normalize it as:

```python
credential = (
    scheme=sig.scheme,
    verifier=address(0),
    actor_id=bytes12(0) || sig.resolved_signer,
)
```

For an EIP-8397 `AUTHENTICATOR` entry, normalize it as:

```python
credential = (
    scheme=AUTHENTICATOR,
    verifier=sig.resolved_signer,
    actor_id=sig.key_id,
)
```

where `sig.resolved_signer` is the authenticator address and `sig.key_id` is the authenticated identifier exposed by EIP-8397.

The signature entry MUST use the canonical frame-transaction signature hash. An entry carrying an explicit `msg` value MUST NOT directly authorize a structured account.

### Structured `VERIFY` frame data

A `VERIFY` frame targeting a structured account carries exactly four bytes:

```text
signature_index                    (4 bytes, uint32 big-endian)
```

The frame is invalid unless:

- `len(frame.data) == STRUCTURED_VERIFY_DATA_LENGTH`;
- `frame.value == 0`; and
- `signature_index < len(tx.signatures)`.

### Direct structured-account verification

When an EIP-8141 `VERIFY` frame resolves to a version-zero structured account, the client MUST directly evaluate the structured account instead of executing its implementation.

Let:

```python
target = resolved_target
sig = tx.signatures[signature_index]
credential = normalize(sig)
```

Derive the roles required by the frame approval flags:

```python
required_roles = 0

if frame.flags & APPROVE_EXECUTION:
    assert target == tx.sender
    required_roles |= ROLE_EXECUTE

if frame.flags & APPROVE_PAYMENT:
    if target == tx.sender:
        required_roles |= ROLE_SELF_PAY
    else:
        required_roles |= ROLE_SPONSOR_PAY
```

`required_roles` MUST NOT be zero.

The client scans the authority entries for an exact match on:

```text
scheme || verifier || actor_id
```

Verification fails unless exactly one matching entry exists, the entry is live, and:

```python
entry.roles & required_roles == required_roles
```

On success:

1. Charge:

   ```text
   STRUCTURED_VERIFY_BASE_GAS
   + STRUCTURED_VERIFY_PER_ENTRY_GAS * authority_count
   ```

   from the frame's execution gas.

2. Apply the effects of EIP-8141 `APPROVE` using the approval scope encoded in `frame.flags`.

3. Complete the frame successfully with empty return data and no logs.

The existing EIP-8141 restrictions on approval scope remain in force. In particular, execution approval can only be granted for `tx.sender`.

Failure of any structured verification rule has the same result as a failed EIP-8141 `VERIFY` frame and makes the transaction invalid.

### Execution dispatch

For every code-executing operation other than direct structured `VERIFY` evaluation, a structured account behaves like an EIP-7702 delegated account whose target is `implementation`.

The affected operations are:

- `CALL`;
- `CALLCODE`;
- `DELEGATECALL`;
- `STATICCALL`;
- a top-level call whose destination is the structured account; and
- an EIP-8141 frame in `DEFAULT` or `SENDER` mode whose resolved target is the structured account.

The implementation code executes in the structured account's execution environment. In particular:

- `ADDRESS` returns the structured account address;
- storage operations access the structured account's storage;
- the account's balance and value semantics are unchanged.

Delegation chains are not followed. The implementation account is read once. If its code is empty, execution succeeds as an empty-code call; otherwise the retrieved bytes are executed directly. If those bytes begin with another special `0xef` designator, they are not interpreted recursively.

### Code introspection

Code introspection follows EIP-7702's distinction between account code and executing code:

- `EXTCODESIZE`, `EXTCODECOPY`, and `EXTCODEHASH` applied to the structured account observe the structured account designator.
- `CODESIZE` and `CODECOPY` during implementation execution observe the implementation code that was loaded for the current frame.

The execution implementation can therefore read its account's authority descriptor with `EXTCODECOPY(ADDRESS, ...)`. No new descriptor-read instruction is introduced.

### `CONFIGURE` frame mode

EIP-8141 frame mode `0x03` is assigned `CONFIGURE`.

A `CONFIGURE` frame replaces the descriptor of `tx.sender` without executing account code. Its frame data is:

```text
signature_index                    (4 bytes, uint32 big-endian)
new_descriptor                     (remaining bytes)
```

A `CONFIGURE` frame is structurally valid only when:

- `frame.mode == CONFIGURE_MODE`;
- `resolved_target == tx.sender`;
- `frame.flags == 0`;
- `frame.value == 0`;
- `signature_index < len(tx.signatures)`;
- the current code of `tx.sender` is a valid version-zero structured account;
- `new_descriptor` is a valid version-zero structured account descriptor; and
- no earlier frame in the transaction has mode `CONFIGURE`.

A transaction MAY contain at most one `CONFIGURE` frame. It MUST be the first frame, except that an optional EIP-8141 expiry verifier frame MAY precede it. A transaction MUST NOT contain both a deploy frame and a `CONFIGURE` frame.

To execute a `CONFIGURE` frame:

1. Normalize `tx.signatures[signature_index]` according to [Credential normalization](#credential-normalization).
2. Read the current descriptor, not `new_descriptor`.
3. Find the exact matching live authority entry in the current descriptor.
4. Require that the entry contains `ROLE_ADMIN`.
5. Charge structured verification gas against `frame.limits.execution`.
6. Charge `CONFIGURE_BASE_GAS` against `frame.limits.execution`.
7. Validate and charge code deposit for `new_descriptor` against `frame.limits.state`.
8. Replace `tx.sender`'s code with `new_descriptor`.
9. Complete the frame successfully with empty return data and no logs.

The signature entry MUST use the canonical frame-transaction signature hash.

The descriptor update follows normal frame and transaction rollback semantics. Subsequent frames in the same transaction observe `new_descriptor`, including its implementation and authority entries.

A `CONFIGURE` frame does not approve execution or payment and does not increment the sender nonce. The transaction must still contain subsequent frames that establish a payer under EIP-8141.

`CONFIGURE` consumes state gas for descriptor code deposit under the active state-gas schedule. The code-deposit charge is assessed for the complete new descriptor even when an identical code blob already exists. No refund is issued for the previous descriptor.

### `SETDESCRIPTOR`

`SETDESCRIPTOR` is a new EVM instruction with opcode `SETDESCRIPTOR_OPCODE`. It provides migration into the structured-account format; it is not the update path for an account that is already structured.

It is defined only during EIP-8141 frame transactions. Executing it under any other transaction type causes an exceptional halt.

The stack inputs are:

| Stack position | Value |
|---|---|
| `top - 0` | `offset` |
| `top - 1` | `length` |

The instruction copies `length` bytes from memory beginning at `offset` and interprets them as a complete version-zero structured account designator.

The instruction causes an exceptional halt when:

- executed in static mode;
- executed from initcode;
- the current frame mode is not `SENDER`;
- `ADDRESS != tx.sender`; or
- the current account already has structured account code.

Entry into a `SENDER` frame already requires the account's existing validation path to have approved execution. That existing authority is the authority for this one-way migration.

If the supplied bytes are not a valid structured account designator, `SETDESCRIPTOR` pushes `0` and makes no state change.

If the supplied bytes are valid:

1. Charge memory expansion and word-copy gas as for `CODECOPY`.
2. Charge `SETDESCRIPTOR_BASE_GAS`.
3. Charge the active code-deposit cost for the complete descriptor length. This charge is assessed even when an identical code blob already exists, so validity and gas do not depend on a client's local code database.
4. Set the current account's code to the supplied descriptor.
5. Push `1`.

Under a state-gas schedule such as the one used by EIP-8141, the code-deposit component is charged in the state dimension according to the active code-deposit rules. The base and copy components are charged as execution gas.

The update follows normal EVM revert semantics. The current frame continues executing the code already loaded for that frame. Later calls to the account in the same transaction observe the new descriptor.

No refund is issued for the previous code.

### Other code-changing mechanisms

Once an account has structured account code, its descriptor can change only through `CONFIGURE`.

In particular:

- EIP-7702 authorization processing MUST treat structured account code as ineligible for delegation replacement.
- `SETDELEGATE`-like instructions MUST treat a structured account as nonempty, non-delegated code and MUST NOT overwrite it.
- [EIP-8298](./eip-8298.md) `SETCODEFROM` and any other self-code-replacement instruction MUST fail when the current account is structured.
- `SETDESCRIPTOR` MUST fail because it is migration-only.

Version zero intentionally provides no migration from structured account code back to regular code or an EIP-7702 delegation indicator. A later EIP MAY define an admin-authorized exit path.

### Contract creation

[EIP-3541](./eip-3541.md) is modified to permit newly created code beginning with `0xef0200` only when the complete returned code is a valid version-zero structured account designator.

All ordinary contract-creation validity and code-size rules, including [EIP-170](./eip-170.md), continue to apply. Invalid code beginning with `0xef` remains rejected.

This permits `CREATE` and `CREATE2` factories to create structured accounts directly. The account address continues to derive from the ordinary creation rules and therefore commits to the initcode, not directly to the descriptor.

### Existing-account migration

An existing smart account can migrate by executing `SETDESCRIPTOR` in a `SENDER` frame after its existing `VERIFY` path has approved the transaction.

An EOA can migrate through the following sequence:

1. install an EIP-7702 delegation to a migration implementation;
2. approve a frame transaction through the existing EOA or delegated-account path;
3. execute the migration implementation in a `SENDER` frame; and
4. call `SETDESCRIPTOR`.

Once migrated, future descriptor changes use `CONFIGURE`, and EIP-7702 authorization processing cannot overwrite the structured descriptor.

### Legacy transaction origination

A structured account is not an EIP-7702 delegation indicator for the purposes of [EIP-3607](./eip-3607.md).

Legacy ECDSA-authenticated transactions whose recovered sender has structured account code remain invalid. Structured accounts originate transactions through account-abstraction transaction types such as EIP-8141.

### Public mempool treatment

A structured `VERIFY` frame is protocol-defined and directly evaluable. It introduces no EVM trace and no storage dependency.

Its mutable validation dependencies are:

- the structured account's code hash;
- the account nonce and balance dependencies already required by EIP-8141 approval;
- the current block timestamp when the matched entry has a nonzero `valid_until`; and
- the code hash dependencies of protocol-validated signatures, including the authenticator code hash required by EIP-8397.

A node SHOULD index a pending transaction by these dependencies. Changing the structured account descriptor invalidates pending transactions from or sponsored by that account, but does not invalidate transactions belonging to unrelated accounts.

The direct structured verification gas counts toward EIP-8141 `MAX_VERIFY_GAS`.

Structured `VERIFY` and `CONFIGURE` frames are added to EIP-8141's direct-evaluation set. A validation prefix consisting only of protocol-defined frames, a possible `CONFIGURE` frame, structured `VERIFY` frames, and otherwise permitted canonical payment frames may be admitted without EVM simulation.

The public mempool recognizes the same validation-prefix shapes as EIP-8141 with an optional `CONFIGURE` frame inserted after an optional expiry verifier and before the ordinary sender or payer verification frames.

## Rationale

### Why authority is stored in account code

The account code hash already lives in the account leaf and is necessarily consulted to dispatch a frame. Placing the common authority list in the code object avoids an additional external account and storage proof during validation.

Changing any authority entry changes only this account's code hash. Pending-transaction invalidation is therefore naturally scoped to the account whose authority changed.

Authority changes are expected to be much less frequent than transaction execution. Paying code-deposit cost on key rotation is an intentional tradeoff for cheap, trace-free common-case validation.

### Why execution code is a separate pointer

Wallet execution code can remain shared across many accounts while each account carries a small unique authority descriptor. Calls still execute common implementation code, but validation does not need to execute that code or understand its storage layout.

This preserves wallet-defined batching helpers, hooks, modules, ERC-1271 behavior, and post-payment policies without making them part of transaction validity.

### Why version zero uses an inline list

A small inline list gives the protocol a complete authorization answer with one account-code lookup. It also avoids defining a shared keystore address, storage-slot derivation, invalidation fan-out rule, and keystore upgrade mechanism in the first version.

The list is bounded at eight entries. Accounts needing larger or genuinely shared authority tables can use a future descriptor version.

`0xef0201` and the rest of the `0xef02 || version` namespace are reserved for later EIPs. A future keystore-backed version should define at least:

- how the keystore implementation is identified or code-hash pinned;
- the exact storage dependency set for one authorization;
- how dependency width and invalidation fan-out are bounded;
- how an authenticated actor identifier maps to protocol roles; and
- how the account changes or removes the keystore pointer.

### Why roles are minimal

The four roles correspond to transaction-validity questions the protocol already has to answer. Fine-grained wallet policy is deliberately excluded.

A session credential that needs target or spending restrictions may carry `ROLE_EXECUTE`, allowing the transaction to pass native validation, while the execution implementation checks the heavier policy after gas payment. Failure of that policy is an ordinary paid execution failure rather than a public-mempool validity failure.

### Why direct evaluation replaces `APPROVE`

The protocol can identify structured account code from its prefix and parse its complete authorization rule. Executing account code merely to emit the approval result would add no expressiveness to the structured path.

Direct evaluation also prevents already deployed ordinary contracts from accidentally becoming frame accounts: only code using the reserved structured format receives this behavior.

### Why configuration is a frame mode

An admin credential should be able to rotate authority without also receiving general execution permission. Granting `ROLE_ADMIN` through an ordinary `SENDER` frame would either require `ROLE_EXECUTE` as well or give arbitrary implementation code a privileged descriptor-write capability.

`CONFIGURE` instead performs one narrow protocol operation:

```text
current ADMIN credential
    -> validate new descriptor
    -> replace descriptor
```

No execution implementation runs, and the new descriptor is committed by the canonical transaction signature hash.

### Why `SETDESCRIPTOR` is migration-only

Before migration, a smart account's existing validation code is its authority. Allowing that account to install a structured descriptor in an already-approved `SENDER` frame provides a practical upgrade path.

After migration, allowing implementation code to call the same instruction would couple execution and authority again. Structured accounts therefore update only through `CONFIGURE`.

### Why the prefix is `0xef0200`

EIP-7702 uses `0xef0100 || address` for unstructured delegation. This proposal assigns the adjacent `0xef02` family to structured account objects and uses the following byte as a format version.

EIP-8141 previously described `0xef02 || version || ...` as a possible future public-key alias format, but did not normatively allocate it. Version zero is assigned here to an executable-account descriptor. Future public-key aliases can use another `0xef02` version or a separate reserved object family.

### Why no descriptor-read opcode

During delegated execution, EIP-7702 already makes the account's own designator observable through `EXTCODECOPY(ADDRESS, ...)`, while `CODECOPY` observes implementation code. Adding a second read mechanism would duplicate existing functionality.

### Implementation code-hash pinning

Version zero stores only an implementation address, matching EIP-7702. This allows shared implementation upgrades but means a change to code at the implementation address changes the behavior of every account pointing to it.

A later version may add an expected implementation code hash. Such a version should define failure behavior when the live code hash does not match.

## Backwards Compatibility

This proposal changes the meaning of the previously rejected `0xef0200` code prefix and requires a hard fork.

Code beginning with `0xef` cannot normally be created after EIP-3541. Ethereum mainnet therefore has no valid post-EIP-3541 contract that this proposal reinterprets. Private networks or genesis allocations containing code beginning with `0xef0200` must audit that code before activation.

Existing EIP-7702 delegation indicators retain their current behavior.

Existing contracts and EOAs do not become structured accounts unless their code is explicitly replaced with a valid structured descriptor or they are created with one.

Tooling that assumes every account beginning with `0xef` is an EIP-7702 delegation indicator must be updated to distinguish `0xef0100` from `0xef0200`.

## Test Cases

Implementations MUST cover at least the following cases.

### Descriptor validation

1. Accept a descriptor with one valid authority entry.
2. Accept a descriptor with zero and with eight entries.
3. Reject a descriptor with more than eight entries.
4. Reject a descriptor whose length does not equal `24 + 60 * authority_count`.
5. Reject duplicate or unsorted credential tuples.
6. Reject a zero actor ID, zero roles, unknown role bits, unsupported scheme, invalid verifier field, or zero implementation.

### Execution dispatch

1. Call a structured account and assert that implementation code executes with `ADDRESS` equal to the structured account.
2. Assert that implementation storage reads and writes affect the structured account.
3. Assert that `EXTCODECOPY(account)` returns the descriptor while `CODECOPY` returns implementation code.
4. Assert that a `DEFAULT` or `SENDER` frame follows the implementation.
5. Assert that a `VERIFY` frame does not execute implementation code.

### Native credential verification

1. Match a `SECP256K1` signature using `actor_id = bytes12(0) || resolved_signer`.
2. Match a `P256` signature using the same address normalization.
3. Reject an `ARBITRARY` signature entry.
4. Reject a signature entry carrying an explicit `msg`.

### Authenticator verification

1. Match an EIP-8397 entry by authenticator address and authenticated `key_id`.
2. Reject the same `key_id` returned by a different authenticator.
3. Reject a claimed actor ID that does not equal the authenticated `key_id`.
4. Assert that replacing raw proof bytes without changing the authenticated result does not change structured authorization.

### Role checks

1. Allow `ROLE_EXECUTE` to approve sender execution.
2. Require `ROLE_SELF_PAY` when sender and payer are the same account.
3. Require `ROLE_SPONSOR_PAY` when the payer differs from the sender.
4. Reject role escalation when requested roles are absent from the authority entry.
5. Reject an expired entry.
6. Permit `ROLE_ADMIN` only for `tx.sender`.

### Descriptor replacement

1. Replace a descriptor with a `CONFIGURE` frame authenticated by a live `ROLE_ADMIN` entry.
2. Reject configuration when the matching entry lacks `ROLE_ADMIN`.
3. Reject a second `CONFIGURE` frame, a frame after `VERIFY` or `SENDER`, a nonzero flag or value, or a target other than `tx.sender`.
4. Revert a successful configuration when the transaction or frame is rolled back.
5. Assert that later frames observe the new implementation and authority entries.
6. Reject `SETDESCRIPTOR` when the account is already structured.
7. Reject `SETDESCRIPTOR` from a non-`SENDER` frame, static context, initcode, or an execution address different from `tx.sender`.
8. Migrate a regular smart account and an EIP-7702 delegated account using their existing sender-approval path.

### Code-mutation protection

1. Reject an EIP-7702 authorization attempting to overwrite a structured account.
2. Reject a `SETDELEGATE`-like overwrite.
3. Reject `SETCODEFROM` when EIP-8298 is active.
4. Reject legacy ECDSA transaction origination from the structured account.

### Public mempool

1. Directly evaluate a structured validation prefix without EVM tracing.
2. Directly evaluate a `CONFIGURE` frame followed by structured sender and payer verification.
3. Revalidate pending transactions when the structured account code hash changes.
4. Do not invalidate transactions of unrelated accounts after one descriptor changes.
5. Drop a pending transaction after its matched authority entry expires.
6. Include structured verification and configuration-authentication gas in `MAX_VERIFY_GAS`.

## Security Considerations

### Execution implementation authority

The implementation executes with the account's address, storage, and balance. A malicious implementation can transfer assets or corrupt wallet storage even though it cannot replace the descriptor without `ROLE_ADMIN`.

Separating descriptor replacement from execution does not make an untrusted implementation safe. Wallets must continue to audit implementation code and restrict delegatecalls and modules.

### Configuration transactions

A `CONFIGURE` frame replaces the account's authority and execution pointer before later transaction frames execute. Wallets should present the complete old and new descriptors as a high-risk account-control operation.

Because later frames observe the new descriptor, self-paid configuration generally requires a credential accepted by the new descriptor or a separate sponsor. This enables explicit key handoff but must be handled carefully by wallet transaction builders.

### Authority visibility

Inline actor identifiers, authenticator addresses, roles, and expiry values are public account code. Users requiring hidden credentials or private policy should not place those values directly in version-zero descriptors.

### Expiry and timestamp

Entry expiry uses `block.timestamp`. Applications must account for the ordinary timestamp latitude available to block producers.

### Implementation address mutability

Version zero does not pin the implementation code hash and does not require code to exist at installation time. Accounts share both the benefits and risks of later deployment or code change at that address. Wallets should prefer implementations whose code identity cannot change unexpectedly or wait for a future pinned format.

### Creation-time execution

Normal contract-creation and `SELFDESTRUCT` rules continue to apply. A factory that creates a structured account and invokes its implementation in the same transaction must not treat the descriptor as protection against a malicious implementation during that creation flow.

### Code-state growth

Every distinct authority list produces a distinct code object. Descriptor replacement deposits another code object even if the old object becomes unused. The bounded descriptor size and full code-deposit charge limit abuse, but clients may retain historical or unreferenced code blobs.

### Explicit-message signatures

Structured authorization rejects explicit-message signatures because they may not commit to all transaction fields. Account implementations may still consume explicit-message signatures during ordinary execution under their own rules.

### Cross-chain configuration

A descriptor is chain-local state. Deploying the same descriptor and implementation addresses across chains produces the same authority semantics, but rotating one chain does not automatically rotate another. Cross-chain synchronization remains a wallet responsibility.

### Future descriptor versions

Clients must reject unknown `0xef02` versions as executable account objects unless a later activated EIP defines them. Treating unknown versions as version zero could create role or parsing confusion.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
