---
title: Structured Root Accounts
description: Separate account execution code from a protocol-readable root credential.
author: Taek (@leekt)
discussions-to: https://ethereum-magicians.org/t/eip-8397-frame-authenticator-signatures/29517
status: Draft
type: Standards Track
category: Core
created: 2026-08-28
requires: 170, 2929, 3541, 3607, 6780, 7702, 8141, 8298, 8397
---

## Abstract

This proposal introduces a fixed-length structured account designator:

```text
0xef0200
|| implementation       (20 bytes)
|| root_commitment      (32 bytes)
```

The designator separates account execution code from one protocol-readable root credential. The root credential has full account authority: it may approve execution, approve payment, sponsor another sender, and replace the structured account descriptor.

For frame transactions, a `VERIFY` frame targeting a structured account is evaluated directly by protocol. The protocol normalizes the referenced signature entry into a credential, compares its commitment against `root_commitment`, and applies the existing EIP-8141 approval effects without executing account code.

Non-`VERIFY` calls execute `implementation` in the structured account's context using one-hop delegation semantics. A new `CONFIGURE` frame mode replaces `implementation` and `root_commitment` after the current root has approved the sender.

## Motivation

EIP-8141 allows arbitrary account code to validate frame transactions. This preserves programmability, but nodes cannot determine the account's authorization rule without executing and tracing account code.

EIP-8397 separates expensive state-independent authentication from stateful account authorization. That makes custom cryptography bounded and cacheable, but the authenticated result is still passed to account code to decide whether execution or payment is authorized.

A shared external keystore can make authorization protocol-readable, but it adds another account and storage path to the common validation case. A variable-length authority list embedded in account code has the opposite problem: it turns the account designator into a miniature keystore, commits the protocol to actor enumeration and role encoding, increases code size, and requires replacing the entire list whenever any entry changes.

This proposal deliberately defines only one root credential. The root is the account's ultimate authority and is represented by a fixed 32-byte commitment. Subordinate credentials, session keys, spending limits, target allowlists, recovery workflows, and other wallet-specific policy remain outside this proposal.

The common path therefore requires only:

```text
account code hash
+ one fixed-size descriptor fetch
+ one protocol-validated credential
```

No authority list is scanned and no account validation code is executed.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

### Constants

| Name | Value |
|---|---:|
| `STRUCTURED_ACCOUNT_MAGIC` | `0xef02` |
| `ROOT_ACCOUNT_VERSION` | `0x00` |
| `STRUCTURED_ACCOUNT_PREFIX` | `0xef0200` |
| `STRUCTURED_ACCOUNT_CODE_LENGTH` | `55` |
| `ROOT_VERIFY_DATA_LENGTH` | `4` |
| `CONFIGURE_MODE` | `0x03` |
| `CONFIGURE_DATA_LENGTH` | `52` |
| `STRUCTURED_VERIFY_GAS` | `500` |
| `CONFIGURE_BASE_GAS` | `5000` |
| `ROOT_CREDENTIAL_DOMAIN` | `keccak256("STRUCTURED_ROOT_ACCOUNT_V0")` |

`STRUCTURED_VERIFY_GAS` and `CONFIGURE_BASE_GAS` are provisional values pending client benchmarks.

### Structured account designator

A version-zero structured root account has exactly 55 bytes of code:

```text
0xef02
|| version              (1 byte, 0x00)
|| implementation       (20 bytes)
|| root_commitment      (32 bytes)
```

Equivalently:

```text
0xef0200 || implementation || root_commitment
```

The byte offsets are:

| Bytes | Field |
|---|---|
| `0..2` | `STRUCTURED_ACCOUNT_PREFIX` |
| `3..22` | `implementation` |
| `23..54` | `root_commitment` |

A descriptor is valid only when:

```python
assert len(code) == STRUCTURED_ACCOUNT_CODE_LENGTH
assert code[0:3] == STRUCTURED_ACCOUNT_PREFIX
assert address(code[3:23]) != address(0)
assert code[23:55] != bytes32(0)
```

The descriptor has no authority count, authority list, role field, expiry field, or account-specific policy encoding.

The `implementation` address determines code executed by ordinary calls. The `root_commitment` identifies exactly one normalized root credential as defined below.

### Normalized root credential

A protocol-validated signature entry is normalized into:

```text
NormalizedCredential {
    scheme               uint8
    verifier             address
    verifier_code_hash   bytes32
    key_id               bytes32
}
```

The normalized values are:

| Signature scheme | `verifier` | `verifier_code_hash` | `key_id` |
|---|---|---|---|
| EIP-8141 `SECP256K1` | zero address | zero | recovered signer, right-aligned in 32 bytes |
| EIP-8141 `P256` | zero address | zero | resolved signer, right-aligned in 32 bytes |
| EIP-8397 `AUTHENTICATOR` | authenticator address | current authenticator code hash | authenticated `key_id` |

An `ARBITRARY` signature entry cannot be used as a structured root credential because the protocol does not authenticate a normalized identity for it.

Future protocol-validated signature schemes MAY define their own normalized `verifier`, `verifier_code_hash`, and `key_id` values.

The root commitment is:

```python
def credential_commitment(credential):
    return keccak256(
        ROOT_CREDENTIAL_DOMAIN
        + bytes1(credential.scheme)
        + bytes20(credential.verifier)
        + bytes32(credential.verifier_code_hash)
        + bytes32(credential.key_id)
    )
```

For contract authenticators, including `verifier_code_hash` pins the root to the exact authenticator code currently installed at the verifier address. A code change therefore changes the normalized root credential and invalidates the old commitment.

### EIP-8141 frame changes

The EIP-8141 frame-mode table is extended with:

| `mode` | Name | Summary |
|---|---|---|
| `0x03` | `CONFIGURE` | Replace the sender's structured root descriptor |

The static frame constraint becomes:

```python
assert frame.mode < 4
```

`CONFIGURE` frames are specified below.

During frame dispatch, valid structured account code is recognized before ordinary EIP-7702 delegation handling:

```python
if frame.mode == CONFIGURE:
    execute_configure(frame)
elif is_structured_account(resolved_target):
    if frame.mode == VERIFY:
        execute_structured_verify(frame)
    else:
        execute_structured_implementation(frame)
else:
    execute_existing_eip8141_dispatch(frame)
```

### Direct root verification

A `VERIFY` frame targeting a structured account does not execute the account implementation.

Its `frame.data` MUST contain exactly one unsigned 32-bit big-endian signature index:

```text
signature_index    (4 bytes)
```

The frame is valid only when:

1. `len(frame.data) == ROOT_VERIFY_DATA_LENGTH`.
2. `signature_index < len(tx.signatures)`.
3. The referenced signature is protocol-validated.
4. The referenced signature uses the canonical transaction signing hash, meaning `len(sig.msg) == 0`.
5. The signature can be normalized under this proposal.
6. `credential_commitment(normalized_credential) == root_commitment`.
7. `frame.flags & APPROVE_SCOPE_MASK != 0`.
8. Every ordinary EIP-8141 structural condition for the requested approval scope holds.

If all checks pass, the protocol applies exactly the state and transaction-context effects that would result from the structured account successfully executing:

```text
APPROVE(frame.flags & APPROVE_SCOPE_MASK)
```

No account bytecode is executed. The root credential has full authority, so no independent role or scope lookup is performed.

Failure of any check makes the frame fail validation and therefore makes the frame transaction invalid under the existing EIP-8141 `VERIFY` rules.

Conceptually:

```python
def execute_structured_verify(frame, tx, state):
    account = resolved_target(frame)
    implementation, root = parse_structured_account(state[account].code)

    assert len(frame.data) == 4
    signature_index = int.from_bytes(frame.data, "big")
    assert signature_index < len(tx.signatures)

    sig = tx.signatures[signature_index]
    assert len(sig.msg) == 0

    credential = normalize_protocol_signature(sig, state)
    assert credential_commitment(credential) == root

    scope = frame.flags & APPROVE_SCOPE_MASK
    assert scope != 0

    apply_eip8141_approve(
        resolved_target=account,
        scope=scope,
    )
```

### Root authority

The committed root credential is implicitly authorized for all protocol-level account verbs:

- approve execution when the structured account is `tx.sender`;
- approve self-payment;
- approve payment on behalf of another sender;
- replace the structured account descriptor through `CONFIGURE`.

This proposal does not encode narrower root roles. A wallet that does not want one credential to have complete authority MUST NOT use version zero.

### `CONFIGURE` frame

A `CONFIGURE` frame replaces the descriptor at `tx.sender` after the sender has been approved under its current authorization mechanism.

The frame data is:

```text
implementation       (20 bytes)
root_commitment      (32 bytes)
```

The frame is valid only when:

1. `resolved_target == tx.sender`.
2. `sender_approved == true` before the frame begins.
3. `frame.flags & APPROVE_SCOPE_MASK == 0`.
4. `frame.value == 0`.
5. `len(frame.data) == CONFIGURE_DATA_LENGTH`.
6. `implementation != address(0)`.
7. `root_commitment != bytes32(0)`.
8. At most one `CONFIGURE` frame appears in the transaction.
9. No `SENDER` frame precedes it.

The `ATOMIC_BATCH_FLAG` MAY be used with a `CONFIGURE` frame. If configuration is included in an atomic batch and a later frame in that batch fails, the descriptor replacement is reverted with the rest of the batch.

On success, the protocol replaces `tx.sender` code with:

```text
0xef0200 || implementation || root_commitment
```

The code update is effective immediately for later frames in the same transaction and follows normal frame and atomic-batch revert semantics.

`CONFIGURE` can be used in three cases:

- rotate the root credential of an existing structured account;
- change its execution implementation;
- migrate an account that was approved by another EIP-8141 validation path into the structured format.

For an existing structured account, the only way to set `sender_approved` is a successful direct root `VERIFY`, so descriptor replacement is necessarily authorized by the current root.

For an unstructured account, its existing EIP-8141 validation path determines whether migration is authorized. A code-less account can therefore migrate after successful default-account verification, while an existing smart account can migrate after its own `VERIFY` logic approves the sender.

Conceptually:

```python
def execute_configure(frame, tx, state):
    assert resolved_target(frame) == tx.sender
    assert sender_approved
    assert frame.flags & APPROVE_SCOPE_MASK == 0
    assert frame.value == 0
    assert len(frame.data) == 52

    implementation = address(frame.data[0:20])
    root = bytes32(frame.data[20:52])

    assert implementation != address(0)
    assert root != bytes32(0)

    state[tx.sender].code = (
        STRUCTURED_ACCOUNT_PREFIX
        + implementation
        + root
    )
```

### Why no descriptor-setting opcode

This proposal does not introduce a general `SETDESCRIPTOR` opcode.

A general instruction callable by the delegated implementation would allow execution code to rewrite the root authority. That would collapse the separation this proposal is intended to create: the execution implementation would once again own authorization.

`CONFIGURE` is instead a transaction-level protocol operation whose precondition is approval under the current authority mechanism. It also provides the migration path that a separate opcode would otherwise serve.

A future proposal MAY define a non-frame interface for structured descriptor replacement, but it MUST preserve the invariant that ordinary execution code cannot unilaterally replace the root.

### Execution delegation

For any code-executing operation targeting a structured account outside direct `VERIFY` or `CONFIGURE` handling, the EVM loads the code at `implementation` and executes it in the structured account's context.

The affected operations are the same as EIP-7702:

- a transaction whose destination is the structured account;
- `CALL`;
- `CALLCODE`;
- `DELEGATECALL`;
- `STATICCALL`.

Resolution is one hop only. If `implementation` is empty, a precompile, an EIP-7702 delegation indicator, or another structured account designator, it is treated as empty code for this resolution path.

During delegated execution:

- `ADDRESS` returns the structured account address;
- storage operations access the structured account's storage;
- `EXTCODESIZE`, `EXTCODECOPY`, and `EXTCODEHASH` observe the 55-byte structured descriptor;
- `CODESIZE` and `CODECOPY` observe the loaded implementation code, matching EIP-7702 delegated-code semantics.

The implementation address is not code-hash pinned by version zero. Changing code at the implementation address changes account execution behavior but does not change root authority.

### Code installation and replacement restrictions

EIP-3541 is modified to permit creation-time installation of code beginning with `0xef0200` only when it is a valid 55-byte structured descriptor.

Code beginning with `0xef02` but not matching a version recognized by the active fork remains invalid for contract creation.

EIP-7702 authorization processing MUST NOT overwrite a structured account. This already follows from EIP-7702 accepting only empty code or an existing EIP-7702 delegation indicator.

EIP-8298 `SETCODEFROM` MUST fail without changing code when the current execution-context account is structured. Without this restriction, delegated implementation code could replace the descriptor and bypass root authorization.

A structured descriptor MUST NOT be a valid source for EIP-8298 `SETCODEFROM`.

Any other proposal that changes account code MUST explicitly specify whether it can replace a structured descriptor. The default is that it cannot.

### EIP-3607 transaction origination

Structured accounts have non-empty code and therefore cannot originate legacy ECDSA transactions under EIP-3607.

They originate frame transactions using direct root verification or another future transaction type that explicitly recognizes structured accounts.

### Gas accounting

Direct structured verification charges:

```text
STRUCTURED_VERIFY_GAS
+ ordinary resolved-target account access cost
+ the referenced signature's protocol-validation cost
```

There is no per-entry scan cost because the descriptor contains exactly one root commitment.

`CONFIGURE` charges `CONFIGURE_BASE_GAS` in execution gas plus the state-gas or code-update charge required by the active state-cost schedule. The code written is always exactly `STRUCTURED_ACCOUNT_CODE_LENGTH` bytes.

Execution delegation charges implementation account access exactly as EIP-7702 charges delegated-code resolution.

### Public mempool handling

A structured root `VERIFY` frame is directly evaluable. Its authorization dependencies are:

- the structured account's current code hash;
- the referenced protocol-validated signature;
- for `AUTHENTICATOR`, the authenticator's current code hash;
- the ordinary nonce, balance, and payer dependencies created by EIP-8141 approval.

No account storage and no external keystore storage are read.

Pending transactions MUST be revalidated when the structured account code changes. An `AUTHENTICATOR` root transaction MUST also be revalidated when the authenticator code hash changes.

Because `CONFIGURE` occurs after sender approval and cannot itself establish `payer`, it is outside the public-mempool validation prefix once the existing EIP-8141 payer requirements have been satisfied.

## Rationale

### Why one root credential

The designator is intended to expose the smallest authority primitive needed for static account reasoning. Enumerating actors in code would make the designator an account registry and would force consensus to define list ordering, maximum list size, roles, expiry, and update behavior.

One root credential avoids those commitments. It is the account's ultimate authority, equivalent to the root owner of a conventional wallet.

### Why a commitment instead of raw key configuration

Different schemes have different key representations. A secp256k1 root can be represented by an address, a P-256 root may use a public-key hash, and a custom authenticator may identify a credential with an arbitrary 32-byte value.

Storing one commitment keeps the descriptor fixed-length and allows future protocol-validated schemes without introducing another account-code version for every key encoding.

### Why pin authenticator code

For an `AUTHENTICATOR` root, authorizing only an address would allow code at that address to change authentication semantics while the account descriptor remained unchanged.

Including the current authenticator code hash in the root commitment makes such a change fail closed. An authenticator upgrade requires an explicit root rotation through `CONFIGURE`.

### Why the root has all roles

Version zero models a root, not a subordinate actor. Adding role bits would create a second authorization layer and raise questions about who can restore omitted authority.

Narrow credentials belong in a future version, an external authority provider, or wallet execution logic.

### Why `CONFIGURE` is a frame mode

Descriptor replacement depends on transaction-level approval state and changes the authority used by future transactions. It is therefore more naturally represented as a frame operation than as a general-purpose EVM instruction.

A frame also makes ordering and atomicity explicit. Wallets can rotate the root, change implementation, and execute an action in one transaction, optionally placing configuration and execution in the same atomic batch.

### Why not an external keystore in version zero

A keystore remains useful when authority is genuinely shared across many accounts or when a wallet needs many independently mutable actors.

It is not required for the root-only common case. A future `0xef02` version may define a fixed external-authority pointer without changing version zero.

### Why implementation and authority are separate

The implementation owns execution behavior: batching helpers, token hooks, application integrations, and wallet-specific functionality.

The root commitment owns ultimate authority. Upgrading implementation code does not implicitly rotate the root, and rotating the root does not require changing execution logic.

## Backwards Compatibility

This proposal requires a network upgrade because it gives special semantics to a new `0xef02` code prefix and adds an EIP-8141 frame mode.

EIP-3541 currently prevents new code starting with `0xef` from being deployed. Existing executable contracts are therefore not reinterpreted as structured accounts.

Pre-upgrade clients reject creation of the descriptor and do not understand `CONFIGURE` frames.

## Test Cases

Implementations MUST cover at least the following cases.

### Descriptor parsing

1. Accept exactly `0xef0200 || nonzero implementation || nonzero root_commitment`.
2. Reject every code length other than 55 bytes.
3. Reject a zero implementation.
4. Reject a zero root commitment.
5. Reject unknown `0xef02` versions.

### Native roots

1. Commit a `SECP256K1` credential and verify a canonical-hash signature from the committed signer.
2. Reject a valid signature from another signer.
3. Commit a `P256` credential and verify the matching signature.
4. Reject an `ARBITRARY` entry as a root credential.
5. Reject an explicit-message signature even when its cryptographic identity matches the root.

### Authenticator roots

1. Commit an EIP-8397 `(authenticator, code_hash, key_id)` credential and accept a matching proof.
2. Reject a proof returning a different `key_id`.
3. Replace code at the authenticator address and reject the previously committed root.
4. Restore the original code hash and confirm the commitment matches again.

### Approval

1. Use the root to approve execution and self-payment.
2. Use the root of another structured account to approve sponsorship payment.
3. Reject a structured `VERIFY` frame with zero approval flags.
4. Reject a signature index outside the signature list.

### Configuration

1. Verify the current root, then replace only the implementation.
2. Verify the current root, then replace only the root commitment.
3. Replace both fields and execute the new implementation in a later frame.
4. Place `CONFIGURE` and a later `SENDER` frame in an atomic batch, make the later frame fail, and confirm descriptor replacement is reverted.
5. Configure without an atomic batch, make a later frame fail, and confirm the already-successful configuration remains applied.
6. Reject more than one `CONFIGURE` frame.
7. Reject `CONFIGURE` after a `SENDER` frame.
8. Migrate a code-less sender after default-account approval.
9. Migrate an existing smart account after its ordinary `VERIFY` path approves execution.

### Code replacement restrictions

1. Confirm EIP-7702 authorization cannot overwrite a structured descriptor.
2. Confirm `SETCODEFROM` fails when executed in a structured account context.
3. Confirm a structured descriptor cannot be a `SETCODEFROM` source.

## Security Considerations

### Root compromise

The root credential has complete authority. Compromise permits execution, payment, sponsorship, implementation replacement, and root rotation.

Wallets SHOULD protect the root more strongly than session or application keys.

### Root loss

Version zero contains no guardian, recovery, threshold, or alternate-root mechanism. Losing the root permanently locks descriptor-controlled frame authorization unless the chosen root authenticator internally implements a recoverable cryptographic construction.

Wallets requiring richer recovery SHOULD use another account format or a future version.

### Authenticator code changes

Authenticator code is pinned by hash in the root commitment. Any code change makes the committed credential unusable until the descriptor is rotated.

Wallet software MUST account for this before selecting an upgradeable authenticator as a root verifier.

### Implementation risk

The implementation executes with the structured account's address, balance, and storage. A malicious implementation can transfer assets or corrupt wallet state during a root-approved execution.

It cannot directly replace the root descriptor through ordinary EVM execution under this proposal, but users must still review implementation changes as full account-code upgrades.

### Configuration ordering

A successful non-atomic `CONFIGURE` frame remains applied even when a later independent frame fails. Wallets requiring all-or-nothing behavior MUST use an atomic batch.

### Commitment preimages

Wallets must retain or be able to reconstruct the normalized credential corresponding to `root_commitment`. The descriptor itself does not reveal the root key or authenticator configuration.

### Client consistency

Clients must agree on descriptor parsing, normalized credential derivation, authenticator code-hash lookup, approval effects, immediate code-update visibility, and atomic-batch rollback. Divergence in any of these rules is consensus-critical.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
