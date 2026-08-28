---
title: Structured Root Accounts
description: Separate account execution code from a protocol-readable root verifier and public key.
author: Taek (@leekt)
discussions-to: https://ethereum-magicians.org/t/eip-8397-frame-authenticator-signatures/29517
status: Draft
type: Standards Track
category: Core
created: 2026-08-28
requires: 170, 2929, 3541, 3607, 7702, 7951, 8141, 8298
---

## Abstract

This proposal introduces a structured account designator:

```text
0xef0200
|| implementation       (20 bytes)
|| verifier             (20 bytes)
|| pubkey_len           (2 bytes, uint16 big-endian)
|| pubkey               (pubkey_len bytes)
```

The designator separates account execution code from one protocol-readable root verification configuration. The root consists of a verifier address and verifier-specific public-key bytes. It has full account authority: it may approve execution, approve payment, sponsor another sender, and replace the structured account descriptor.

For frame transactions, a `VERIFY` frame targeting a structured account is evaluated directly by protocol. `ECRECOVER` at address `0x01` verifies a secp256k1 root, `P256VERIFY` at address `0x100` verifies a P-256 root, and another verifier address is invoked in a bounded state-independent context. No account validation code is executed.

Non-`VERIFY` calls execute `implementation` in the structured account's context using one-hop delegation semantics. A new `CONFIGURE` frame mode replaces the implementation, verifier, and public key after the current root has approved the sender.

## Motivation

EIP-8141 allows arbitrary account code to validate frame transactions. This preserves programmability, but nodes cannot determine an account's authorization rule without executing and tracing account code.

Separating cryptographic authentication from account execution solves this for the common single-root account. The account code object itself declares:

```text
what code executes
+ what verifier authenticates the root
+ what public key that verifier must use
```

A node can therefore validate the account from one account-code fetch and one bounded signature verification. It does not need to execute wallet code, inspect wallet storage, or read an external keystore.

This proposal deliberately defines only one root credential. Subordinate credentials, session keys, spending limits, target allowlists, recovery workflows, and other wallet-specific policy remain outside this proposal.

The descriptor also avoids an embedded actor list. A list would turn the account designator into a miniature keystore, commit consensus to actor enumeration and role encoding, increase code size, and require replacing the entire list whenever any entry changes.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

### Constants

| Name | Value |
|---|---:|
| `STRUCTURED_ACCOUNT_MAGIC` | `0xef02` |
| `ROOT_ACCOUNT_VERSION` | `0x00` |
| `STRUCTURED_ACCOUNT_PREFIX` | `0xef0200` |
| `STRUCTURED_ACCOUNT_HEADER_LENGTH` | `45` |
| `STRUCTURED_ACCOUNT_PAYLOAD_HEADER_LENGTH` | `42` |
| `PUBKEY_LENGTH_BYTES` | `2` |
| `MIN_PUBKEY_LENGTH` | `1` |
| `MAX_PUBKEY_LENGTH` | `MAX_CODE_SIZE - STRUCTURED_ACCOUNT_HEADER_LENGTH` |
| `ECRECOVER_VERIFIER` | `address(0x01)` |
| `P256_VERIFIER` | `address(0x100)` |
| `ROOT_VERIFY_DATA_LENGTH` | `4` |
| `CONFIGURE_MODE` | `0x03` |
| `STRUCTURED_VERIFY_BASE_GAS` | `500` |
| `CUSTOM_VERIFIER_GAS_LIMIT` | `50000` |
| `CUSTOM_VERIFIER_BASE_COST` | `COLD_ACCOUNT_ACCESS_COST` |
| `CUSTOM_VERIFIER_COST` | `CUSTOM_VERIFIER_BASE_COST + CUSTOM_VERIFIER_GAS_LIMIT` |
| `CONFIGURE_BASE_GAS` | `5000` |

`MAX_CODE_SIZE` is the active EIP-170 maximum deployed-code size. `STRUCTURED_VERIFY_BASE_GAS`, `CUSTOM_VERIFIER_GAS_LIMIT`, and `CONFIGURE_BASE_GAS` are provisional values pending client benchmarks.

### Structured account designator

A version-zero structured root account has the following code:

```text
0xef02
|| version              (1 byte, 0x00)
|| implementation       (20 bytes)
|| verifier             (20 bytes)
|| pubkey_len           (2 bytes, uint16 big-endian)
|| pubkey               (pubkey_len bytes)
```

Equivalently:

```text
0xef0200 || implementation || verifier || pubkey_len || pubkey
```

The byte offsets are:

| Bytes | Field |
|---|---|
| `0..2` | `STRUCTURED_ACCOUNT_PREFIX` |
| `3..22` | `implementation` |
| `23..42` | `verifier` |
| `43..44` | `pubkey_len` |
| `45..` | `pubkey` |

A descriptor is valid only when:

```python
assert code[0:3] == STRUCTURED_ACCOUNT_PREFIX
assert len(code) >= STRUCTURED_ACCOUNT_HEADER_LENGTH + MIN_PUBKEY_LENGTH
assert len(code) <= MAX_CODE_SIZE

implementation = address(code[3:23])
verifier = address(code[23:43])
pubkey_len = int.from_bytes(code[43:45], "big")
pubkey = code[45:]

assert implementation != address(0)
assert verifier != address(0)
assert MIN_PUBKEY_LENGTH <= pubkey_len <= MAX_PUBKEY_LENGTH
assert len(pubkey) == pubkey_len
```

The descriptor has no authority count, authority list, role field, expiry field, commitment, or account-specific policy encoding.

The `implementation` address determines code executed by ordinary calls. The tuple `(verifier, pubkey)` identifies exactly one root verification configuration.

### Public-key encoding

`pubkey` is verifier-specific canonical key data. Version zero defines two native verifier formats.

#### secp256k1 root

When:

```text
verifier == ECRECOVER_VERIFIER
```

`pubkey_len` MUST equal `20`, and `pubkey` is the nonzero Ethereum address derived from the secp256k1 public key.

The descriptor stores the address rather than a full secp256k1 point because the EIP-8141 `SECP256K1` signature path resolves a signer address through `ECRECOVER`.

#### P-256 root

When:

```text
verifier == P256_VERIFIER
```

`pubkey_len` MUST equal `64`, and `pubkey` is:

```text
qx || qy
```

where each coordinate is a 32-byte big-endian field element using the encoding defined by EIP-7951. The all-zero public key is invalid.

#### Custom root verifier

For every other verifier address, `pubkey` is an opaque canonical byte string interpreted by that verifier. The verifier specification is responsible for defining accepted lengths, canonical encoding, and key validity.

A custom verifier address MAY be placed in a descriptor before code exists at that address. Verification fails until the address contains valid regular verifier code.

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
3. The referenced signature uses the canonical transaction signing hash, meaning `len(sig.msg) == 0`.
4. The descriptor's root verifier accepts the referenced signature as specified below.
5. `frame.flags & APPROVE_SCOPE_MASK != 0`.
6. Every ordinary EIP-8141 structural condition for the requested approval scope holds.

If all checks pass, the protocol applies exactly the state and transaction-context effects that would result from the structured account successfully executing:

```text
APPROVE(frame.flags & APPROVE_SCOPE_MASK)
```

No account bytecode is executed. The root has full authority, so no independent role or scope lookup is performed.

Failure of any check makes the frame fail validation and therefore makes the frame transaction invalid under the existing EIP-8141 `VERIFY` rules.

Conceptually:

```python
def execute_structured_verify(frame, tx, state):
    account = resolved_target(frame)
    descriptor = parse_structured_account(state[account].code)

    assert len(frame.data) == ROOT_VERIFY_DATA_LENGTH
    signature_index = int.from_bytes(frame.data, "big")
    assert signature_index < len(tx.signatures)

    sig = tx.signatures[signature_index]
    assert len(sig.msg) == 0

    digest = compute_sig_hash(tx)
    assert verify_root(descriptor, sig, digest, state)

    scope = frame.flags & APPROVE_SCOPE_MASK
    assert scope != 0

    apply_eip8141_approve(
        resolved_target=account,
        scope=scope,
    )
```

### Native secp256k1 verification

When `verifier == ECRECOVER_VERIFIER`:

1. `pubkey_len` MUST equal `20`.
2. The referenced signature entry MUST use EIP-8141 `SECP256K1`.
3. The entry MUST have been successfully protocol-validated by EIP-8141.
4. The entry's `resolved_signer` MUST equal the address encoded in `pubkey`.

No additional EVM or precompile execution occurs during the `VERIFY` frame because EIP-8141 already validated the signature before frame execution.

Conceptually:

```python
def verify_k1_root(descriptor, sig):
    assert descriptor.verifier == ECRECOVER_VERIFIER
    assert descriptor.pubkey_len == 20
    assert sig.scheme == SECP256K1
    return bytes20(sig.resolved_signer) == descriptor.pubkey
```

### Native P-256 verification

When `verifier == P256_VERIFIER`:

1. `pubkey_len` MUST equal `64`.
2. The referenced signature entry MUST use EIP-8141 `P256`.
3. The entry MUST have been successfully protocol-validated by EIP-8141.
4. The `qx || qy` bytes carried by the validated signature entry MUST exactly equal `pubkey`.

The raw P-256 signature remains opaque to EVM execution. This comparison is performed by protocol while processing the already-validated signature entry.

Conceptually:

```python
def verify_p256_root(descriptor, sig):
    assert descriptor.verifier == P256_VERIFIER
    assert descriptor.pubkey_len == 64
    assert sig.scheme == P256

    qx_qy = sig.signature[64:128]
    return qx_qy == descriptor.pubkey
```

### Custom verifier interface

When `verifier` is neither `ECRECOVER_VERIFIER` nor `P256_VERIFIER`, the referenced signature entry MUST use EIP-8141 `ARBITRARY`. Its raw `signature` bytes are interpreted as `proof`.

A custom verifier implements:

```solidity
pragma solidity ^0.8.0;

interface IStructuredRootVerifier {
    function verify(
        bytes32 digest,
        bytes calldata pubkey,
        bytes calldata proof
    ) external view returns (bool);
}
```

The protocol calls `verify(digest, pubkey, proof)` with `CUSTOM_VERIFIER_GAS_LIMIT` gas in the pure verifier context below.

The call succeeds only when it returns exactly 32 bytes containing the ABI encoding of `true`. A `false` result, malformed return data, revert, exceptional halt, out-of-gas condition, or forbidden operation makes root verification fail.

The verifier MUST contain regular deployed code. It MUST NOT be a precompile, an EIP-7702 delegation indicator, or a structured account designator.

There is no fallback from custom root verification to account-code validation.

Conceptually:

```python
def verify_custom_root(descriptor, sig, digest, state):
    assert descriptor.verifier not in [
        ECRECOVER_VERIFIER,
        P256_VERIFIER,
    ]
    assert sig.scheme == ARBITRARY

    require_regular_verifier_code(state, descriptor.verifier)

    return pure_verifier_call(
        target=descriptor.verifier,
        calldata=abi_encode_verify(
            digest,
            descriptor.pubkey,
            sig.signature,
        ),
        gas=CUSTOM_VERIFIER_GAS_LIMIT,
    ) == abi_encode(True)
```

### Pure verifier context

Custom root verification is state-independent and bounded. Its top-level environment is:

| Property | Value |
|---|---|
| `ADDRESS` | verifier address |
| `CALLER` | EIP-8141 `ENTRY_POINT` |
| `CALLVALUE` | `0` |
| calldata | ABI-encoded `verify(digest, pubkey, proof)` |
| static mode | enabled |
| gas limit | `CUSTOM_VERIFIER_GAS_LIMIT` |

The following operations are forbidden and make verification fail:

- world-state reads or writes: `BALANCE`, `SELFBALANCE`, `SLOAD`, `SSTORE`, `TLOAD`, `TSTORE`, `EXTCODESIZE`, `EXTCODECOPY`, `EXTCODEHASH`, and `SELFDESTRUCT`;
- block or transaction-environment reads: `BLOCKHASH`, `COINBASE`, `TIMESTAMP`, `NUMBER`, `PREVRANDAO`, `GASLIMIT`, `CHAINID`, `BASEFEE`, `BLOBHASH`, `BLOBBASEFEE`, `GASPRICE`, and `ORIGIN`;
- contract creation or non-precompile calls: `CREATE`, `CREATE2`, `CALL`, `CALLCODE`, and `DELEGATECALL`;
- logs: `LOG0` through `LOG4`.

`STATICCALL` is allowed only when its target is an active protocol precompile. A `STATICCALL` to any other address makes verification fail.

An opcode introduced after this proposal is forbidden in the pure verifier context unless a later EIP explicitly permits it.

### Custom verifier code access

Reading custom verifier code during direct verification is a consensus state dependency.

The verifier code hash MUST be included in any authentication cache identity. A safe cache key includes at least:

```text
chain_id
fork_id
verifier
verifier_code_hash
digest
keccak256(pubkey)
keccak256(proof)
```

Pending transactions using a custom verifier MUST be revalidated whenever code at the verifier address changes.

Custom-verifier execution does not warm the verifier for subsequent EVM execution. Block-level code-access accounting follows the active block access-list rules.

### Root authority

The root verification configuration is implicitly authorized for all protocol-level account verbs:

- approve execution when the structured account is `tx.sender`;
- approve self-payment;
- approve payment on behalf of another sender;
- replace the structured account descriptor through `CONFIGURE`.

This proposal does not encode narrower root roles. A wallet that does not want one key to have complete authority MUST NOT use version zero.

### `CONFIGURE` frame

A `CONFIGURE` frame replaces the descriptor at `tx.sender` after the sender has been approved under its current authorization mechanism and transaction payment has been established.

The frame data is the descriptor payload without `STRUCTURED_ACCOUNT_PREFIX`:

```text
implementation       (20 bytes)
verifier             (20 bytes)
pubkey_len           (2 bytes, uint16 big-endian)
pubkey               (pubkey_len bytes)
```

The frame is valid only when:

1. `resolved_target == tx.sender`.
2. `sender_approved == true` before the frame begins.
3. `payer != None` before the frame begins.
4. `frame.flags & APPROVE_SCOPE_MASK == 0`.
5. No undefined flag bit is set.
6. `frame.value == 0`.
7. `len(frame.data) >= STRUCTURED_ACCOUNT_PAYLOAD_HEADER_LENGTH + MIN_PUBKEY_LENGTH`.
8. `len(STRUCTURED_ACCOUNT_PREFIX || frame.data) <= MAX_CODE_SIZE`.
9. `frame.data` parses to a valid implementation, verifier, and public key under the descriptor rules above.
10. At most one `CONFIGURE` frame appears in the transaction.
11. No `SENDER` frame precedes it.

The `ATOMIC_BATCH_FLAG` MAY be used with a `CONFIGURE` frame. If configuration is included in an atomic batch and a later frame in that batch fails, the descriptor replacement is reverted with the rest of the batch.

On success, the protocol replaces `tx.sender` code with:

```text
STRUCTURED_ACCOUNT_PREFIX || frame.data
```

The code update is effective immediately for later frames in the same transaction and follows normal frame and atomic-batch revert semantics.

`CONFIGURE` can be used in three cases:

- rotate the root verifier or public key of an existing structured account;
- change its execution implementation;
- migrate an account approved by another EIP-8141 validation path into the structured format.

For an existing structured account, the only way to set `sender_approved` is a successful direct root `VERIFY`, so descriptor replacement is necessarily authorized by the current root.

For an unstructured account, its existing EIP-8141 validation path determines whether migration is authorized. A code-less account can therefore migrate after successful default-account verification, while an existing smart account can migrate after its own `VERIFY` logic approves the sender.

Conceptually:

```python
def execute_configure(frame, tx, state):
    assert resolved_target(frame) == tx.sender
    assert sender_approved
    assert payer is not None
    assert frame.flags & APPROVE_SCOPE_MASK == 0
    assert frame.value == 0

    new_code = STRUCTURED_ACCOUNT_PREFIX + frame.data
    parse_structured_account(new_code)

    state[tx.sender].code = new_code
```

### Why no descriptor-setting opcode

This proposal does not introduce a general `SETDESCRIPTOR` opcode.

A general instruction callable by the delegated implementation would allow execution code to rewrite the root verifier or public key. That would collapse the separation this proposal is intended to create: execution code would once again own authorization.

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
- `EXTCODESIZE`, `EXTCODECOPY`, and `EXTCODEHASH` observe the structured descriptor;
- `CODESIZE` and `CODECOPY` observe the loaded implementation code, matching EIP-7702 delegated-code semantics.

The descriptor remains readable from delegated implementation code through `EXTCODECOPY(ADDRESS, ...)`.

The implementation address is not code-hash pinned by version zero. Changing code at the implementation address changes account execution behavior but does not change root authority.

### Code installation and replacement restrictions

EIP-3541 is modified to permit creation-time installation of code beginning with `0xef0200` only when it is a valid structured descriptor under this proposal.

Code beginning with `0xef02` but not matching a version recognized by the active fork remains invalid for contract creation.

EIP-7702 authorization processing MUST NOT overwrite a structured account. This already follows from EIP-7702 accepting only empty code or an existing EIP-7702 delegation indicator.

EIP-8298 `SETCODEFROM` MUST fail without changing code when the current execution-context account is structured. Without this restriction, delegated implementation code could replace the descriptor and bypass root authorization.

A structured descriptor MUST NOT be a valid source for EIP-8298 `SETCODEFROM`.

Any other proposal that changes account code MUST explicitly specify whether it can replace a structured descriptor. The default is that it cannot.

### EIP-3607 transaction origination

Structured accounts have non-empty code and therefore cannot originate legacy ECDSA transactions under EIP-3607.

They originate frame transactions using direct root verification or another future transaction type that explicitly recognizes structured accounts.

### Gas accounting

Native secp256k1 and P-256 direct verification charges:

```text
STRUCTURED_VERIFY_BASE_GAS
+ ordinary resolved-target account access cost
+ the referenced signature's EIP-8141 protocol-validation cost
```

The signature-validation cost is already included by EIP-8141 in transaction intrinsic and public-mempool verification accounting.

Custom root verification additionally charges the fixed:

```text
CUSTOM_VERIFIER_COST
```

The complete custom-verifier amount is charged even when the verifier returns with unused gas. This gives nodes a statically known upper bound.

`CONFIGURE` charges `CONFIGURE_BASE_GAS` in execution gas plus the state-gas or code-update charge required by the active state-cost schedule. The number of bytes written is the resulting descriptor length.

Execution delegation charges implementation account access exactly as EIP-7702 charges delegated-code resolution.

### Public mempool handling

A structured root `VERIFY` frame is directly evaluable. Its authorization dependencies are:

- the structured account's current code hash;
- the referenced signature entry;
- for a custom verifier, the verifier's current code hash;
- the ordinary nonce, balance, and payer dependencies created by EIP-8141 approval.

No account storage and no external keystore storage are read.

Pending transactions MUST be revalidated when the structured account code changes. A custom-verifier transaction MUST also be revalidated when the verifier code hash changes.

Custom verification counts `CUSTOM_VERIFIER_COST` toward EIP-8141's public-mempool validation-work cap. This proposal does not modify that cap. A transaction containing multiple custom-root verifications may therefore be consensus-valid while ineligible for public-mempool propagation under the active EIP-8141 policy.

Because `CONFIGURE` requires `payer != None`, it is outside the public-mempool validation prefix.

## Rationale

### Why store the verifier and public key directly

The account descriptor is the source of root authority. Storing the verifier and public key directly makes that authority inspectable without an offchain commitment preimage or a separate registry.

A node, wallet, or explorer can read the account code and immediately determine:

```text
which verifier is used
+ which key is authoritative
```

Changing either field changes the account code hash and invalidates only pending transactions from that account.

### Why use verifier addresses

Verifier addresses unify native and custom cryptography in one account format.

- `address(0x01)` selects Ethereum's existing secp256k1 recovery path.
- `address(0x100)` selects EIP-7951 P-256 verification.
- another address selects bounded custom verifier code.

A future fork may assign additional precompile addresses without changing the descriptor structure.

### Why include `pubkey_len`

The key is variable-length because different cryptosystems use different encodings. A two-byte length is sufficient because EIP-170 limits the entire descriptor to less than `2**16` bytes.

Although version zero places the key last, an explicit length makes parsing self-describing and permits a later descriptor version to append fields without redefining the key encoding.

### Why secp256k1 stores an address

The ECRECOVER path authenticates an Ethereum address, not an exposed full public key. Storing the 20-byte derived address matches EIP-8141's native secp256k1 result and avoids adding 44 unnecessary bytes to every such account.

The field remains named `pubkey` at the wire level because it is the verifier-specific root-key representation.

### Why P-256 stores the full point

EIP-7951 verifies a signature against `qx || qy`. Storing the full 64-byte point avoids relying on a 160-bit address hash collision and lets clients compare the exact key used during protocol signature validation.

### Why one root credential

The designator is intended to expose the smallest authority primitive needed for static account reasoning. Enumerating actors in code would make the designator an account registry and would force consensus to define list ordering, maximum list size, roles, expiry, and update behavior.

One root avoids those commitments. It is the account's ultimate authority, equivalent to the root owner of a conventional wallet.

### Why custom verifiers are pure

A custom verifier performs expensive cryptography, not authorization policy. Disallowing state and environmental reads makes its result cacheable and prevents unrelated state changes from invalidating large sets of pending transactions.

Stateful session policy, spending limits, recovery, and application permissions remain execution-layer concerns.

### Why the root has all roles

Version zero models a root, not a subordinate actor. Adding role bits would create a second authorization layer and raise questions about who can restore omitted authority.

Narrow credentials belong in a future version, an external authority provider, or wallet execution logic.

### Why `CONFIGURE` is a frame mode

Descriptor replacement depends on transaction-level approval state and changes the authority used by future transactions. It is therefore more naturally represented as a frame operation than as a general-purpose EVM instruction.

A frame also makes ordering and atomicity explicit. Wallets can rotate the root, change implementation, and execute an action in one transaction, optionally placing configuration and execution in the same atomic batch.

### Why not an external keystore in version zero

A keystore remains useful when authority is genuinely shared across many accounts or when a wallet needs many independently mutable actors.

It is not required for the root-only common case. A future `0xef02` version may define an external-authority pointer without changing version zero.

### Why implementation and authority are separate

The implementation owns execution behavior: batching helpers, token hooks, application integrations, and wallet-specific functionality.

The verifier and public key own ultimate authority. Changing implementation does not implicitly rotate the root, and rotating the root does not require changing execution logic.

## Backwards Compatibility

This proposal requires a network upgrade because it gives special semantics to a new `0xef02` code prefix and adds an EIP-8141 frame mode.

EIP-3541 currently prevents new code starting with `0xef` from being deployed. Existing executable contracts are therefore not reinterpreted as structured accounts.

Pre-upgrade clients reject creation of the descriptor and do not understand `CONFIGURE` frames.

## Test Cases

Implementations MUST cover at least the following cases.

### Descriptor parsing

1. Accept `0xef0200 || implementation || verifier || pubkey_len || pubkey` when every field is valid.
2. Reject code shorter than `STRUCTURED_ACCOUNT_HEADER_LENGTH + MIN_PUBKEY_LENGTH`.
3. Reject a code length greater than `MAX_CODE_SIZE`.
4. Reject a zero implementation.
5. Reject a zero verifier.
6. Reject `pubkey_len == 0`.
7. Reject a `pubkey_len` that differs from the remaining code length.
8. Reject unknown `0xef02` versions.
9. Reject an ECRECOVER descriptor whose key length is not 20.
10. Reject a P256 descriptor whose key length is not 64 or whose key is all zeroes.

### secp256k1 root

1. Store a 20-byte Ethereum address under `ECRECOVER_VERIFIER` and accept a canonical-hash EIP-8141 `SECP256K1` signature resolving to that address.
2. Reject a valid secp256k1 signature from another address.
3. Reject a P-256 or `ARBITRARY` signature entry under `ECRECOVER_VERIFIER`.
4. Reject an explicit-message signature even when it resolves to the configured address.

### P-256 root

1. Store `qx || qy` under `P256_VERIFIER` and accept a matching canonical-hash EIP-8141 `P256` signature.
2. Reject another valid P-256 key whose address hash collides only at an account-defined truncated representation; exact `qx || qy` equality is required.
3. Reject a secp256k1 or `ARBITRARY` signature entry under `P256_VERIFIER`.
4. Reject an explicit-message signature.

### Custom verifier root

1. Deploy regular verifier code, store its address and public key, and accept a matching `ARBITRARY` proof.
2. Reject a proof for another public key.
3. Reject `false`, malformed return data, revert, exceptional halt, and out-of-gas.
4. Reject a verifier that reads storage or block environment data.
5. Reject a verifier that calls a non-precompile contract.
6. Reject a verifier address containing EIP-7702, structured, or empty code.
7. Replace verifier code at the same address and confirm pending transactions are revalidated against the new code hash.

### Approval

1. Use the root to approve execution and self-payment.
2. Use the root of another structured account to approve sponsorship payment.
3. Reject a structured `VERIFY` frame with zero approval flags.
4. Reject a signature index outside the signature list.

### Configuration

1. Verify the current root, establish payment, then replace only the implementation.
2. Verify the current root, establish payment, then replace only the public key.
3. Replace verifier and public key together.
4. Replace every descriptor field and execute the new implementation in a later frame.
5. Place `CONFIGURE` and a later `SENDER` frame in an atomic batch, make the later frame fail, and confirm descriptor replacement is reverted.
6. Configure without an atomic batch, make a later frame fail, and confirm the already-successful configuration remains applied.
7. Reject more than one `CONFIGURE` frame.
8. Reject `CONFIGURE` before payment is established.
9. Reject `CONFIGURE` after a `SENDER` frame.
10. Migrate a code-less sender after default-account approval and payment.
11. Migrate an existing smart account after its ordinary `VERIFY` path approves execution and payment.

### Code replacement restrictions

1. Confirm EIP-7702 authorization cannot overwrite a structured descriptor.
2. Confirm `SETCODEFROM` fails when executed in a structured account context.
3. Confirm a structured descriptor cannot be a `SETCODEFROM` source.

## Security Considerations

### Root compromise

The root key has complete authority. Compromise permits execution, payment, sponsorship, implementation replacement, verifier replacement, and root rotation.

Wallets SHOULD protect the root more strongly than session or application keys.

### Root loss

Version zero contains no guardian, recovery, threshold, or alternate-root mechanism. Losing the root permanently locks descriptor-controlled frame authorization unless the selected verifier implements a recoverable or threshold cryptographic construction entirely within the bounded pure-verification model.

Wallets requiring richer stateful recovery SHOULD use another account format or a future version.

### Public-key disclosure

The root public key or verifier-specific key representation is stored in account code and is public. Wallets MUST NOT use this format for schemes whose security requires the verification key to remain secret.

### Custom verifier changes

Version zero authorizes a custom verifier address, not a verifier code hash. If code at that address can change, authentication semantics can change without replacing the account descriptor.

Wallets SHOULD use immutable verifier deployments or treat verifier upgrade authority as equivalent to root-key authority. Clients MUST include verifier code hash in cache identities and revalidate pending transactions after code changes.

### Custom verifier correctness

A custom verifier defines key parsing and proof validity. A verifier that accepts malformed keys, ignores `digest`, accepts non-canonical proofs, or returns success without cryptographic verification compromises every structured account using it.

### Large public keys

The descriptor may contain a large key up to the EIP-170 code-size limit. Code-deposit, state-growth, calldata, hashing, and verifier-input copy costs MUST be charged under the active gas schedule.

Implementations MUST parse `pubkey_len` before allocating memory and MUST reject inconsistent lengths without copying attacker-controlled amounts.

### Implementation risk

The implementation executes with the structured account's address, balance, and storage. A malicious implementation can transfer assets or corrupt wallet state during a root-approved execution.

It cannot directly replace the root descriptor through ordinary EVM execution under this proposal, but users must still review implementation changes as full account-code upgrades.

### Configuration ordering

A successful non-atomic `CONFIGURE` frame remains applied even when a later independent frame fails. Wallets requiring all-or-nothing behavior MUST use an atomic batch.

### Client consistency

Clients must agree on descriptor parsing, native key comparison, pure-verifier restrictions, custom-verifier return handling, approval effects, immediate code-update visibility, and atomic-batch rollback. Divergence in any of these rules is consensus-critical.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).