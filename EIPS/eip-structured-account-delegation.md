---
title: Structured Account Authority
description: Separate account execution code from typed protocol-readable verification.
author: Taek (@leekt)
discussions-to: https://ethereum-magicians.org/t/eip-8397-frame-authenticator-signatures/29517
status: Draft
type: Standards Track
category: Core
created: 2026-08-28
requires: 170, 2929, 3541, 3607, 7702, 7951, 8141, 8298, 8397
---

## Abstract

This proposal extends EIP-8141 with a structured-account code format that separates ordinary account execution from transaction authorization.

```text
0xef02
|| authority_type               (1 byte)
|| execution_implementation     (20 bytes)
|| authority_payload            (type-defined)
```

Two authority types are defined initially.

```text
0x00 INLINE_ROOT
0xef0200
|| execution_implementation     (20 bytes)
|| verifier                     (20 bytes)
|| key_id                       (32 bytes)
```

```text
0x01 VERIFY_IMPLEMENTATION
0xef0201
|| execution_implementation     (20 bytes)
|| verification_implementation  (20 bytes)
```

`INLINE_ROOT` directly binds one protocol-authenticated `(verifier, key_id)` pair to the account. `VERIFY_IMPLEMENTATION` loads a dedicated verification implementation while retaining the structured account as the EVM execution context. The verification implementation may consume authenticated signature metadata, call an external actor keystore, and invoke EIP-8141 `APPROVE` from the account context. Ordinary account calls continue to execute the independent `execution_implementation`.

This combines EIP-8141's frame transaction and signature container with EIP-8130's `authenticator -> actor ID -> authorization` model. It does not introduce a second transaction envelope or a second account execution path.

## Motivation

EIP-8141 permits arbitrary account code to validate frame transactions. This preserves programmability, but couples transaction authorization to the complete wallet implementation. A sequencer seeking static validation must either understand every wallet implementation or execute and trace arbitrary wallet code.

EIP-8130 separates three responsibilities:

```text
authenticator  -> proves a credential and returns an actor identity
authority      -> determines what that actor may authorize
account code   -> performs ordinary execution
```

The useful parts of both designs can be combined without keeping two native-AA systems:

1. EIP-8141 remains the single transaction, frame, payment, and signature format.
2. Protocol or pure signature verification produces a normalized `(verifier, key_id)` result.
3. A structured account identifies a narrow authority path independently from its execution implementation.
4. The authority path calls `APPROVE`, after which ordinary EIP-8141 execution continues.

A simple account can place one root identity directly in its descriptor. A richer account can select a small verification implementation that queries a multi-actor keystore supporting session keys, expiry, recovery, or threshold authority. The wallet's token receivers, batching helpers, hooks, and other application behavior remain in an unrestricted execution implementation.

Executing verification code in the account context solves the immediate EIP-8141 caller problem: the verification code has `ADDRESS == resolved_target`, so it may call `APPROVE` without returning to arbitrary wallet execution code. It also introduces constraints that must be explicit:

- verification code and execution code share the account's storage namespace;
- a top-level verification code-hash allowlist does not automatically bound delegated libraries or external calls;
- external keystore storage is not admitted by EIP-8141's generic public-mempool rules;
- code at the verification implementation address may change independently from the descriptor; and
- code written as a normal stateful contract or proxy does not retain its own storage when executed in another account's context.

This proposal defines those semantics and the profile requirements needed for code-hash-based admission and direct evaluation.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

### Constants

| Name | Value |
|---|---:|
| `STRUCTURED_ACCOUNT_MAGIC` | `0xef02` |
| `INLINE_ROOT` | `0x00` |
| `VERIFY_IMPLEMENTATION` | `0x01` |
| `STRUCTURED_ACCOUNT_COMMON_LENGTH` | `23` |
| `INLINE_ROOT_CODE_LENGTH` | `75` |
| `VERIFY_IMPLEMENTATION_CODE_LENGTH` | `43` |
| `ECRECOVER_VERIFIER` | `address(0x01)` |
| `P256_VERIFIER` | `address(0x100)` |
| `SIGPARAM_KEY_ID` | `0x04` |
| `SIGPARAM_VERIFIER` | `0x05` |
| `ROOT_VERIFY_DATA_LENGTH` | `4` |
| `CONFIGURE_MODE` | `0x03` |
| `CONFIGURE_LENGTH_BYTES` | `2` |
| `CONFIGURE_SUCCESS` | `keccak256("STRUCTURED_ACCOUNT_CONFIGURE_SUCCESS")` |
| `SETDESCRIPTOR_OPCODE` | `TBD` |
| `STRUCTURED_VERIFY_BASE_GAS` | `500` |
| `CONFIGURE_BASE_GAS` | `5000` |
| `SETDESCRIPTOR_BASE_GAS` | `5000` |

The gas values are provisional pending client benchmarks.

### Unified authentication result

Every protocol-validated signature scheme usable for structured authorization produces:

```text
AuthenticationResult {
    verifier    address
    key_id      bytes32
}
```

`verifier` identifies the stateless authentication program or native verification primitive. `key_id` identifies the exact credential or canonical credential configuration proven by the witness.

The initial normalization rules are:

| Signature scheme | `verifier` | `key_id` |
|---|---|---|
| EIP-8141 `SECP256K1` | `ECRECOVER_VERIFIER` | recovered address right-aligned in 32 bytes |
| EIP-8141 `P256` | `P256_VERIFIER` | `keccak256(qx || qy)` |
| EIP-8397 `AUTHENTICATOR` | authenticator address | authenticated EIP-8397 `key_id` |

For P-256, the full 64-byte public key remains part of the opaque protocol-validated signature entry. Computing its 32-byte identifier does not expose the raw signature witness to EVM code.

An `ARBITRARY` signature entry has no authenticated result. It may still be consumed by account code through EIP-8141 `SIGDATACOPY`, but it cannot authorize `INLINE_ROOT` directly.

A multisig, threshold key, or other compound stateless credential MAY define:

```text
key_id = keccak256(canonical credential configuration)
```

provided its authenticator derives that value from the verified witness rather than trusting a transaction-supplied claim.

### EIP-8141 signature attributes

EIP-8141 validated signature entries are extended with immutable `verifier` and `key_id` attributes.

The `SIGPARAM` table is extended with:

| `param` | Return value |
|---|---|
| `0x04` | authenticated `key_id` |
| `0x05` | authenticated `verifier` |

These values are defined only for protocol-validated signatures that produce an `AuthenticationResult`. Requesting either value for `ARBITRARY` results in an exceptional halt.

For EIP-8397 `AUTHENTICATOR`, `SIGPARAM(0x04)` retains the EIP-8397 key identifier and `SIGPARAM(0x05)` returns the authenticator address. For native secp256k1 and P-256 entries, the values are derived according to the table above.

Existing `SIGPARAM(0x00)` `resolved_signer` semantics are unchanged for backward compatibility. Structured authorization SHOULD consume `SIGPARAM_KEY_ID` and `SIGPARAM_VERIFIER` rather than interpreting the scheme-dependent meaning of `resolved_signer`.

### Structured account envelope

Every structured account begins with:

```text
0xef02
|| authority_type               (1 byte)
|| execution_implementation     (20 bytes)
```

The common byte offsets are:

| Bytes | Field |
|---|---|
| `0..1` | `STRUCTURED_ACCOUNT_MAGIC` |
| `2` | `authority_type` |
| `3..22` | `execution_implementation` |
| `23..` | `authority_payload` |

`execution_implementation` MUST be nonzero.

`authority_type` is a tagged-union discriminator, not a sequential version number. Multiple authority types may coexist. Unknown authority types are invalid structured-account code until assigned by a later EIP.

```python
def parse_structured_account(code):
    assert len(code) >= STRUCTURED_ACCOUNT_COMMON_LENGTH
    assert code[0:2] == STRUCTURED_ACCOUNT_MAGIC

    authority_type = code[2]
    execution_implementation = address(code[3:23])
    assert execution_implementation != address(0)

    if authority_type == INLINE_ROOT:
        return parse_inline_root(code)
    if authority_type == VERIFY_IMPLEMENTATION:
        return parse_verify_implementation(code)

    invalid_structured_account()
```

### Authority type `0x00`: inline root

An inline-root account has exactly 75 bytes of code:

```text
0xef0200
|| execution_implementation     (20 bytes)
|| verifier                     (20 bytes)
|| key_id                       (32 bytes)
```

The offsets are:

| Bytes | Field |
|---|---|
| `0..2` | `0xef0200` |
| `3..22` | `execution_implementation` |
| `23..42` | `verifier` |
| `43..74` | `key_id` |

A valid inline-root descriptor requires:

```python
assert len(code) == INLINE_ROOT_CODE_LENGTH
assert code[0:3] == b"\xef\x02\x00"
assert address(code[3:23]) != address(0)
assert address(code[23:43]) != address(0)
assert bytes32(code[43:75]) != bytes32(0)
```

The configured `(verifier, key_id)` is full account authority. It may approve execution, self-payment, sponsorship payment, and structured descriptor replacement.

```python
def authorize_inline_root(descriptor, auth_result):
    return (
        auth_result.verifier == descriptor.verifier
        and auth_result.key_id == descriptor.key_id
    )
```

### Authority type `0x01`: verification implementation

A verification-implementation account has exactly 43 bytes of code:

```text
0xef0201
|| execution_implementation     (20 bytes)
|| verification_implementation  (20 bytes)
```

The offsets are:

| Bytes | Field |
|---|---|
| `0..2` | `0xef0201` |
| `3..22` | `execution_implementation` |
| `23..42` | `verification_implementation` |

A valid descriptor requires:

```python
assert len(code) == VERIFY_IMPLEMENTATION_CODE_LENGTH
assert code[0:3] == b"\xef\x02\x01"
assert address(code[3:23]) != address(0)
assert address(code[23:43]) != address(0)
```

`verification_implementation` is a code source, not an externally called verifier instance. Its runtime code is loaded while the structured account remains the execution-environment account.

The protocol does not assign a Solidity ABI, calldata encoding, actor mapping, keystore address, storage layout, expiry encoding, or scope model to this authority type.

A verification implementation that needs validation-critical constants SHOULD embed them in its runtime code. A canonical actor-keystore adapter may, for example, embed a deterministic keystore address and use the structured account address plus authenticated `key_id` as its lookup key.

Validation-critical pointers stored in ordinary structured-account storage are NOT RECOMMENDED for an authority-separated profile because `execution_implementation` has write access to the same storage during ordinary execution.

### Structured code dispatch

Structured code is recognized before EIP-7702 delegation handling.

For the top-level call of a frame whose `resolved_target` is a structured account:

```python
if frame.mode == VERIFY:
    if descriptor.authority_type == INLINE_ROOT:
        execute_inline_root_verify(frame, descriptor)
    elif descriptor.authority_type == VERIFY_IMPLEMENTATION:
        execute_verification_implementation(frame, descriptor)

elif frame.mode == CONFIGURE:
    execute_structured_configure(frame, descriptor)

else:
    execute_execution_implementation(frame, descriptor)
```

This is protocol code selection analogous to EIP-7702 delegated-code dispatch. It is not execution of the `DELEGATECALL` opcode and does not create an additional EVM call frame.

#### Calls back to the frame target

While the current frame mode is `VERIFY` or `CONFIGURE`, any nested code-executing operation whose target is the current frame's `resolved_target` MUST resolve the same verification code section rather than `execution_implementation`.

This prevents verification code from switching into arbitrary execution code through a self-call. Calls to other structured accounts use their ordinary `execution_implementation` unless they are themselves the current frame's resolved target.

A verification implementation can still explicitly execute another address with `DELEGATECALL` or `CALLCODE`. Such code runs in the same account context and may call `APPROVE`. A code-hash admission policy MUST therefore account for transitive delegated code; whitelisting only the top-level verification implementation is insufficient when dynamic delegated calls are permitted.

### Account-context verification execution

A `VERIFY` frame targeting a `VERIFY_IMPLEMENTATION` account executes with:

| Property | Value |
|---|---|
| code source | runtime code at `verification_implementation` |
| `ADDRESS` | structured account (`resolved_target`) |
| persistent storage | structured account storage |
| transient storage | structured account transient storage |
| top-level `CALLER` | EIP-8141 `ENTRY_POINT` |
| `ORIGIN` | EIP-8141 frame caller, therefore `ENTRY_POINT` in `VERIFY` |
| `CALLVALUE` | `0` |
| calldata | `frame.data`, unchanged |
| static mode | enabled |
| gas pools | frame-declared EIP-8141 limits |
| `CODESIZE`, `CODECOPY` | verification implementation code |
| `EXTCODE*` of `ADDRESS` | structured descriptor code |
| `SELFBALANCE` | structured account balance |

Code resolution is one hop. A precompile, empty account, EIP-7702 delegation indicator, or another structured descriptor is not recursively resolved as a verification implementation.

Because `ADDRESS == resolved_target`, verification code may invoke EIP-8141 `APPROVE`. An external contract reached with `CALL` or `STATICCALL` has its own address and cannot approve on behalf of the structured account. It must return a result to account-context verification code, which performs the final check and invokes `APPROVE`.

A contract designed as a normal stateful verifier or proxy cannot assume it retains storage at `verification_implementation`: every `SLOAD` observes the structured account's storage. Proxy implementation slots at the verification implementation address are therefore not visible. State belonging to a reusable authority service must be reached through an external call or encoded as immutable runtime-code data.

### Inline-root `VERIFY`

An `INLINE_ROOT` `VERIFY` frame contains exactly one unsigned 32-bit big-endian signature index:

```text
signature_index    (4 bytes)
```

It succeeds only when:

1. `len(frame.data) == ROOT_VERIFY_DATA_LENGTH`.
2. `signature_index < len(tx.signatures)`.
3. The referenced signature uses the canonical frame-transaction signing hash.
4. The signature produces an `AuthenticationResult`.
5. The result matches the descriptor's `(verifier, key_id)`.
6. The frame requests a nonzero EIP-8141 approval scope.
7. Every ordinary EIP-8141 structural rule for that approval scope holds.

On success, protocol applies the same effects as:

```text
APPROVE(frame.flags & APPROVE_SCOPE_MASK)
```

No verification or execution implementation bytecode runs.

```python
def execute_inline_root_verify(frame, descriptor, tx):
    assert len(frame.data) == 4
    signature_index = int.from_bytes(frame.data, "big")
    assert signature_index < len(tx.signatures)

    sig = tx.signatures[signature_index]
    assert len(sig.msg) == 0

    auth_result = AuthenticationResult(
        verifier=sig.verifier,
        key_id=sig.key_id,
    )
    assert authorize_inline_root(descriptor, auth_result)

    scope = frame.flags & APPROVE_SCOPE_MASK
    assert scope != 0
    apply_eip8141_approve(resolved_target(frame), scope)
```

### Verification-implementation `VERIFY`

A `VERIFY_IMPLEMENTATION` `VERIFY` frame passes `frame.data` unchanged to account-context verification code.

The implementation MAY:

- read `SIGPARAM_KEY_ID` and `SIGPARAM_VERIFIER`;
- read other EIP-8141 transaction, frame, or signature metadata;
- consume an `ARBITRARY` witness through `SIGDATACOPY`;
- read structured-account storage;
- call a stateless authenticator, actor keystore, or other external authority contract; and
- invoke `APPROVE` after authorization succeeds.

The frame remains subject to EIP-8141 `VERIFY` semantics:

- execution is static except for protocol-defined `APPROVE` effects;
- revert, exceptional halt, or failure to call the required `APPROVE` invalidates the frame transaction;
- the approved scope must be permitted by `frame.flags`; and
- `APPROVE_EXECUTION` is valid only for `tx.sender`.

`frame.data` is opaque to core protocol. It may use packed bytes, Solidity ABI, RLP, SSZ, or another adapter-defined encoding.

A minimal actor-keystore adapter can perform:

```text
signature_index = parse(frame.data)
authenticator = SIGPARAM(SIGPARAM_VERIFIER, signature_index)
actor_id = SIGPARAM(SIGPARAM_KEY_ID, signature_index)

config = keystore.authorize(account=ADDRESS,
                            authenticator=authenticator,
                            actor_id=actor_id,
                            requested_scope=FRAMEPARAM(...))

check config / scope / expiry
APPROVE(requested_scope)
```

The authenticator remains stateless: it proves the credential and returns `actor_id`. Account-specific authorization remains in the authority mapping.

The external keystore does not need to understand EIP-8141 instructions. Only the account-context verification implementation reads frame metadata and calls `APPROVE`.

### Authority separation and account storage

Account-context code selection separates validation bytecode from execution bytecode, but it does not by itself isolate their storage.

`execution_implementation` executes with the same structured account storage and can modify any unprotected slot. Therefore:

- an authority stored in ordinary account slots remains mutable by execution code;
- a verification implementation that reads an implementation pointer, owner, threshold, or key set from ordinary account storage has not fully externalized authority; and
- whitelisting the verification bytecode does not prevent a malicious execution implementation from changing the data that bytecode trusts.

A profile claiming EIP-8130-style separation of authority from execution MUST satisfy at least one of:

1. ultimate authority is stored in an external keystore whose mutation rules do not trust ordinary execution code;
2. authority is committed directly in the structured descriptor, as with `INLINE_ROOT`; or
3. a later EIP defines protocol-protected account storage that ordinary execution cannot modify.

Account-local storage MAY still be used for non-authoritative caches or policy data where execution-controlled mutation is intentional.

### `CONFIGURE` frame

EIP-8141's frame mode table is extended with:

| `mode` | Name | Summary |
|---|---|---|
| `0x03` | `CONFIGURE` | replace a structured descriptor after authorization by its current authority path |

The static frame constraint becomes:

```python
assert frame.mode < 4
```

A `CONFIGURE` frame targets `tx.sender`, carries no approval scope or value, and requires payment to have already been established. The `ATOMIC_BATCH_FLAG` is permitted for `CONFIGURE`.

Its data is:

```text
new_descriptor_length   (2 bytes, uint16 big-endian)
new_descriptor          (new_descriptor_length bytes)
authorization_data      (remaining bytes)
```

A `CONFIGURE` frame is structurally valid only when:

1. `resolved_target == tx.sender`.
2. `tx.sender` currently contains a valid structured descriptor.
3. `payer != None` before the frame begins.
4. `frame.flags & APPROVE_SCOPE_MASK == 0`.
5. no undefined flag bit is set.
6. `frame.value == 0`.
7. `new_descriptor` parses under an active authority type.
8. at most one `CONFIGURE` frame appears in the transaction.
9. no `SENDER` frame precedes it.

Configuration is authorized against the current descriptor, not the proposed descriptor.

#### Inline-root configuration

For `INLINE_ROOT`, `authorization_data` is one 4-byte signature index. The referenced canonical-hash signature must produce an `AuthenticationResult` matching the current inline root. The canonical transaction hash commits to the complete proposed descriptor.

#### Verification-implementation configuration

For `VERIFY_IMPLEMENTATION`, the current verification implementation executes in account context under `CONFIGURE_MODE`, static mode, and `frame.data` calldata.

It may inspect the exact proposed descriptor and perform an admin, root, recovery, or keystore check. Authorization succeeds only when the top-level execution returns exactly 32 bytes equal to `CONFIGURE_SUCCESS`.

`APPROVE` is invalid in `CONFIGURE` because the frame declares no approval scope. The verification implementation MUST bind its success result to the exact new descriptor, structured account, chain/replay domain, and transaction context required by its authority model.

On success, protocol replaces `tx.sender` code with `new_descriptor`. The new descriptor is visible to later frames and follows normal frame and atomic-batch rollback semantics.

### `SETDESCRIPTOR` instruction

`SETDESCRIPTOR` provides a one-way migration path from existing account code into structured authority.

Stack behavior:

```text
[..., offset, length] -> [..., success]
```

The memory range is interpreted as a complete proposed descriptor beginning with `0xef02`.

The instruction causes an exceptional halt when:

- the current transaction is not an EIP-8141 frame transaction;
- the current frame mode is not `SENDER`;
- `ADDRESS != tx.sender`;
- `sender_approved == false` or `payer == None`;
- execution is static;
- execution is initcode; or
- the current execution-context account is already structured.

Otherwise, it charges `SETDESCRIPTOR_BASE_GAS`, memory expansion, and the active code-write cost; validates the descriptor; and replaces the current account code on success. Invalid descriptor input pushes `0` and makes no state change.

Code reached through EIP-7702 delegation may migrate the delegating account because `ADDRESS` is the delegating account. A conventional smart account may expose an account-authorized migration function that reaches this instruction.

Once structured, an account can change authority only through `CONFIGURE`.

`SETDESCRIPTOR_OPCODE` remains to be assigned. Whether this operation should instead be exposed through a system contract or messaging interface is an open design question.

### Ordinary execution

For `DEFAULT` and `SENDER` frames targeting a structured account, code is loaded from `execution_implementation` and executes in the structured account context.

Resolution is one hop. Empty code, precompiles, EIP-7702 delegations, and nested structured descriptors are not recursively followed as execution implementations.

During execution:

- `ADDRESS` and storage belong to the structured account;
- `CODESIZE` and `CODECOPY` observe execution implementation code; and
- `EXTCODE*` of the structured account observes the descriptor.

The execution implementation address is not code-hash pinned by this authority type. Changes to code at that address change account behavior but do not directly alter the authority payload.

### Code installation and replacement restrictions

EIP-3541 is modified to permit creation-time installation of code beginning with `0xef02` only when the complete code is a valid structured descriptor under an active authority type.

EIP-7702 authorization processing MUST NOT overwrite structured code.

EIP-8298 `SETCODEFROM` MUST fail when the current execution-context account is structured, and a structured descriptor MUST NOT be a valid `SETCODEFROM` source.

`SETDESCRIPTOR` MUST fail for an already structured account.

Any future account-code replacement mechanism MUST explicitly specify whether it may replace structured code. The default is that it may not.

Structured accounts have nonempty non-delegation code. Legacy ECDSA transaction origination remains invalid under EIP-3607, while EIP-8141 frame origination is permitted.

### Gas accounting

Inline-root authorization charges:

```text
STRUCTURED_VERIFY_BASE_GAS
+ resolved-target account access
+ referenced signature validation cost
```

Verification-implementation authorization uses the frame's normal execution-gas budget. Resolving `verification_implementation` charges the applicable warm or cold account/code access cost analogously to EIP-7702. Calls and storage reads made by verification code are charged through normal EVM rules.

A direct evaluator MUST reproduce equivalent EVM gas, warm/cold accesses, approval effects, returndata, and failure behavior. Direct evaluation is an optimization, not a repricing.

`CONFIGURE` charges `CONFIGURE_BASE_GAS`, authority-check execution, and the active descriptor code-write cost. `SETDESCRIPTOR` charges its base cost, memory expansion, and code-write cost.

### Public mempool

#### Generic EIP-8141 behavior

An `INLINE_ROOT` `VERIFY` frame is directly evaluable from the descriptor and referenced authenticated signature result.

A `VERIFY_IMPLEMENTATION` frame is consensus-valid by executing its verification code under EIP-8141 `VERIFY` semantics. Without an additional recognized profile, EIP-8141's generic public-mempool trace rules apply.

In particular, the base EIP-8141 public mempool rejects validation that reads storage outside `tx.sender`. Therefore a verification implementation that calls an external actor keystore may be block-valid but is not generically public-mempool eligible unless the network recognizes an exception/profile for that implementation.

#### Code-hash allowlisting is not sufficient by itself

Knowing the top-level verification implementation's runtime code hash establishes which initial bytecode executes. It does not by itself bound:

- dynamic `DELEGATECALL` or `CALLCODE` targets running in account context;
- external `CALL` or `STATICCALL` code and storage dependencies;
- account-storage values mutable by `execution_implementation`;
- block/environment dependencies such as timestamp-based expiry;
- code changes at the verification implementation or external authority addresses; or
- implementation-specific interpretation of opaque `frame.data`.

A chain may still execute and trace the known bytecode. A chain seeking no-tracing admission must define more than a bare code-hash allowlist.

#### Recognized verification profiles

Public-mempool policy MAY recognize a verification profile identified by the runtime code hash at `verification_implementation`.

A complete profile MUST define:

1. the exact runtime code hash;
2. permitted frame modes and approval scopes;
3. the maximum validation execution gas;
4. the frame-data parser or structural constraints;
5. whether `DELEGATECALL` and `CALLCODE` are forbidden, or the complete permitted transitive code-hash closure;
6. permitted external call targets and their required code hashes;
7. an exact dependency function mapping transaction/account inputs to a bounded set of account and storage reads;
8. permitted environmental dependencies, including timestamp if expiry is checked;
9. all events that require pending-transaction revalidation; and
10. an optional direct evaluator that is behaviorally and gas-equivalent to EVM execution.

A profile MAY relax the generic rule forbidding external storage reads, but only for the exact bounded dependencies produced by its dependency function. Any other external storage access rejects the transaction from the public mempool.

A profile that permits dynamic delegated code without pinning its transitive code hashes is incomplete and MUST NOT be used as a no-tracing fast path.

#### Canonical actor-keystore profile

A companion profile can standardize the EIP-8130-style path:

```text
protocol/pure authenticator
  -> (verifier, actor_id)

account-context verification implementation
  -> external keystore lookup(account, actor_id)
  -> check stored verifier, scope, and expiry
  -> APPROVE
```

For bounded invalidation, the actor lookup SHOULD be keyed by both account and actor ID. Any account-level epoch, lock, or shared root additionally read by the profile is a dependency and may increase invalidation fan-out.

To obtain one shared L1/L2 public-mempool path for multi-actor accounts, at least one canonical actor-keystore verification profile, including its code hash and dependency rules, must be standardized or commonly configured. This proposal defines the generic mechanism but does not select that profile.

#### Chain admission

A chain requiring static validation MAY propagate only:

- `INLINE_ROOT`; and
- `VERIFY_IMPLEMENTATION` descriptors whose current runtime code hash matches a recognized profile.

This allowlist applies to verification implementations, not arbitrary execution implementations. An unrecognized implementation may remain block-valid, be accepted through a private/local mempool, or be rejected by chain-specific public admission policy.

Pending transactions MUST be revalidated when any dependency declared by the active profile changes, including the current verification implementation code hash.

## Remaining design questions

The following issues are not fully solved by account-context verification alone.

### Canonical multi-actor authority profile

The core format intentionally does not select a keystore ABI or storage layout. A unified 8130/8141 deployment still needs agreement on at least one canonical actor-keystore verification profile if multi-actor accounts must propagate through the same public mempool across L1 and L2s.

### Shared storage namespace

Verification and execution code share account storage. Strong authority separation therefore requires external authority state, inline descriptor authority, or future protocol-protected slots. Merely separating code addresses does not prevent execution code from changing account-local authority data.

### Verification code identity

The descriptor stores a verification implementation address rather than an expected code hash. Code changes at that address alter authorization semantics without changing account code. Wallets may rely on immutable deployments, while a future authority type may pin the runtime code hash explicitly.

### Transitive code and state dependencies

A top-level allowlist does not cover dynamic libraries or called contracts. Every no-tracing profile must close over delegated code and exact external state dependencies.

### Migration primitive

`SETDESCRIPTOR` still requires opcode assignment, gas benchmarking, client review, and a decision between an opcode, system contract, or transaction messaging interface.

### Pre-validation authority changes

EIP-8130 permits account changes before validation. The current frame model validates the old authority before a paid `CONFIGURE` or keystore-update execution. Atomic rotation and action are possible using the old authority, but first-use-by-a-new-key and just-in-time actor installation require an explicit construction or later extension.

### Nonce model

Keyed/two-dimensional nonces and nonce-free authorizations remain separate from this proposal. A shared production account profile must decide which nonce extensions are required without blocking the base frame format.

### Validation gas budget

Pure authentication cost plus sender and payer verification must fit the active EIP-8141 public-mempool verification budget. Expensive PQ verification or two custom authenticators may require separate authentication and authorization gas buckets or a larger bound.

### Legacy signature authority

Installing structured code prevents legacy transaction origination and EIP-7702 redelegation, but it does not change `ECRECOVER` results used by third-party contracts, permits, or other message-signature systems. Complete retirement of an old ECDSA key remains a separate compatibility problem.

### Cross-chain authority synchronization

A shared account format does not automatically synchronize descriptor changes or external keystore state across chains. Multichain signed updates, proofs, or root synchronization remain authority-profile concerns.

### Post-execution verification

Post-execution assertions and revert-protection use cases are orthogonal to account authority. `SENDER` execution still requires prior account approval, while later assertions require separate ordering and public-mempool policy.

## Rationale

### Why account-context verification

EIP-8141 `APPROVE` requires `ADDRESS == resolved_target`. Calling an external verifier directly cannot approve for the account. Loading a dedicated verification code source while retaining the account context lets that narrow code path call `APPROVE` without re-entering arbitrary wallet execution code.

### Why this is not ordinary `DELEGATECALL`

An actual `DELEGATECALL` would require some account bytecode to initiate it, returning validation to the account implementation problem. Protocol code selection avoids that wrapper and does not add a call frame. The resulting EVM environment intentionally resembles delegated execution.

### Why an actor ID is required

An authenticator address identifies a verification algorithm, not the particular key authorized by an account. Every user may share one stateless P-256 authenticator. The authenticator must therefore derive:

```text
actor_id = keccak256(qx || qy)
```

and authorization must bind the exact `(authenticator, actor_id)` pair. `INLINE_ROOT` stores that pair directly; a keystore adapter looks up the returned actor ID in its authority mapping.

### Why verifier code may be allowlisted

Verification implementations are expected to be much fewer and smaller than wallet execution implementations. A chain can recognize a canonical adapter code hash while leaving wallet execution unrestricted.

The profile requirements exist because a code hash names only the first bytecode object. No-tracing admission also needs bounded transitive code, state, environment, and invalidation dependencies.

### Why the protocol does not know an ABI

The core protocol forwards `frame.data` unchanged. ABI knowledge belongs to the selected verification profile. This lets raw-EVM chains execute the same adapter while L2 clients optionally implement an equivalent direct evaluator.

### Why inline root remains useful

A single-root account should not pay an extra contract and storage read. `INLINE_ROOT` is the one-entry specialization of the same `(verifier, actor_id) -> authority` model used by a multi-actor keystore.

### Why ordinary account storage is insufficient for strong separation

Code separation and state separation are distinct. Both code sections execute with the account's storage, so execution code can mutate slots read by verification code. An external keystore earns its place when authority must remain outside arbitrary wallet execution.

### Why signatures remain in the EIP-8141 list

The signature list provides a common location for protocol validation, witness elision, future aggregation, and signatures consumed during ordinary execution. Structured authority changes how authenticated results are authorized; it does not create a second signature namespace.

### Why configuration is separate from execution approval

Execution/payment approval does not imply root or recovery authority for a multi-actor account. `CONFIGURE` therefore uses the current authority path and a separate fixed success result rather than treating any session key with `APPROVE_EXECUTION` as an administrator.

### Validation after execution

This proposal does not require every verification-like assertion to precede execution. Account authority must be established before `SENDER` frames, while zero-slippage or other postconditions may be evaluated later where transaction and mempool rules permit.

## Backwards Compatibility

This proposal requires a network upgrade because it assigns special semantics to `0xef02`, extends EIP-8141 signature introspection and frame modes, and introduces a descriptor-installation operation.

EIP-3541 prevents newly deployed ordinary code beginning with `0xef`, so existing deployable EVM contracts are not reinterpreted as structured accounts.

Pre-upgrade clients reject structured descriptors and do not understand the new signature attributes, `CONFIGURE`, or `SETDESCRIPTOR`.

## Test Cases

Implementations MUST cover at least the following cases.

### Authentication result

1. A secp256k1 signature exposes `verifier = address(0x01)` and the recovered address as `key_id`.
2. A P-256 signature exposes `verifier = address(0x100)` and `keccak256(qx || qy)` as `key_id`.
3. EIP-8397 exposes the authenticator address and returned key identifier.
4. `SIGPARAM_KEY_ID` and `SIGPARAM_VERIFIER` halt on `ARBITRARY`.
5. Raw P-256 signature bytes remain unavailable through `SIGDATACOPY`.

### Descriptor parsing

1. Accept valid 75-byte `INLINE_ROOT` and 43-byte `VERIFY_IMPLEMENTATION` descriptors.
2. Reject zero implementation, verifier, key ID, or verification implementation.
3. Reject malformed lengths and unknown authority types.
4. Confirm `execution_implementation` always occupies bytes `3..22`.

### Inline root

1. Accept a matching `(verifier, key_id)` and requested approval scope.
2. Reject the same key ID under another verifier.
3. Reject another P-256 key even when a truncated account representation would collide.
4. Use a stateless multisig authenticator whose returned key ID commits to threshold configuration.

### Verification context

1. Confirm `VERIFY` loads verification code, not execution code.
2. Confirm `ADDRESS`, storage, and balance belong to the structured account.
3. Confirm top-level `CALLER` and `ORIGIN` equal `ENTRY_POINT`.
4. Confirm calldata equals `frame.data` byte-for-byte.
5. Confirm `CODESIZE` sees verification code while `EXTCODESIZE(ADDRESS)` sees 43 bytes.
6. Confirm a normal proxy implementation reads the structured account's slots rather than the proxy address's slots.
7. Confirm a nested call back to the frame's resolved target re-enters verification code and cannot switch to execution code.
8. Confirm a direct `DELEGATECALL` to another library retains the account address and that such a library can call `APPROVE`.
9. Confirm an external keystore called with `CALL` cannot itself call `APPROVE` for the account.
10. Confirm the verification implementation can validate the keystore result and call `APPROVE`.

### Storage separation

1. Store an owner in ordinary account storage and show that execution code can change it.
2. Store the same authority in an external keystore and show that ordinary execution cannot change it unless the keystore authorizes the mutation.
3. Confirm a recognized authority-separated profile rejects validation-critical account-storage pointers unless explicitly part of its trust model.

### Recognized profiles

1. Reject a claimed no-tracing profile that permits an unpinned dynamic `DELEGATECALL` target.
2. Admit a profile with a fixed transitive code closure and exact actor-slot dependency.
3. Allow only the declared external keystore slot and reject any additional storage read.
4. Track timestamp as a dependency for expiry.
5. Change verification code, external authority code, or a declared storage slot and revalidate pending transactions.
6. Directly evaluate the profile and reproduce EVM success, gas, warmness, returndata, and approval effects.

### Configuration

1. Rotate an inline root with a canonical-hash signature from the current root.
2. Switch from inline root to verification implementation.
3. Authorize configuration through an external keystore admin and return `CONFIGURE_SUCCESS`.
4. Reject a configuration result not bound to the exact proposed descriptor.
5. Roll back configuration with a failed atomic batch.
6. Keep a successful non-atomic configuration when a later independent frame fails.

### Migration and code replacement

1. Migrate an approved EIP-7702 account in a paid `SENDER` frame.
2. Migrate a conventional smart account through its authorized function.
3. Reject migration before sender approval or payment.
4. Reject `SETDESCRIPTOR` from a structured account.
5. Confirm EIP-7702 and EIP-8298 cannot overwrite structured code.

## Security Considerations

### Verification implementation is authority code

A verification implementation decides whether `APPROVE` or configuration succeeds. A bug that ignores the transaction hash, misparses a key ID, trusts an unauthenticated external result, or grants excessive scope compromises every account using it.

### Code-hash changes

The descriptor names an address, not a code hash. Verification code changes alter authority semantics without changing the descriptor. Nodes must revalidate pending transactions, and wallets should prefer immutable deployments or an authority type that pins code identity.

### Transitive delegated code

Any code reached through `DELEGATECALL` or `CALLCODE` runs as the structured account and may invoke `APPROVE`. A top-level implementation allowlist does not secure dynamic delegate targets. No-tracing profiles must forbid or pin the full delegated code closure.

### Shared account storage

Verification and execution code share storage. A malicious execution implementation can change every ordinary account slot. Authority kept in those slots is not isolated from wallet code.

### External authority contracts

An external keystore cannot approve directly, but malicious or upgradeable authority code can return forged authorization to an adapter that trusts it. Its code, storage, and upgrade authority are part of the security boundary and dependency set.

### Reentrancy and self-calls

Calls back to the frame target re-enter verification code. Verification implementations should reject unexpected callers or recursive entry where appropriate. Recognized profiles must specify whether such calls are permitted.

### Opaque calldata

The protocol does not parse `frame.data` for authority type `0x01`. Wallets and explorers need a parser associated with the recognized verification profile. Unknown code must not be decoded using another profile's ABI.

### Configuration authorization

`CONFIGURE_SUCCESS` must be returned only after authorization commits to the exact new descriptor, account, chain/replay domain, and relevant transaction context. Detached admin signatures may enable replay or descriptor substitution.

### Migration

`SETDESCRIPTOR` relies on the old account authority to approve a paid `SENDER` frame and reach the instruction. A vulnerability in the old account or delegated implementation may permit unauthorized permanent migration.

### Legacy signatures

Structured migration disables legacy transaction origination but does not revoke message signatures already recognized by external contracts. Wallets must not represent descriptor rotation as universal retirement of the old ECDSA identity.

### Client consistency

Clients must agree on descriptor parsing, signature attribute derivation, mode-sensitive code resolution, account-context EVM semantics, `APPROVE` caller checks, profile dependency handling, gas accounting, configuration results, and rollback behavior. Divergence is consensus-critical.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
