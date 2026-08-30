---
title: Structured Account Authority
description: Separate account execution from typed account-context verification.
author: Taek (@leekt)
discussions-to: https://ethereum-magicians.org/t/eip-8397-frame-authenticator-signatures/29517
status: Draft
type: Standards Track
category: Core
created: 2026-08-28
requires: 170, 2929, 3541, 3607, 7702, 7951, 8141, 8298, 8397
---

## Abstract

This proposal extends [EIP-8141](./eip-8141.md) with a structured-account code format that separates ordinary account execution from transaction authorization.

```text
0xef02
|| authority_type               (1 byte)
|| execution_implementation     (20 bytes)
|| authority_payload            (type-defined)
```

Two authority types are initially defined.

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

`INLINE_ROOT` directly binds one protocol-authenticated `(verifier, key_id)` pair to the account.

`VERIFY_IMPLEMENTATION` loads code from `verification_implementation` while retaining the structured account as the EVM execution context. The selected code receives frame calldata unchanged, chooses where and how authority state is represented, and invokes EIP-8141 `APPROVE` from the account context. Ordinary calls execute the independent `execution_implementation`.

A new `CONFIGURE` frame mode and mode-specific `APPROVE_CONFIGURE` action support both:

1. replacing the structured descriptor; and
2. mutating authority state consumed by the current verification implementation.

This combines EIP-8141's frame transaction, payment, execution, and signature container with EIP-8130's `authenticator -> actor identity -> authorization` model. It does not define a second transaction envelope, a second signature namespace, or a mandatory keystore layout.

## Motivation

EIP-8141 permits arbitrary account code to validate frame transactions. This preserves programmability, but couples authorization to the complete wallet implementation. A sequencer seeking a statically understandable path must either recognize every wallet implementation or execute and trace arbitrary wallet code.

EIP-8130 separates three responsibilities:

```text
authenticator  -> proves a credential and returns an actor identity
authority      -> determines what that actor may authorize
account code   -> performs ordinary execution
```

The useful parts of both designs can be combined into one native account model:

1. EIP-8141 remains the single transaction, frame, payment, and signature format.
2. Protocol or pure authentication produces a normalized `(verifier, key_id)` result.
3. A structured account selects a narrow authorization path independently from ordinary wallet execution.
4. The authorization path invokes `APPROVE`, after which ordinary frame execution continues.

The common single-root case requires no state lookup beyond the account descriptor. Richer accounts may select a dedicated verification implementation that uses account storage, a deterministic per-account authority contract, a shared keystore, immutable code data, a committed root, or another authority representation.

The core protocol deliberately does not select among those storage models. The selected verification implementation owns its ABI, state layout, actor mapping, scope model, expiry model, and update mechanism. A chain may recognize selected verification implementation code hashes for public-mempool admission or equivalent direct evaluation without constraining the account's ordinary execution implementation.

Configuration also needs the same separation. Changing the descriptor and changing verification-owned data are distinct operations:

- changing the descriptor replaces the execution implementation, authority type, or verification implementation pointer;
- changing verification-owned data adds or revokes actors, rotates a stateful root, changes a threshold, updates expiry, or modifies another authority parameter without changing the descriptor.

Both operations are authorized by the current authority path and use the same `CONFIGURE` frame and `APPROVE_CONFIGURE` action.

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
| `NO_DESCRIPTOR_CHANGE` | `0x0000` |
| `APPROVE_CONFIGURE` | `0x10` |
| `STRUCTURED_VERIFY_BASE_GAS` | `500` |
| `CONFIGURE_BASE_GAS` | `5000` |

`APPROVE_CONFIGURE` is an `APPROVE` operand used only in `CONFIGURE` mode. It is not part of `APPROVE_SCOPE_MASK` and is not encoded in `frame.flags`.

The gas values are provisional pending client benchmarks.

### Unified authentication result

Every protocol-validated signature scheme usable for structured authorization produces:

```text
AuthenticationResult {
    verifier    address
    key_id      bytes32
}
```

`verifier` identifies the native or pure authentication program. `key_id` identifies the exact credential or canonical credential configuration proven by the witness.

The initial normalization rules are:

| Signature scheme | `verifier` | `key_id` |
|---|---|---|
| EIP-8141 `SECP256K1` | `ECRECOVER_VERIFIER` | recovered address right-aligned in 32 bytes |
| EIP-8141 `P256` | `P256_VERIFIER` | `keccak256(qx || qy)` |
| EIP-8397 `AUTHENTICATOR` | authenticator address | authenticated EIP-8397 `key_id` |

For P-256, the full public key remains part of the opaque protocol-validated signature entry. Computing its identifier does not expose the raw witness to EVM code.

An `ARBITRARY` signature entry does not produce an authenticated result. It may still be consumed through EIP-8141 `SIGDATACOPY`, but it cannot directly authorize `INLINE_ROOT`.

A threshold, multisig, or other compound stateless credential MAY use:

```text
key_id = keccak256(canonical credential configuration)
```

provided the authenticator derives the value from the verified witness rather than trusting a transaction-supplied claim.

### Signature entry attributes

EIP-8141 validated signature entries are extended with immutable `verifier` and `key_id` attributes.

The EIP-8141 `SIGPARAM` table is extended with:

| `param` | Return value |
|---|---|
| `0x04` | authenticated `key_id` |
| `0x05` | authenticated `verifier` |

These values are defined only for signatures that produce an `AuthenticationResult`. Requesting either value for `ARBITRARY` results in an exceptional halt.

For EIP-8397 `AUTHENTICATOR`, `SIGPARAM(0x04)` retains the EIP-8397 key identifier and `SIGPARAM(0x05)` returns the authenticator address. Existing EIP-8141 `resolved_signer` behavior is unchanged for backward compatibility.

### Structured account envelope

Every structured account begins with:

```text
0xef02
|| authority_type               (1 byte)
|| execution_implementation     (20 bytes)
```

The common offsets are:

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

The configured `(verifier, key_id)` is full account authority. It may approve execution, self-payment, sponsorship payment, and descriptor replacement.

```python
def authorize_inline_root(descriptor, auth_result):
    return (
        auth_result.verifier == descriptor.verifier
        and auth_result.key_id == descriptor.key_id
    )
```

An `INLINE_ROOT` account has no implementation-defined mutable authority state. Its root or execution implementation is changed by replacing the descriptor.

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

`verification_implementation` is a code source. It is not an externally called verifier instance and it is not required to store authority at its own address.

The implementation decides where authority state lives. It MAY use, among other designs:

- structured-account storage;
- a deterministic per-account authority address;
- a shared actor keystore;
- immutable data embedded in code;
- a committed root plus transaction proofs; or
- no mutable state at all.

The base protocol assigns no ABI, calldata format, storage layout, actor mapping, scope encoding, expiry encoding, or keystore address to this authority type.

### Mode-sensitive code selection

Structured account code is recognized before EIP-7702 delegation handling.

Frame dispatch is extended as follows:

```python
current_descriptor = (
    parse_structured_account(state[resolved_target].code)
    if is_structured_account(resolved_target)
    else None
)

if frame.mode == CONFIGURE:
    execute_structured_configure(frame, current_descriptor)

elif current_descriptor is not None:
    if frame.mode == VERIFY:
        if current_descriptor.authority_type == INLINE_ROOT:
            execute_inline_root_verify(frame, current_descriptor)
        elif current_descriptor.authority_type == VERIFY_IMPLEMENTATION:
            execute_verification_implementation(
                frame, current_descriptor, static=True
            )
    else:
        execute_execution_implementation(frame, current_descriptor)

else:
    execute_existing_eip8141_dispatch(frame)
```

This is protocol code selection analogous to EIP-7702 delegated-code dispatch. It is not execution of the `DELEGATECALL` opcode and does not create an additional EVM call frame.

The code bytes are loaded directly from the selected implementation address without recursively resolving an EIP-7702 indicator or another structured descriptor at that address.

While the current frame mode is `VERIFY` or `CONFIGURE`, a nested code-executing operation targeting that frame's `resolved_target` MUST select the same verification implementation rather than the execution implementation. This prevents a self-call from switching the authority path into arbitrary wallet execution code.

### Account-context verification

A `VERIFY` frame targeting a `VERIFY_IMPLEMENTATION` account executes with:

| Property | Value |
|---|---|
| code source | runtime code at `verification_implementation` |
| `ADDRESS` | structured account (`resolved_target`) |
| persistent storage | structured account storage |
| transient storage | structured account transient storage |
| top-level `CALLER` | EIP-8141 `ENTRY_POINT` |
| `ORIGIN` | EIP-8141 frame caller |
| `CALLVALUE` | `0` |
| calldata | `frame.data`, unchanged |
| static mode | enabled |
| gas pools | frame-declared EIP-8141 limits |
| `CODESIZE`, `CODECOPY` | verification implementation code |
| `EXTCODE*` of `ADDRESS` | structured descriptor code |
| `SELFBALANCE` | structured account balance |

Because `ADDRESS == resolved_target`, verification code may invoke EIP-8141 `APPROVE`.

An external contract reached with `CALL` or `STATICCALL` has its own address and cannot approve on behalf of the structured account. It must return a result to the account-context verification code, which performs the final authorization check and invokes `APPROVE`.

Every `SLOAD` performed directly by verification code observes the structured account's storage, not storage at `verification_implementation`. A reusable stateful authority service must therefore be called externally, or its state must be represented through another implementation-defined mechanism.

`frame.data` is opaque to the core protocol. It may use packed bytes, Solidity ABI, RLP, SSZ, or another implementation-defined encoding.

A verification implementation MAY:

- read `SIGPARAM_KEY_ID` and `SIGPARAM_VERIFIER`;
- inspect other transaction, frame, or signature metadata;
- consume an `ARBITRARY` witness through `SIGDATACOPY`;
- read structured-account storage;
- call external authority contracts; and
- invoke `APPROVE` after authorization succeeds.

The frame remains subject to EIP-8141 `VERIFY` semantics. Revert, exceptional halt, or failure to invoke the required approval makes the frame transaction invalid. The approved execution/payment scope MUST be permitted by `frame.flags`.

A minimal EIP-8130-style adapter can perform:

```text
signature_index = parse(frame.data)
authenticator = SIGPARAM(SIGPARAM_VERIFIER, signature_index)
actor_id = SIGPARAM(SIGPARAM_KEY_ID, signature_index)

authorization = authority_backend.authorize(
    account = ADDRESS,
    authenticator = authenticator,
    actor_id = actor_id,
    requested_scope = FRAMEPARAM(...)
)

check authorization
APPROVE(requested_scope)
```

The authenticator remains stateless. It proves a credential and returns `actor_id`; the selected authority backend determines whether that actor may approve the requested action.

### Inline-root verification

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
7. Every ordinary EIP-8141 structural rule for that scope holds.

On success, protocol applies the same effects as:

```text
APPROVE(frame.flags & APPROVE_SCOPE_MASK)
```

No verification or execution implementation bytecode runs.

### `APPROVE_CONFIGURE`

This proposal extends the EIP-8141 `APPROVE` instruction with the mode-specific operand `APPROVE_CONFIGURE`.

Existing `APPROVE_PAYMENT`, `APPROVE_EXECUTION`, and `APPROVE_EXECUTION_AND_PAYMENT` behavior is unchanged in `VERIFY` mode. `APPROVE_CONFIGURE` is invalid in `VERIFY`, `DEFAULT`, and `SENDER` modes.

When `APPROVE` is executed with `scope == APPROVE_CONFIGURE` in a `CONFIGURE` frame:

1. If `ADDRESS != resolved_target`, revert the current call frame.
2. If `resolved_target != tx.sender`, revert the current call frame.
3. If `payer == None`, revert the current call frame.
4. If `frame.flags & APPROVE_SCOPE_MASK != 0`, revert the current call frame.
5. If the opcode is not executed in the top-level EVM call frame created for the `CONFIGURE` frame, revert the current call frame.
6. If the current `CONFIGURE` frame has already been approved, revert the current call frame.
7. Mark the current configuration as approved.
8. Terminate the top-level configuration call frame successfully, using the `offset` and `length` operands as return data exactly as existing `APPROVE` does.

`APPROVE_CONFIGURE` does not set `sender_approved`, does not select or change `payer`, does not increment a nonce, and does not collect additional maximum cost.

`APPROVE_CONFIGURE` is permitted in a `CONFIGURE` frame carrying `ATOMIC_BATCH_FLAG`. Existing execution/payment approvals remain unavailable inside an atomic batch. Configuration state and descriptor changes are journaled and revert if the atomic batch is later unrolled.

### `CONFIGURE` frame

EIP-8141's frame mode table is extended with:

| `mode` | Name | Summary |
|---|---|---|
| `0x03` | `CONFIGURE` | mutate verification-owned authority state and optionally install or replace a structured descriptor |

The static frame constraint becomes:

```python
assert frame.mode < 4
```

A `CONFIGURE` frame targets `tx.sender`, carries no value or execution/payment approval scope, and requires transaction payment to have already been established. The atomic-batch flag is permitted.

Its data is:

```text
new_descriptor_length   (2 bytes, uint16 big-endian)
new_descriptor          (new_descriptor_length bytes; omitted when length is zero)
configuration_data      (remaining bytes, authority-implementation-defined)
```

`new_descriptor_length == NO_DESCRIPTOR_CHANGE` means the descriptor remains unchanged. A nonzero length requests descriptor installation or replacement and MUST identify one complete valid structured descriptor.

The frame is structurally valid only when:

1. `resolved_target == tx.sender`.
2. `payer != None` before the frame begins.
3. `frame.flags & APPROVE_SCOPE_MASK == 0`.
4. no undefined flag bit is set.
5. `frame.value == 0`.
6. a nonzero `new_descriptor_length` fits within `frame.data` and the selected bytes parse under an active authority type.
7. at most one `CONFIGURE` frame appears in the transaction.
8. no `SENDER` frame precedes it.

At frame entry, clients create a state checkpoint covering all account, storage, call, log, and descriptor effects of the frame. A `CONFIGURE` frame succeeds only through `APPROVE_CONFIGURE` or one of the direct protocol paths defined below. Returning or stopping normally without approval is a failed configuration and rolls back to the frame-entry checkpoint. Revert or exceptional halt has the same rollback effect.

#### Configuration class 1: authority-state update

When `new_descriptor_length == 0`, the descriptor is not changed.

This form is valid only when the current account is a structured `VERIFY_IMPLEMENTATION` account. The current verification implementation executes in account context with:

| Property | Value |
|---|---|
| code source | current `verification_implementation` |
| `ADDRESS` | structured account |
| calldata | complete `frame.data`, unchanged |
| static mode | disabled |
| frame mode | `CONFIGURE_MODE` |
| gas pools | frame-declared EIP-8141 limits |

The implementation authenticates the current root, admin, recovery path, multisig, or other authority according to its own rules; mutates its chosen authority state; and finally invokes `APPROVE(APPROVE_CONFIGURE)`.

The mutable state may be:

- structured-account storage;
- storage at a deterministic per-account authority contract;
- a shared keystore mapping;
- another external authority service; or
- any other state selected by the verification implementation.

For example, this form can add or revoke a session actor, rotate a stateful root, change an expiry, update a threshold, or modify a recovery configuration without changing the descriptor.

All writes and external calls occur before `APPROVE_CONFIGURE`. Because `APPROVE_CONFIGURE` is restricted to and terminates the top-level configuration call frame, no configuration write can occur after approval. If approval is never reached, all provisional state changes are rolled back. A delegated library may assist the check or mutation, but it must return to the top-level verification implementation, which performs the final `APPROVE_CONFIGURE`.

#### Configuration class 2: descriptor update

When `new_descriptor_length > 0`, the indicated descriptor is installed or replaces the current descriptor after authorization.

If the current account is `VERIFY_IMPLEMENTATION`, the current verification implementation executes in the same non-static configuration context described above. It MAY also mutate verification-owned state before calling `APPROVE_CONFIGURE`. On approval, both the state mutations and descriptor replacement commit. This permits one frame to migrate authority data and switch verification implementations atomically.

If the current account is `INLINE_ROOT`, `configuration_data` MUST contain exactly one unsigned 32-bit big-endian signature index. The referenced canonical-hash signature MUST produce an `AuthenticationResult` matching the current inline root. The protocol then applies the effects equivalent to a successful `APPROVE(APPROVE_CONFIGURE)` and installs the new descriptor. No implementation-defined authority-state mutation occurs on this direct path.

If `tx.sender` is not yet structured:

- `sender_approved` MUST already be true;
- `configuration_data` MUST be empty; and
- the prior EIP-8141 validation path authorizes installation.

The protocol applies the effects equivalent to a successful `APPROVE(APPROVE_CONFIGURE)` and installs the descriptor. An account that cannot yet approve an EIP-8141 frame transaction requires an account-specific migration path outside this proposal.

#### Applying configuration

For a `VERIFY_IMPLEMENTATION` account, the current descriptor always determines which verification code authorizes the frame. The proposed descriptor is never used for authorization before installation.

Conceptually:

```python
def execute_structured_configure(frame, current_descriptor, tx, state):
    assert resolved_target(frame) == tx.sender
    assert payer is not None
    assert frame.flags & APPROVE_SCOPE_MASK == 0
    assert frame.value == 0

    new_len = int.from_bytes(frame.data[0:2], "big")
    assert 2 + new_len <= len(frame.data)

    new_descriptor = None
    if new_len != 0:
        new_descriptor = frame.data[2:2 + new_len]
        parse_structured_account(new_descriptor)

    configuration_data = frame.data[2 + new_len:]
    checkpoint = state.checkpoint()

    if current_descriptor is None:
        assert new_descriptor is not None
        assert sender_approved
        assert len(configuration_data) == 0
        configuration_approved = True

    elif current_descriptor.authority_type == INLINE_ROOT:
        assert new_descriptor is not None
        assert len(configuration_data) == 4
        sig = tx.signatures[int.from_bytes(configuration_data, "big")]
        assert len(sig.msg) == 0
        assert authorize_inline_root(
            current_descriptor,
            AuthenticationResult(sig.verifier, sig.key_id),
        )
        configuration_approved = True

    elif current_descriptor.authority_type == VERIFY_IMPLEMENTATION:
        configuration_approved = execute_current_verification_implementation(
            mode=CONFIGURE_MODE,
            static=False,
            calldata=frame.data,
            success_condition=APPROVE_CONFIGURE,
        )

    if not configuration_approved:
        state.revert(checkpoint)
        return FRAME_FAILURE

    if new_descriptor is not None:
        charge_descriptor_write(new_descriptor)
        state[tx.sender].code = new_descriptor

    return FRAME_SUCCESS
```

If descriptor-write charging fails, the complete `CONFIGURE` frame fails and reverts to the frame-entry checkpoint, including any verification-owned state mutations performed before `APPROVE_CONFIGURE`.

The complete configuration frame is committed by the canonical transaction signature whenever the selected authority uses an EIP-8141 signature with empty `msg`. A verification implementation using another authorization message MUST bind approval to all configuration data it considers security-critical, including the exact descriptor when present, account, chain or replay domain, and update nonce or sequence.

A descriptor update and authority-state update MAY occur in the same `VERIFY_IMPLEMENTATION` configuration frame. A failed later frame in the same atomic batch reverts both.

An `INLINE_ROOT -> VERIFY_IMPLEMENTATION` transition does not itself execute the newly selected verification implementation. If the destination implementation requires mutable authority state, that state must already be initialized or a companion profile must define a bootstrap procedure authorized by the inline root.

### Ordinary execution

For `DEFAULT` and `SENDER` frames targeting a structured account, code is loaded from `execution_implementation` and executed in the structured account context.

During execution:

- `ADDRESS` and storage belong to the structured account;
- `CODESIZE` and `CODECOPY` observe execution implementation code; and
- `EXTCODE*` of the structured account observes the descriptor.

The execution implementation is intentionally independent from the authority implementation. Changing ordinary wallet logic does not require changing the validation representation, and a chain's verification-code policy does not restrict the execution implementation.

### Code installation and replacement

EIP-3541 is modified to permit creation-time installation of code beginning with `0xef02` only when the complete code is a valid structured descriptor under an active authority type.

EIP-7702 authorization processing MUST NOT overwrite structured code.

EIP-8298 `SETCODEFROM` MUST fail when the current execution-context account is structured, and a structured descriptor MUST NOT be a valid EIP-8298 source. Otherwise ordinary execution code could replace the authority descriptor outside `CONFIGURE`.

Any future account-code replacement mechanism MUST explicitly specify whether it may replace structured code. The default is that it may not.

Structured accounts have nonempty non-delegation code. Legacy ECDSA transaction origination remains invalid under EIP-3607, while EIP-8141 frame origination is permitted.

### Gas accounting

Inline-root authorization charges:

```text
STRUCTURED_VERIFY_BASE_GAS
+ resolved-target account access
+ referenced signature validation cost
```

Verification-implementation authorization uses the frame's ordinary EIP-8141 execution-gas budget. Resolving `verification_implementation` charges the applicable warm or cold account/code access cost analogously to EIP-7702 code resolution. Calls and storage reads made by verification code are charged through normal EVM rules.

`CONFIGURE` runs non-statically for `VERIFY_IMPLEMENTATION` and may consume both execution and state gas. All calls, storage writes, account creation, logs, and external effects are charged normally. `CONFIGURE_BASE_GAS` additionally covers configuration dispatch and optional descriptor replacement bookkeeping.

`APPROVE_CONFIGURE` has the same memory-expansion and return-data cost behavior as existing `APPROVE`. It has no additional execution-gas base cost.

A direct evaluator MUST reproduce equivalent EVM gas, warmness, returndata, state effects, failure behavior, and approval effects. Direct evaluation is an optimization, not a repricing.

### Public mempool

An `INLINE_ROOT` `VERIFY` frame is directly evaluable from the account descriptor and referenced authenticated signature result.

A `VERIFY_IMPLEMENTATION` frame is consensus-valid by executing its selected code under EIP-8141 `VERIFY` semantics. Generic EIP-8141 public-mempool tracing rules apply unless a network recognizes an implementation-specific profile.

A chain MAY admit only verification implementations whose current runtime code hash belongs to a configured set. Such a policy applies to verification code, not arbitrary wallet execution code.

A code hash identifies the initial verification bytecode. A no-tracing profile additionally SHOULD specify any constraints required by that bytecode, including permitted external authority calls, bounded state dependencies, environmental dependencies, gas bounds, calldata parsing, and revalidation conditions. These are properties of the selected implementation profile, not fields of the structured account envelope.

A profile MAY provide an equivalent direct evaluator. The current runtime code hash at `verification_implementation` is always a validation dependency; pending transactions MUST be revalidated when it changes.

A verification implementation that calls an external keystore may be block-valid while failing the generic EIP-8141 public-mempool rule against external mutable storage. A companion profile or public-mempool EIP may admit the exact bounded external dependencies of a canonical actor-authority implementation.

`CONFIGURE` requires `payer != None`; it is therefore outside the public-mempool validation prefix. Its non-static authority-state mutation does not expand public-mempool admission work. Builders and block validators still execute it under ordinary consensus rules.

## Out of Scope

This proposal intentionally does not define:

- one mandatory keystore address or storage layout;
- actor scopes, expiry packing, recovery, guardians, or session policy;
- how a verification implementation stores or synchronizes authority state;
- keyed or two-dimensional nonces;
- nonce-free authorization;
- signature aggregation algorithms;
- public-key aliasing;
- post-execution assertions or revert protection;
- cross-chain authority synchronization; or
- universal revocation of legacy `ECRECOVER`-based message authority.

These features can be standardized independently without changing the structured account envelope.

## Remaining Design Questions

### Canonical actor-authority profile

A shared production path for multi-actor accounts still requires agreement on at least one canonical verification implementation or profile. That profile may choose a shared keystore, deterministic per-account authority address, account-local storage, or another representation.

For L1/L2 public-mempool interoperability it must also specify the bounded state dependencies and code hashes a client recognizes.

### Verification implementation code identity

The descriptor stores an address rather than an expected runtime code hash. An implementation change at the same address changes authority semantics without changing the account descriptor. Immutable deployments are recommended; a later authority type may pin a code hash.

### Bootstrap into stateful verification

`VERIFY_IMPLEMENTATION` can update its own authority data once it is active. A direct transition from `INLINE_ROOT` or an unstructured account to a verification implementation with uninitialized account-local authority data can lock the account. A companion profile may define pre-initialized external authority, deterministic initialization, or a root-authorized bootstrap call to the destination verification implementation.

### Existing non-frame accounts

`CONFIGURE` can migrate code-less accounts and smart accounts that already support EIP-8141 validation. ERC-4337-only accounts that cannot approve a frame transaction still need an implementation-specific upgrade or migration path.

### Pre-validation authority changes

Configuration occurs after payment and is authorized by existing authority. Atomic rotation and action are possible under the old authority, but first-use by a newly installed actor in the same transaction requires a separate construction.

### Validation gas budget

Pure authentication, sender authorization, and payer authorization must fit the active EIP-8141 public-mempool validation budget. Expensive post-quantum verification or two custom authenticators may require separate authentication and authorization budgets or a larger cap.

## Rationale

### Why verification executes in account context

EIP-8141 `APPROVE` requires `ADDRESS == resolved_target`. Calling an external verifier or keystore directly cannot approve for the account. Selecting verification code while retaining the account context lets the narrow validation path invoke `APPROVE` without re-entering the ordinary wallet implementation.

### Why this is not ordinary `DELEGATECALL`

An actual `DELEGATECALL` would require account bytecode to initiate it, returning validation to the arbitrary wallet implementation problem. Protocol code selection uses delegated execution semantics without an initiating wrapper or extra call frame.

### Why the verification implementation owns storage design

Code-path separation and state-layout standardization are different questions. Some accounts need no mutable authority state; some prefer account-local slots; some need per-account stores; others need a shared cross-chain keystore.

The core EIP only needs a recognizable verification code source. The selected implementation and any public-mempool profile can define the storage model appropriate to that account class.

### Why actor identity is separate from authenticator identity

An authenticator address identifies a verification algorithm, not the particular key authorized by an account. Every user may share the same stateless P-256 authenticator. The authenticator therefore derives:

```text
key_id = keccak256(qx || qy)
```

and authorization binds the exact `(authenticator, key_id)` pair. `INLINE_ROOT` stores the pair directly; a richer verification implementation may look it up in an actor mapping.

### Why verifier code may be allowlisted

Verification implementations are expected to be fewer and smaller than wallet execution implementations. A chain can recognize a canonical validation code hash while leaving execution code unrestricted.

Allowlisting is public-mempool policy, not account authorization. The verification implementation still decides which authenticated actor may approve the transaction.

### Why the protocol does not know an ABI

Core protocol forwards `frame.data` unchanged. ABI knowledge belongs to the selected verification implementation and optional profile. This allows the same bytecode path to run on a general EVM chain while selected clients implement equivalent native evaluation.

### Why inline root remains useful

A simple account should not pay an external call and storage lookup merely to represent one ultimate key. `INLINE_ROOT` is the one-entry specialization of the same `(verifier, key_id) -> authority` model used by richer implementations.

### Why configuration uses `APPROVE`

`CONFIGURE_SUCCESS` would create a second signaling convention alongside EIP-8141 `APPROVE`. `APPROVE_CONFIGURE` keeps every account-context authorization result on one protocol channel.

The action is mode-specific rather than an execution/payment frame flag. This prevents a session actor's ability to approve execution from automatically implying descriptor or authority-state administration.

### Why configuration is non-static

Descriptor replacement alone needs only a protocol code update, but verification-owned data may live in account storage or an external keystore. Supporting actor addition, revocation, root rotation, and recovery updates therefore requires state changes.

A `CONFIGURE` frame runs only after payment has been established. Its state changes remain provisional until current authority reaches `APPROVE_CONFIGURE`, and they are rolled back otherwise.

### Why zero descriptor length means state-only configuration

The descriptor is optional because many authority updates do not change code identity. Requiring a redundant descriptor rewrite for every session-key or expiry update would add data and state churn.

A nonzero length supports descriptor-only and combined descriptor-plus-state migration in the same frame.

### Why signatures remain in the EIP-8141 list

The signature list provides one location for protocol validation, witness elision, future aggregation, and signatures consumed during ordinary execution. Structured authority changes how authenticated results are authorized; it does not create a second signature container.

### Validation after execution

Account authority must be established before a `SENDER` frame. Post-execution assertions, zero-slippage protection, and similar revert-protection schemes are orthogonal and may be evaluated later where EIP-8141 ordering and public-mempool policy permit.

## Backwards Compatibility

This proposal requires a network upgrade because it assigns special semantics to `0xef02`, extends EIP-8141 signature introspection and `APPROVE`, and adds a frame mode.

EIP-3541 prevents newly deployed ordinary code beginning with `0xef`, so existing deployable EVM contracts are not reinterpreted as structured accounts.

Pre-upgrade clients reject structured descriptors and do not understand the new signature attributes, `CONFIGURE` mode, or `APPROVE_CONFIGURE` action.

## Test Cases

Implementations MUST cover at least the following cases.

### Authentication result

1. A secp256k1 signature exposes `verifier = address(0x01)` and the recovered address as `key_id`.
2. A P-256 signature exposes `verifier = address(0x100)` and `keccak256(qx || qy)` as `key_id`.
3. EIP-8397 exposes the authenticator address and returned key identifier.
4. `SIGPARAM_KEY_ID` and `SIGPARAM_VERIFIER` halt for `ARBITRARY`.
5. Raw P-256 witness bytes remain unavailable through `SIGDATACOPY`.

### Descriptor parsing

1. Accept valid 75-byte `INLINE_ROOT` and 43-byte `VERIFY_IMPLEMENTATION` descriptors.
2. Reject zero implementation, verifier, key ID, or verification implementation.
3. Reject malformed lengths and unknown authority types.
4. Confirm `execution_implementation` always occupies bytes `3..22`.

### Inline root

1. Accept a matching `(verifier, key_id)` and requested approval scope.
2. Reject the same key ID under another verifier.
3. Accept a stateless multisig authenticator whose returned key ID commits to a canonical threshold configuration.
4. Reject `ARBITRARY` as an inline-root credential.

### Verification context

1. Confirm `VERIFY` loads verification code rather than execution code.
2. Confirm `ADDRESS`, storage, and balance belong to the structured account.
3. Confirm calldata equals `frame.data` byte-for-byte.
4. Confirm `CODESIZE` sees verification code and `EXTCODESIZE(ADDRESS)` sees the 43-byte descriptor.
5. Confirm a direct `SLOAD` reads structured-account storage, not storage at the verification implementation address.
6. Confirm a nested call to the same structured account remains on the verification path.
7. Confirm an external authority contract cannot invoke execution/payment `APPROVE` for the account.
8. Confirm verification code can validate the external result and invoke `APPROVE` itself.
9. Confirm ordinary `SENDER` execution uses `execution_implementation` rather than verification code.

### `APPROVE_CONFIGURE`

1. Accept `APPROVE_CONFIGURE` only in `CONFIGURE` mode with `ADDRESS == resolved_target == tx.sender` and an established payer.
2. Reject it in `VERIFY`, `DEFAULT`, and `SENDER` modes.
3. Reject execution/payment approval operands in `CONFIGURE` mode.
4. Confirm it does not alter `sender_approved`, payer, nonce, or maximum-cost collection.
5. Confirm the opcode terminates the top-level configuration call frame successfully.
6. Reject `APPROVE_CONFIGURE` from a nested `CALL`, `DELEGATECALL`, or `CALLCODE` frame.
7. Confirm a normal return without `APPROVE_CONFIGURE` rolls back all configuration state changes.
8. Confirm `APPROVE_CONFIGURE` can be used in an atomic batch and is rolled back if the batch later fails.

### Authority-state configuration

1. Use `new_descriptor_length == 0` to add an actor in structured-account storage and keep the descriptor unchanged.
2. Use the same form to update a deterministic per-account authority contract.
3. Use the same form to update a shared keystore entry.
4. Perform writes and then return without approval; confirm every write is rolled back.
5. Perform external state changes and then revert; confirm all effects are rolled back.
6. Reject state-only configuration for `INLINE_ROOT` and unstructured accounts.

### Descriptor configuration

1. Install structured authority from a code-less account after default-account approval and payment.
2. Install it from an unstructured frame-aware smart account after its existing validation approves the transaction.
3. Rotate an inline root with a canonical-hash signature from the current root.
4. Switch from inline root to verification implementation.
5. Replace the execution implementation through the current verification implementation.
6. Replace the verification implementation after current-authority approval.
7. Mutate current authority state and replace the descriptor in one frame; confirm both commit together.
8. Fail before `APPROVE_CONFIGURE`; confirm both state and descriptor remain unchanged.
9. Roll back state and descriptor with a failed atomic batch.
10. Keep a successful non-atomic configuration when a later independent frame fails.

### Public mempool

1. Validate an unrecognized verification implementation under generic EIP-8141 rules.
2. Admit a recognized runtime code hash under chain-specific policy.
3. Change verification code and revalidate pending transactions.
4. Directly evaluate a recognized profile and reproduce EVM gas, returndata, failure, dependency, and approval behavior.
5. Reject undeclared external mutable-state dependencies under the applicable public-mempool profile.

### Code replacement

1. Confirm EIP-7702 authorization cannot overwrite structured code.
2. Confirm EIP-8298 cannot replace a structured descriptor.
3. Confirm a structured descriptor cannot be used as an EIP-8298 source.

## Security Considerations

### Verification implementation is authority code

A verification implementation decides whether execution/payment approval or configuration succeeds. A bug that ignores the transaction hash, misparses a key ID, trusts an unauthenticated external result, or grants excessive authority compromises every account using it.

### Non-static configuration

`CONFIGURE` permits current verification code to write account state and call state-changing external contracts before invoking `APPROVE_CONFIGURE`. These effects commit when configuration is approved.

This does not grant more authority than an approved account execution, but it makes the verification implementation's configuration path security-critical. Implementations SHOULD minimize configuration call targets and MUST ensure only the intended current root, administrator, recovery path, or threshold can reach `APPROVE_CONFIGURE`.

### Authority storage is implementation-defined

If verification reads authority from structured-account storage, ordinary execution code may be able to modify that state. If this is not intended, the verification implementation must use a protected external authority contract, immutable descriptor data, cryptographic commitments, or another design that prevents unauthorized execution-layer mutation.

### Verification implementation code changes

The descriptor names an address rather than a code hash. Code changes at that address alter authorization semantics. Nodes must revalidate pending transactions, and wallets should prefer immutable verification deployments or treat their upgrade authority as account root authority.

### Transitive code execution

Code reached through `DELEGATECALL` or `CALLCODE` runs with the structured account address and can mutate configuration state or influence the final authorization result. It cannot directly complete configuration because `APPROVE_CONFIGURE` is restricted to the top-level configuration call frame, but it remains part of the authority implementation's trust boundary. A chain recognizing only the top-level code hash must ensure that the selected implementation's transitive behavior satisfies its admission and security policy.

### External authority contracts

An external keystore or authority service cannot approve directly, but a malicious or upgradeable service can return forged authorization to an adapter that trusts it. Its code, state, and upgrade authority are part of the account's security boundary.

### Opaque calldata

Core protocol does not parse `configuration_data` or ordinary `VERIFY_IMPLEMENTATION` frame data. Wallets and explorers need a parser associated with the selected implementation or profile. Unknown verification code must not be decoded under another implementation's ABI.

### Configuration authorization binding

A verification implementation must invoke `APPROVE_CONFIGURE` only after authorization is bound to every security-critical field. For descriptor updates this includes the exact new descriptor. For authority-state updates it includes the exact mutation payload. Account, chain or replay domain, and update nonce or sequence must be included where required by the authority model.

### Configuration ordering

A successful non-atomic configuration remains applied if a later independent frame fails. Wallets requiring configuration and subsequent execution to be all-or-nothing MUST place them in the same atomic batch.

### Bootstrap lockout

Installing a stateful verification implementation without initialized authority state may permanently lock the account. Wallets must initialize the destination authority first or use a standardized bootstrap profile.

### Legacy signatures

Installing structured authority disables legacy transaction origination but does not revoke message signatures recognized by third-party contracts. Descriptor rotation must not be represented as universal retirement of an old ECDSA identity.

### Client consistency

Clients must agree on descriptor parsing, authentication-result derivation, mode-sensitive code selection, account-context execution, `APPROVE_CONFIGURE` behavior, provisional configuration state, descriptor replacement, gas accounting, and rollback semantics. Divergence is consensus-critical.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
