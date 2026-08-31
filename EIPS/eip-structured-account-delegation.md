---
title: Structured Account Authority
description: Separate account execution from typed account-context verification.
author: Taek (@leekt)
discussions-to: TBD
status: Draft
type: Standards Track
category: Core
created: 2026-08-28
requires: 170, 2929, 3541, 3607, 7702, 7951, 8141, 8298
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

`VERIFY_IMPLEMENTATION` loads code from `verification_implementation` while retaining the structured account as the EVM execution context. The selected code receives frame calldata unchanged, chooses where and how authority state is represented, and invokes [EIP-8141](./eip-8141.md) `APPROVE` from the account context. Ordinary calls execute the independent `execution_implementation`.

A new `CONFIGURE` frame mode and mode-specific `APPROVE_CONFIGURE` action support both:

1. replacing the structured descriptor; and
2. mutating authority state consumed by the current verification implementation.

`CONFIGURE` may execute before transaction payment is approved. This permits an existing administrator to install a new actor and a later `VERIFY` frame in the same transaction to authorize execution or payment with that new actor.

This combines [EIP-8141](./eip-8141.md)'s frame transaction, payment, execution, and signature container with [EIP-8130](./eip-8130.md)'s `authenticator -> actor identity -> authorization` model. It does not define a second transaction envelope, a second signature namespace, or a mandatory keystore layout.

## Motivation

[EIP-8141](./eip-8141.md) permits arbitrary account code to validate frame transactions. This preserves programmability, but couples authorization to the complete wallet implementation. A sequencer seeking a statically understandable path must either recognize every wallet implementation or execute and trace arbitrary wallet code.

[EIP-8130](./eip-8130.md) separates three responsibilities:

```text
authenticator  -> proves a credential and returns an actor identity
authority      -> determines what that actor may authorize
account code   -> performs ordinary execution
```

The useful parts of both designs can be combined into one native account model:

1. [EIP-8141](./eip-8141.md) remains the single transaction, frame, payment, and signature format.
2. Protocol or pure authentication produces a normalized `(verifier, key_id)` result.
3. A structured account selects a narrow authorization path independently from ordinary wallet execution.
4. The authorization path invokes `APPROVE`, after which ordinary frame execution continues.

The common single-root case requires no state lookup beyond the account descriptor. Richer accounts may select a dedicated verification implementation that uses account storage, a deterministic per-account authority contract, a shared keystore, immutable code data, a committed root, or another authority representation.

The core protocol deliberately does not select among those storage models. The selected verification implementation owns its ABI, state layout, actor mapping, scope model, expiry model, and update mechanism. A chain may recognize selected verification implementation code hashes for public-mempool admission or equivalent direct evaluation without constraining the account's ordinary execution implementation.

Configuration also needs the same separation. Changing the descriptor and changing verification-owned data are distinct operations:

- changing the descriptor replaces the execution implementation, authority type, or verification implementation pointer;
- changing verification-owned data adds or revokes actors, rotates a stateful root, changes a threshold, updates expiry, or modifies another authority parameter without changing the descriptor.

Both operations are authorized by the current authority path and use the same `CONFIGURE` frame and `APPROVE_CONFIGURE` action.

A blanket requirement that payment be approved before configuration prevents a useful construction:

```text
old administrator signature
  -> CONFIGURE installs new actor
new actor signature
  -> VERIFY approves execution and payment
```

All protocol-validated signatures are authenticated before frame execution, so the new actor's cryptographic proof can be checked before the actor becomes authorized. Frame ordering then determines when the new authority state becomes visible. This proposal therefore permits pre-payment configuration while bounding it through the validation-prefix and public-mempool rules below.

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

`verifier` identifies the native or pure authentication program. `ECRECOVER_VERIFIER` is the `ecrecover` precompile address; `P256_VERIFIER` is the [EIP-7951](./eip-7951.md) `secp256r1` verification precompile address. `key_id` identifies the exact credential or canonical credential configuration proven by the witness.

The initial normalization rules are:

| Signature scheme | `verifier` | `key_id` |
|---|---|---|
| [EIP-8141](./eip-8141.md) `SECP256K1` | `ECRECOVER_VERIFIER` | recovered address right-aligned in 32 bytes |
| [EIP-8141](./eip-8141.md) `P256` | `P256_VERIFIER` | `keccak256(qx || qy)` |

A future EIP defining an additional protocol-validated signature scheme MAY extend this table by specifying how the scheme derives its `AuthenticationResult` from the verified witness.

For P-256, the full public key remains part of the opaque protocol-validated signature entry. Computing its identifier does not expose the raw witness to EVM code.

An `ARBITRARY` signature entry does not produce an authenticated result. It may still be consumed through [EIP-8141](./eip-8141.md) `SIGDATACOPY`, but it cannot directly authorize `INLINE_ROOT`.

A future scheme proving a threshold, multisig, or other compound stateless credential SHOULD use:

```text
key_id = keccak256(canonical credential configuration)
```

provided the scheme derives the value from the verified witness rather than trusting a transaction-supplied claim.

### Signature entry attributes

[EIP-8141](./eip-8141.md) validated signature entries are extended with immutable `verifier` and `key_id` attributes.

The [EIP-8141](./eip-8141.md) `SIGPARAM` table is extended with:

| `param` | Return value |
|---|---|
| `0x04` | authenticated `key_id` |
| `0x05` | authenticated `verifier` |

These values are defined only for signatures that produce an `AuthenticationResult`. Requesting either value for `ARBITRARY` results in an exceptional halt.

Existing [EIP-8141](./eip-8141.md) `resolved_signer` behavior is unchanged for backward compatibility.

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

Structured account code is recognized before [EIP-7702](./eip-7702.md) delegation handling.

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

This is protocol code selection analogous to [EIP-7702](./eip-7702.md) delegated-code dispatch. It is not execution of the `DELEGATECALL` opcode and does not create an additional EVM call frame.

The code bytes are loaded directly from the selected implementation address without recursively resolving an [EIP-7702](./eip-7702.md) indicator or another structured descriptor at that address.

While the current frame mode is `VERIFY` or `CONFIGURE`, a nested code-executing operation targeting that frame's `resolved_target` MUST select the same verification implementation rather than the execution implementation. This prevents a self-call from switching the authority path into arbitrary wallet execution code.

Outside that case, any code-executing operation targeting a structured account -- including a call from an unrelated contract, from another account's frame, or during ordinary execution -- loads code from `execution_implementation`. The structured descriptor itself is never executed as bytecode.

### Account-context verification

A `VERIFY` frame targeting a `VERIFY_IMPLEMENTATION` account executes with:

| Property | Value |
|---|---|
| code source | runtime code at `verification_implementation` |
| `ADDRESS` | structured account (`resolved_target`) |
| persistent storage | structured account storage |
| transient storage | structured account transient storage |
| top-level `CALLER` | [EIP-8141](./eip-8141.md) `ENTRY_POINT` |
| `ORIGIN` | [EIP-8141](./eip-8141.md) frame caller |
| `CALLVALUE` | `0` |
| calldata | `frame.data`, unchanged |
| static mode | enabled |
| gas pools | frame-declared [EIP-8141](./eip-8141.md) limits |
| `CODESIZE`, `CODECOPY` | verification implementation code |
| `EXTCODE*` of `ADDRESS` | structured descriptor code |
| `SELFBALANCE` | structured account balance |

Because `ADDRESS == resolved_target`, verification code may invoke [EIP-8141](./eip-8141.md) `APPROVE`.

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

The frame remains subject to [EIP-8141](./eip-8141.md) `VERIFY` semantics. Revert, exceptional halt, or failure to invoke the required approval makes the frame transaction invalid. The approved execution/payment scope MUST be permitted by `frame.flags`.

A minimal [EIP-8130](./eip-8130.md)-style adapter can perform:

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
6. The frame requests a nonzero [EIP-8141](./eip-8141.md) approval scope.
7. Every ordinary [EIP-8141](./eip-8141.md) structural rule for that scope holds.

On success, protocol applies the same effects as:

```text
APPROVE(frame.flags & APPROVE_SCOPE_MASK)
```

No verification or execution implementation bytecode runs.

### `APPROVE_CONFIGURE`

This proposal extends the [EIP-8141](./eip-8141.md) `APPROVE` instruction with the mode-specific operand `APPROVE_CONFIGURE`.

Existing `APPROVE_PAYMENT`, `APPROVE_EXECUTION`, and `APPROVE_EXECUTION_AND_PAYMENT` behavior is unchanged in `VERIFY` mode. `APPROVE_CONFIGURE` is invalid in `VERIFY`, `DEFAULT`, and `SENDER` modes.

When `APPROVE` is executed with `scope == APPROVE_CONFIGURE` in a `CONFIGURE` frame:

1. If `ADDRESS != resolved_target`, revert the current call frame.
2. If `resolved_target != tx.sender`, revert the current call frame.
3. If `frame.flags & APPROVE_SCOPE_MASK != 0`, revert the current call frame.
4. If the opcode is not executed in the top-level EVM call frame created for the `CONFIGURE` frame, revert the current call frame.
5. If the current `CONFIGURE` frame has already been approved, revert the current call frame.
6. Mark the current configuration as approved.
7. Terminate the top-level configuration call frame successfully, using the `offset` and `length` operands as return data exactly as existing `APPROVE` does.

`APPROVE_CONFIGURE` does not require `payer` to be set. It does not set `sender_approved`, does not select or change `payer`, does not increment a nonce, and does not collect maximum cost.

If `payer == None` when the `CONFIGURE` frame begins, the configuration is a **pre-payment configuration** and belongs to the transaction's validation prefix. Its effects remain part of the transaction journal and are visible to later frames. They commit only if a later frame successfully establishes a payer and the transaction remains valid.

If no payer is established by transaction end, or a later `VERIFY` frame makes the transaction invalid, all pre-payment configuration effects are reverted with the transaction.

`APPROVE_CONFIGURE` is permitted in a `CONFIGURE` frame carrying `ATOMIC_BATCH_FLAG` only when `payer` was already set at frame entry. Existing execution/payment approvals remain unavailable inside an atomic batch.

### `CONFIGURE` frame

[EIP-8141](./eip-8141.md)'s frame mode table is extended with:

| `mode` | Name | Summary |
|---|---|---|
| `0x03` | `CONFIGURE` | mutate verification-owned authority state and optionally install or replace a structured descriptor |

The static frame constraint becomes:

```python
assert frame.mode < 4
```

A `CONFIGURE` frame targets `tx.sender` and carries no value or execution/payment approval scope. It may execute before or after payer approval.

Its data is:

```text
new_descriptor_length   (2 bytes, uint16 big-endian)
new_descriptor          (new_descriptor_length bytes; omitted when length is zero)
configuration_data      (remaining bytes, authority-implementation-defined)
```

`new_descriptor_length == NO_DESCRIPTOR_CHANGE` means the descriptor remains unchanged. A nonzero length requests descriptor installation or replacement and MUST identify one complete valid structured descriptor.

The frame is structurally valid only when:

1. `resolved_target == tx.sender`.
2. `frame.flags & APPROVE_SCOPE_MASK == 0`.
3. no undefined flag bit is set.
4. `frame.value == 0`.
5. a nonzero `new_descriptor_length` fits within `frame.data` and the selected bytes parse under an active authority type.
6. at most one `CONFIGURE` frame appears in the transaction.
7. no `SENDER` frame precedes it.
8. if `payer == None` at frame entry, `ATOMIC_BATCH_FLAG` is not set.

At frame entry, clients create a state checkpoint covering all account, storage, call, log, and descriptor effects of the frame.

A `CONFIGURE` frame succeeds only through `APPROVE_CONFIGURE` or one of the direct protocol paths defined below. Returning or stopping normally without approval is a configuration failure and rolls back to the frame-entry checkpoint.

- If the frame began before payer approval, any configuration failure, revert, or exceptional halt makes the frame transaction invalid.
- If the frame began after payer approval, configuration failure produces a failed paid frame and the transaction may continue under ordinary frame semantics.

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
| gas pools | frame-declared [EIP-8141](./eip-8141.md) limits |

The implementation authenticates the current root, administrator, recovery path, multisig, or other authority according to its own rules; mutates its chosen authority state; and finally invokes `APPROVE(APPROVE_CONFIGURE)`.

The mutable state may be:

- structured-account storage;
- storage at a deterministic per-account authority contract;
- a shared keystore mapping;
- another external authority service; or
- any other state selected by the verification implementation.

This form can add or revoke an actor, rotate a stateful root, change expiry, update a threshold, or modify recovery configuration without changing the descriptor.

All writes and external calls occur before `APPROVE_CONFIGURE`. Because `APPROVE_CONFIGURE` terminates the top-level configuration call frame, no configuration write can occur after approval. If approval is never reached, all provisional effects are rolled back.

#### Configuration class 2: descriptor update

When `new_descriptor_length > 0`, the indicated descriptor is installed or replaces the current descriptor after authorization.

If the current account is `VERIFY_IMPLEMENTATION`, the current verification implementation executes in the same non-static configuration context. It MAY also mutate verification-owned state before calling `APPROVE_CONFIGURE`. On approval, both the state mutations and descriptor replacement remain in the transaction journal. This permits one frame to migrate authority data and switch verification implementations atomically at the frame level.

If the current account is `INLINE_ROOT`, `configuration_data` MUST contain exactly one unsigned 32-bit big-endian signature index referencing an existing entry in `tx.signatures`. An out-of-bounds index or an entry that does not produce an `AuthenticationResult` is a configuration failure. The referenced canonical-hash signature MUST produce an `AuthenticationResult` matching the current inline root. The protocol applies effects equivalent to successful `APPROVE_CONFIGURE` and installs the new descriptor. No implementation-defined authority-state mutation occurs on this direct path.

If `tx.sender` is not yet structured:

- `sender_approved` MUST already be true;
- `configuration_data` MUST be empty; and
- the prior [EIP-8141](./eip-8141.md) validation path authorizes installation.

The protocol applies effects equivalent to successful `APPROVE_CONFIGURE` and installs the descriptor. An account that cannot yet approve an [EIP-8141](./eip-8141.md) frame transaction requires an account-specific migration path outside this proposal.

#### Applying configuration

The current descriptor always determines which authority authorizes configuration. The proposed descriptor is never used before installation.

```python
def execute_structured_configure(frame, current_descriptor, tx, state):
    assert resolved_target(frame) == tx.sender
    assert frame.flags & APPROVE_SCOPE_MASK == 0
    assert frame.value == 0

    prepayment = payer is None
    if prepayment:
        assert not (frame.flags & ATOMIC_BATCH_FLAG)

    charge_execution_gas(frame, CONFIGURE_BASE_GAS)

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
        sig_index = int.from_bytes(configuration_data, "big")
        assert sig_index < len(tx.signatures)
        sig = tx.signatures[sig_index]
        assert len(sig.msg) == 0
        assert produces_authentication_result(sig)
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
        if prepayment:
            invalid_transaction()
        return FRAME_FAILURE

    if new_descriptor is not None:
        charge_descriptor_write(new_descriptor)
        state[tx.sender].code = new_descriptor

    return FRAME_SUCCESS
```

If descriptor-write charging fails, the complete frame rolls back to its entry checkpoint. When this occurs before payer approval, the transaction is invalid; when it occurs after payer approval, the paid configuration frame fails.

The complete configuration frame is committed by the canonical transaction signature whenever the selected authority uses an [EIP-8141](./eip-8141.md) signature with empty `msg`. A verification implementation using another authorization message MUST bind approval to all configuration data it considers security-critical, including the exact descriptor when present, account, chain or replay domain, and update nonce or sequence.

A descriptor update and authority-state update MAY occur in the same `VERIFY_IMPLEMENTATION` configuration frame.

An `INLINE_ROOT -> VERIFY_IMPLEMENTATION` transition does not itself execute the newly selected verification implementation. If the destination implementation requires mutable authority state, that state must already be initialized or a companion profile must define a bootstrap procedure authorized by the inline root.

### Install and first use in one transaction

A pre-payment `CONFIGURE` frame may install an actor that authorizes a later `VERIFY` frame in the same transaction.

```text
signatures[0] = current administrator signs canonical transaction hash
signatures[1] = new actor signs canonical transaction hash

frame 0: CONFIGURE
    current verification implementation authenticates signatures[0]
    installs authorization for signatures[1].(verifier, key_id)
    APPROVE_CONFIGURE

frame 1: VERIFY
    current verification implementation reads signatures[1]
    observes the actor installed by frame 0
    APPROVE_EXECUTION_AND_PAYMENT

frame 2: SENDER
    ordinary execution
```

[EIP-8141](./eip-8141.md) authenticates both protocol-validated signatures before frame execution. This does not authorize the new actor early; it only establishes the actor identity. The ordered `CONFIGURE` frame creates authorization before the later `VERIFY` consumes it.

If frame 0 fails, frame 1 fails, no payer is established, or another validation failure makes the transaction invalid, the actor installation is reverted.

### Ordinary execution

For `DEFAULT` and `SENDER` frames targeting a structured account, code is loaded from `execution_implementation` and executed in the structured account context.

During execution:

- `ADDRESS` and storage belong to the structured account;
- `CODESIZE` and `CODECOPY` observe execution implementation code; and
- `EXTCODE*` of the structured account observes the descriptor.

The execution implementation is intentionally independent from the authority implementation. Changing ordinary wallet logic does not require changing the validation representation, and a chain's verification-code policy does not restrict the execution implementation.

### Code installation and replacement

[EIP-3541](./eip-3541.md) is modified to permit creation-time installation of code beginning with `0xef02` only when the complete code is a valid structured descriptor under an active authority type. A structured descriptor is account code for every other purpose, including the [EIP-170](./eip-170.md) size limit, which it trivially satisfies.

[EIP-7702](./eip-7702.md) authorization processing MUST NOT overwrite structured code.

Descriptor installation through `CONFIGURE` MAY replace empty code, an [EIP-7702](./eip-7702.md) delegation indicator, or existing contract code. In every case the replacement is authorized by the account's current authority: the current structured descriptor's authority path, or, for a not-yet-structured account, the [EIP-8141](./eip-8141.md) validation path that set `sender_approved`. The prior code, including a delegation indicator, is permanently discarded and is not recoverable from the descriptor.

[EIP-8298](./eip-8298.md) `SETCODEFROM` MUST fail when the current execution-context account is structured, and a structured descriptor MUST NOT be a valid [EIP-8298](./eip-8298.md) source. Otherwise ordinary execution code could replace the authority descriptor outside `CONFIGURE`.

Any future account-code replacement mechanism MUST explicitly specify whether it may replace structured code. The default is that it may not.

Structured accounts have nonempty non-delegation code. Legacy ECDSA transaction origination remains invalid under [EIP-3607](./eip-3607.md), while [EIP-8141](./eip-8141.md) frame origination is permitted.

### Gas accounting

Inline-root authorization charges:

```text
STRUCTURED_VERIFY_BASE_GAS
+ resolved-target account access
+ referenced signature validation cost
```

Verification-implementation authorization uses the frame's ordinary [EIP-8141](./eip-8141.md) execution-gas budget. Resolving `verification_implementation` charges the applicable [EIP-2929](./eip-2929.md) warm or cold account/code access cost analogously to [EIP-7702](./eip-7702.md) code resolution. Calls and storage reads made by verification code are charged through normal EVM rules.

`CONFIGURE` runs non-statically for `VERIFY_IMPLEMENTATION` and may consume both execution and state gas. All calls, storage writes, account creation, logs, and external effects are charged normally. `CONFIGURE_BASE_GAS` additionally covers configuration dispatch and optional descriptor replacement bookkeeping. It is charged from the frame's `limits.execution` at frame entry, after the resolved-target account-access charge and before any verification-implementation code executes. A frame that cannot cover it fails exceptionally; before payer approval this makes the transaction invalid.

`charge_descriptor_write` charges descriptor installation or replacement as state growth: `max(0, len(new_descriptor) - len(current_code)) * CPSB` is deducted from the frame's `state_gas_left` immediately before the code write, using the same per-state-byte accounting as [EIP-8141](./eip-8141.md)'s account-creation charge. A shrinking or equal-size replacement charges no growth. The dispatch cost of the write is covered by `CONFIGURE_BASE_GAS`; there is no separate per-byte execution-gas charge.

When configuration precedes payer approval, its consumed gas and state gas are still included in the transaction's total usage and maximum cost. The later payer approval therefore escrows and ultimately pays for work already performed earlier in the frame sequence. If no payer is established, the transaction is invalid and cannot be included.

`APPROVE_CONFIGURE` has the same memory-expansion and return-data cost behavior as existing `APPROVE`. It has no additional execution-gas base cost.

A direct evaluator MUST reproduce equivalent EVM gas, warmness, returndata, state effects, failure behavior, and approval effects. Direct evaluation is an optimization, not a repricing.

### Public mempool

#### Validation-prefix inclusion

A `CONFIGURE` frame occurring while `payer == None` is part of the [EIP-8141](./eip-8141.md) validation prefix. Its execution and state-gas limits count toward the active `MAX_VERIFY_GAS` and `MAX_VERIFY_STATE_GAS` bounds.

Public-mempool implementations MAY recognize forms equivalent to:

```text
[pre_configure, self_verify]
[pre_configure, only_verify, pay]
```

as well as the existing optional expiry/deploy variants, provided the applicable profile defines their exact ordering and dependencies.

A pre-payment configuration is evaluated on a temporary state overlay. Every later validation frame observes that overlay. The overlay is discarded if the transaction is rejected, replaced, evicted, becomes invalid, or fails to establish a payer.

#### Inline-root pre-configuration

An inline-root descriptor replacement is directly evaluable. Its dependencies are the current descriptor, the referenced current-root signature result, the proposed descriptor, and the later validation-prefix dependencies.

#### Verification-implementation pre-configuration

A generic unrecognized verification implementation MAY be consensus-valid but SHOULD NOT be propagated through the public mempool when it performs state changes before payer approval.

A public-mempool profile admitting pre-payment configuration MUST define:

1. the exact verification implementation runtime code hash;
2. permitted configuration calldata or a parser for it;
3. the maximum execution and state gas;
4. the exact accounts and storage keys that may be read or written;
5. permitted external call targets and required code hashes;
6. whether delegated calls are forbidden or their complete code-hash closure;
7. all environmental dependencies;
8. the dependency and write set used for revalidation;
9. the behavior of subsequent `VERIFY` frames against the temporary overlay; and
10. an optional gas- and behavior-equivalent direct evaluator.

A canonical [EIP-8130](./eip-8130.md)-style actor-authority profile can use this mechanism to install an actor and immediately validate it without a separate transaction or account-change envelope.

#### Post-payment configuration

A `CONFIGURE` frame occurring after payer approval is outside the validation prefix. It follows ordinary consensus execution and may be propagated without adding pre-validation state-mutation work.

#### Code-hash admission

A chain MAY admit only verification implementations whose current runtime code hash belongs to a configured set. Such a policy applies to verification code, not arbitrary wallet execution code.

A code hash identifies the initial verification bytecode. A no-tracing profile additionally SHOULD specify permitted external authority calls, bounded state dependencies, environmental dependencies, gas bounds, calldata parsing, and revalidation conditions.

The current runtime code hash at `verification_implementation` is always a validation dependency. Pending transactions MUST be revalidated when it changes.

## Rationale

### Why verification executes in account context

[EIP-8141](./eip-8141.md) `APPROVE` requires `ADDRESS == resolved_target`. Calling an external verifier or keystore directly cannot approve for the account. Selecting verification code while retaining the account context lets the narrow validation path invoke `APPROVE` without re-entering the ordinary wallet implementation.

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

A separate magic return value would create another signaling convention alongside [EIP-8141](./eip-8141.md) `APPROVE`. `APPROVE_CONFIGURE` keeps every account-context authorization result on one protocol channel.

The action is mode-specific rather than an execution/payment frame flag. This prevents a session actor's ability to approve execution from automatically implying descriptor or authority-state administration.

### Why configuration may precede payment

An earlier draft required `payer != None` before `CONFIGURE`. That restriction was chosen to ensure configuration work was paid, keep non-static writes outside the public-mempool validation prefix, and avoid changing [EIP-8141](./eip-8141.md)'s validation-prefix rules.

It was unnecessarily restrictive. [EIP-8141](./eip-8141.md) authenticates signature entries before frame execution, and a later payer approval covers the transaction's complete gas budget, including earlier frames. Treating pre-payment configuration as bounded validation-prefix work therefore permits install-and-first-use without creating a second transaction format.

The DoS concern is addressed by validation gas/state bounds and recognized profiles, not by prohibiting the ordering entirely.

### Why zero descriptor length means state-only configuration

Many authority updates do not change account code identity. Requiring a descriptor rewrite for every session-key or expiry update would add data and state churn.

A nonzero length supports descriptor-only and combined descriptor-plus-state migration in the same frame.

### Why signatures remain in the [EIP-8141](./eip-8141.md) list

The signature list provides one location for protocol validation, witness elision, future aggregation, and signatures consumed during ordinary execution. Structured authority changes how authenticated results are authorized; it does not create a second signature container.

### Validation after execution

Account authority must be established before a `SENDER` frame. Post-execution assertions, zero-slippage protection, and similar revert-protection schemes are orthogonal and may be evaluated later where [EIP-8141](./eip-8141.md) ordering and public-mempool policy permit.

### Scope boundaries

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

### Open questions

### Canonical actor-authority profile

A shared production path for multi-actor accounts still requires agreement on at least one canonical verification implementation or profile. That profile may choose a shared keystore, deterministic per-account authority address, account-local storage, or another representation.

For L1/L2 public-mempool interoperability it must specify bounded read and write dependencies, code hashes, pre-payment configuration semantics, and revalidation rules.

#### Verification implementation code identity

The descriptor stores an address rather than an expected runtime code hash. An implementation change at the same address changes authority semantics without changing the account descriptor. Immutable deployments are recommended; a later authority type may pin a code hash.

#### Bootstrap into stateful verification

`VERIFY_IMPLEMENTATION` can update its own authority data once active. A direct transition from `INLINE_ROOT` or an unstructured account to a verification implementation with uninitialized account-local authority data can lock the account. A companion profile may define pre-initialized external authority, deterministic initialization, or a root-authorized bootstrap call to the destination verification implementation.

#### Existing non-frame accounts

`CONFIGURE` can migrate code-less accounts and smart accounts that already support [EIP-8141](./eip-8141.md) validation. [ERC-4337](./eip-4337.md)-only accounts that cannot approve a frame transaction still need an implementation-specific upgrade or migration path.

#### Validation gas budget

Pure authentication, pre-payment configuration, sender authorization, and payer authorization must fit the active [EIP-8141](./eip-8141.md) public-mempool validation budget. Expensive post-quantum verification or multiple custom authenticators may require separate authentication and authorization budgets or a larger cap.

#### Configuration and subsequent execution atomicity

A pre-payment configuration is reverted if later validation fails or no payer is established. Once payment is approved, a later non-atomic execution-frame failure does not automatically revert the earlier configuration. Wallets that require configuration and business execution to commit together need a compatible atomic construction or a later transaction-level assertion.

## Backwards Compatibility

This proposal requires a network upgrade because it assigns special semantics to `0xef02`, extends [EIP-8141](./eip-8141.md) signature introspection and `APPROVE`, and adds a frame mode.

[EIP-3541](./eip-3541.md) prevents newly deployed ordinary code beginning with `0xef`, so existing deployable EVM contracts are not reinterpreted as structured accounts.

Pre-upgrade clients reject structured descriptors and do not understand the new signature attributes, `CONFIGURE` mode, or `APPROVE_CONFIGURE` action.

## Test Cases

Implementations MUST cover at least the following cases.

### Authentication result

1. A secp256k1 signature exposes `verifier = address(0x01)` and the recovered address as `key_id`.
2. A P-256 signature exposes `verifier = address(0x100)` and `keccak256(qx || qy)` as `key_id`.
3. `SIGPARAM_KEY_ID` and `SIGPARAM_VERIFIER` halt for `ARBITRARY`.
4. Raw P-256 witness bytes remain unavailable through `SIGDATACOPY`.

### Descriptor parsing

1. Accept valid 75-byte `INLINE_ROOT` and 43-byte `VERIFY_IMPLEMENTATION` descriptors.
2. Reject zero implementation, verifier, key ID, or verification implementation.
3. Reject malformed lengths and unknown authority types.
4. Confirm `execution_implementation` always occupies bytes `3..22`.

### Inline root

1. Accept a matching `(verifier, key_id)` and requested approval scope.
2. Reject the same key ID under another verifier.
3. Reject `ARBITRARY` as an inline-root credential.

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

1. Accept `APPROVE_CONFIGURE` before or after payer approval when `ADDRESS == resolved_target == tx.sender`.
2. Reject it in `VERIFY`, `DEFAULT`, and `SENDER` modes.
3. Reject execution/payment approval operands in `CONFIGURE` mode.
4. Confirm it does not alter `sender_approved`, payer, nonce, or maximum-cost collection.
5. Confirm it terminates the top-level configuration call frame successfully.
6. Reject it from a nested `CALL`, `DELEGATECALL`, or `CALLCODE` frame.
7. Confirm a normal return without approval rolls back all configuration state changes.
8. Reject `ATOMIC_BATCH_FLAG` on a pre-payment configuration.

### Pre-payment configuration

1. Add a new actor under authorization from an existing administrator, then approve execution and payment with the new actor in a later `VERIFY` frame.
2. Prevalidate both signatures before frame execution and confirm the new actor is not authorized until `CONFIGURE` succeeds.
3. Fail configuration and confirm the transaction is invalid and all changes revert.
4. Succeed in configuration but fail the later `VERIFY`; confirm all changes revert.
5. Succeed in configuration but never establish a payer; confirm the transaction is invalid and all changes revert.
6. Confirm the eventual payer is charged for gas and state gas consumed by the earlier configuration.
7. Confirm later validation observes the temporary configuration overlay.
8. Apply a replacement/eviction/reorg during mempool handling and discard the temporary overlay.

### Post-payment configuration

1. Update authority state after payment and approve configuration.
2. Fail configuration after payment and record a failed paid frame without committing its state.
3. Use an atomic batch after payment and roll configuration back when a later batch frame fails.

### Descriptor configuration

1. Rotate an inline root before payment, then verify and pay with the new root.
2. Replace the execution implementation through the current verification implementation.
3. Replace the verification implementation after current-authority approval.
4. Mutate current authority state and replace the descriptor in one frame.
5. Confirm the current, not proposed, authority authorizes replacement.
6. Reject descriptor-write out-of-gas and revert all configuration effects.

### Public mempool

1. Admit directly evaluable inline-root pre-configuration.
2. Reject unrecognized state-changing pre-payment verification implementations from generic propagation.
3. Admit a recognized profile with bounded reads, writes, calls, and gas.
4. Change a declared dependency and revalidate the transaction and temporary overlay.
5. Directly evaluate a profile and reproduce EVM gas, state, returndata, failure, and approval behavior.

### Code replacement

1. Confirm [EIP-7702](./eip-7702.md) authorization cannot overwrite structured code.
2. Confirm [EIP-8298](./eip-8298.md) cannot replace a structured descriptor.
3. Confirm a structured descriptor cannot be used as an [EIP-8298](./eip-8298.md) source.

## Security Considerations

### Verification implementation is authority code

A verification implementation decides whether execution/payment approval or configuration succeeds. A bug that ignores the transaction hash, misparses a key ID, trusts an unauthenticated external result, or grants excessive authority compromises every account using it.

### Pre-payment configuration denial of service

Pre-payment configuration performs work before a payer is selected. Although any included valid transaction eventually pays for that work, public nodes could otherwise be forced to simulate arbitrary state-changing configurations that are later discarded.

Public-mempool admission MUST therefore count pre-payment configuration against validation gas and state-gas limits. State-changing `VERIFY_IMPLEMENTATION` configurations SHOULD be propagated only under recognized profiles with bounded code, call, read, and write dependencies.

### Provisional state visibility

Later validation frames intentionally observe state produced by pre-payment configuration. Clients must use an isolated transaction overlay and must discard it whenever the transaction fails validation, lacks a payer, is replaced, evicted, or otherwise not committed.

Incorrect overlay reuse could make one pending transaction affect validation of another.

### Authority storage is implementation-defined

If verification reads authority from structured-account storage, ordinary execution code may be able to modify that state. If this is not intended, the verification implementation must use a protected external authority contract, immutable descriptor data, cryptographic commitments, or another design that prevents unauthorized execution-layer mutation.

### Verification implementation code changes

The descriptor names an address rather than a code hash. Code changes at that address alter authorization semantics. Nodes must revalidate pending transactions, and wallets should prefer immutable verification deployments or treat their upgrade authority as account root authority.

### Transitive code execution

Code reached through `DELEGATECALL` or `CALLCODE` runs with the structured account address and can mutate configuration state or influence authorization. It cannot directly complete configuration because `APPROVE_CONFIGURE` is restricted to the top-level configuration call frame, but it remains part of the authority implementation's trust boundary.

### External authority contracts

An external keystore or authority service cannot approve directly, but a malicious or upgradeable service can return forged authorization to an adapter that trusts it. Its code, state, and upgrade authority are part of the account's security boundary.

### Configuration authorization binding

A verification implementation must invoke `APPROVE_CONFIGURE` only after authorization is bound to every security-critical field. For descriptor updates this includes the exact new descriptor. For authority-state updates it includes the exact mutation payload. Account, chain or replay domain, and update nonce or sequence must be included where required by the authority model.

### Configuration and execution atomicity

A pre-payment configuration is provisional through later validation and payer selection. After payer approval, a later non-atomic execution failure does not automatically revert it. Wallets must not assume install-and-first-use implies install-and-business-action atomicity.

### Bootstrap lockout

Installing a stateful verification implementation without initialized authority state may permanently lock the account. Wallets must initialize the destination authority first or use a standardized bootstrap profile.

### Descriptor installation discards prior code

Installing a structured descriptor overwrites the account's previous code, including an [EIP-7702](./eip-7702.md) delegation indicator or a complete smart-account implementation. Wallets MUST point `execution_implementation` at equivalent logic before installation -- for example, the previous runtime code already deployed at another address. The discarded code cannot be recovered from the descriptor.

### Legacy signatures

Installing structured authority disables legacy transaction origination but does not revoke message signatures recognized by third-party contracts. Descriptor rotation must not be represented as universal retirement of an old ECDSA identity.

### Client consistency

Clients must agree on descriptor parsing, authentication-result derivation, mode-sensitive code selection, account-context execution, pre-payment configuration overlays, `APPROVE_CONFIGURE`, gas charging, descriptor replacement, and rollback semantics. Divergence is consensus-critical.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
