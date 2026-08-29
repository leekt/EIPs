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

This proposal introduces a typed structured-account designator:

```text
0xef02
|| authority_type               (1 byte)
|| execution_implementation     (20 bytes)
|| authority_payload            (type-defined, fixed length)
```

The designator separates the code used for ordinary account execution from the mechanism used to validate frame transactions. The execution implementation occupies the same position for every authority type, while `authority_type` selects how `VERIFY` frames are handled.

Two authority types are defined initially:

```text
0x00 INLINE_ROOT
0xef0200
|| execution_implementation     (20 bytes)
|| verifier                     (20 bytes)
|| key_id                       (32 bytes)
```

and:

```text
0x01 VERIFY_IMPLEMENTATION
0xef0201
|| execution_implementation     (20 bytes)
|| verification_implementation  (20 bytes)
```

`INLINE_ROOT` is the common single-root case. Protocol signature validation resolves a `(verifier, key_id)` pair, and the protocol directly compares it with the descriptor before applying the requested EIP-8141 approval.

`VERIFY_IMPLEMENTATION` separates validation code from execution code. During a `VERIFY` frame, the protocol loads `verification_implementation` but executes it in the structured account's context. The verification implementation receives `frame.data` unchanged, may consume EIP-8141 signature metadata, may call an external keystore or other authority contract, and calls `APPROVE` from the structured account's address. The protocol does not know the verification implementation's ABI or authority-storage layout.

All non-validation calls execute `execution_implementation` in the structured account's context using one-hop delegation semantics. A `CONFIGURE` frame replaces a structured descriptor after authorization by the current authority path. A `SETDESCRIPTOR` instruction provides a one-way migration path from an existing non-structured account.

## Motivation

EIP-8141 allows arbitrary account code to validate frame transactions. This preserves programmability, but couples transaction authorization to the complete wallet implementation. A sequencer that wants to understand validation statically must recognize every wallet implementation or execute and trace arbitrary account code.

Authentication, authorization, and execution have different requirements:

- cryptographic authentication should be bounded and independently cacheable;
- authorization may need account or keystore state;
- ordinary account execution should remain fully programmable; and
- a wallet should not have to standardize its token receivers, session execution, hooks, or application logic merely to obtain a statically understandable validation path.

EIP-8397 separates expensive state-independent authentication from account authorization by producing an authenticated `(verifier, key_id)` result before frame execution. This proposal separates the remaining authorization path from ordinary execution code.

For a simple account, the root verifier and key identifier are stored directly in the descriptor and no validation bytecode executes. For a richer account, the descriptor points to a dedicated verification implementation. That implementation can be a small adapter which reads an authenticated actor ID, queries a transport-agnostic keystore, checks scope and expiry, and calls `APPROVE`. The account's unrelated execution implementation is never involved in validation.

This distinction avoids two opposite extremes:

- embedding an open-ended list of actors, roles, expiry values, and recovery rules into account code; and
- requiring the base protocol to understand one particular keystore address, Solidity ABI, storage layout, or scope encoding.

A chain may execute any verification implementation through the EVM. A public mempool or L2 may additionally recognize a small set of verification-implementation code hashes and directly evaluate their known semantics. This permits static analysis without maintaining an allowlist of arbitrary wallet execution implementations.

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
| `ROOT_VERIFY_DATA_LENGTH` | `4` |
| `CONFIGURE_MODE` | `0x03` |
| `CONFIGURE_LENGTH_BYTES` | `2` |
| `CONFIGURE_SUCCESS` | `keccak256("STRUCTURED_ACCOUNT_CONFIGURE_SUCCESS")` |
| `SETDESCRIPTOR_OPCODE` | `TBD` |
| `STRUCTURED_VERIFY_BASE_GAS` | `500` |
| `CONFIGURE_BASE_GAS` | `5000` |
| `SETDESCRIPTOR_BASE_GAS` | `5000` |

`STRUCTURED_VERIFY_BASE_GAS`, `CONFIGURE_BASE_GAS`, and `SETDESCRIPTOR_BASE_GAS` are provisional values pending client benchmarks.

### Structured account envelope

Every structured account begins with:

```text
0xef02
|| authority_type               (1 byte)
|| execution_implementation     (20 bytes)
```

The byte offsets common to every authority type are:

| Bytes | Field |
|---|---|
| `0..1` | `STRUCTURED_ACCOUNT_MAGIC` |
| `2` | `authority_type` |
| `3..22` | `execution_implementation` |
| `23..` | `authority_payload` |

`execution_implementation` MUST be nonzero.

`authority_type` is a tagged-union discriminator, not a sequential version number. Multiple authority types may coexist at the same fork. An incompatible authority representation receives a new `authority_type` value.

Unknown authority types are invalid structured-account code until assigned by a later EIP.

Conceptually:

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

### Authentication result

Direct structured authorization consumes a normalized authentication result:

```text
AuthenticationResult {
    verifier    address
    key_id      bytes32
}
```

The result is produced during protocol signature validation and is immutable for the remainder of the transaction.

For EIP-8141 signature schemes, normalization is:

| Signature scheme | `verifier` | `key_id` |
|---|---|---|
| `SECP256K1` | `ECRECOVER_VERIFIER` | recovered Ethereum address right-aligned in 32 bytes |
| `P256` | `P256_VERIFIER` | `keccak256(qx || qy)` |
| EIP-8397 `AUTHENTICATOR` | authenticator address | authenticated EIP-8397 `key_id` |

`ARBITRARY` does not produce an `AuthenticationResult`. A verification implementation may nevertheless consume an `ARBITRARY` entry through EIP-8141's existing `SIGDATACOPY` instruction.

For `P256`, `qx || qy` is the 64-byte public key contained in the protocol-validated signature entry. Computing `key_id` does not make the raw signature bytes EVM-visible.

Future protocol-validated signature schemes MAY define a `(verifier, key_id)` normalization through a later EIP.

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

The configured `(verifier, key_id)` is the account's root authority. It is implicitly authorized for all structured-account protocol operations:

- approve execution;
- approve self payment;
- approve sponsorship payment; and
- replace the structured descriptor.

Authorization succeeds when:

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

`verification_implementation` identifies code used only for structured-account `VERIFY` and `CONFIGURE` handling. It is not called as an external verifier contract. Its code is loaded and executed with the structured account as the execution-environment address, analogous to EIP-7702 delegated-code execution.

The descriptor MAY be installed before code exists at `verification_implementation`. A `VERIFY` or `CONFIGURE` frame cannot succeed until code resolution produces valid executable verification code.

The base protocol does not assign an ABI, calldata schema, storage layout, actor model, scope model, or keystore address to this authority type.

### EIP-8141 frame changes

The EIP-8141 frame-mode table is extended with:

| `mode` | Name | Summary |
|---|---|---|
| `0x03` | `CONFIGURE` | replace the sender's structured descriptor after authorization by its current authority path |

The static frame constraint becomes:

```python
assert frame.mode < 4
```

The `ATOMIC_BATCH_FLAG` is also valid for `CONFIGURE` frames under this proposal.

During dispatch, valid structured-account code is recognized before ordinary EIP-7702 delegation handling:

```python
if is_structured_account(resolved_target):
    descriptor = parse_structured_account(state[resolved_target].code)

    if frame.mode == VERIFY:
        execute_structured_verify(frame, descriptor)
    elif frame.mode == CONFIGURE:
        execute_structured_configure(frame, descriptor)
    else:
        execute_structured_execution(frame, descriptor)
else:
    assert frame.mode != CONFIGURE
    execute_existing_eip8141_dispatch(frame)
```

A `CONFIGURE` frame targeting an account that is not already structured is invalid. Migration into the structured format uses `SETDESCRIPTOR`.

### Inline-root `VERIFY`

A `VERIFY` frame targeting an `INLINE_ROOT` account does not execute account code.

Its `frame.data` contains exactly one unsigned 32-bit big-endian signature index:

```text
signature_index    (4 bytes)
```

The frame succeeds only when:

1. `len(frame.data) == ROOT_VERIFY_DATA_LENGTH`.
2. `signature_index < len(tx.signatures)`.
3. The referenced signature uses the canonical frame-transaction signing hash, meaning `len(sig.msg) == 0`.
4. The referenced signature produces an `AuthenticationResult`.
5. The result matches the descriptor's `(verifier, key_id)`.
6. `frame.flags & APPROVE_SCOPE_MASK != 0`.
7. Every ordinary EIP-8141 structural rule for the requested approval scope holds.

On success, the protocol applies the same effects as:

```text
APPROVE(frame.flags & APPROVE_SCOPE_MASK)
```

Conceptually:

```python
def execute_inline_root_verify(frame, descriptor, tx):
    assert len(frame.data) == 4
    signature_index = int.from_bytes(frame.data, "big")
    assert signature_index < len(tx.signatures)

    sig = tx.signatures[signature_index]
    assert len(sig.msg) == 0

    auth_result = structured_authentication_result(sig)
    assert authorize_inline_root(descriptor, auth_result)

    approve_scope = frame.flags & APPROVE_SCOPE_MASK
    assert approve_scope != 0

    apply_eip8141_approve(
        resolved_target=resolved_target(frame),
        scope=approve_scope,
    )
```

No execution or verification implementation bytecode runs on this path.

### Verification-implementation `VERIFY`

A `VERIFY` frame targeting a `VERIFY_IMPLEMENTATION` account executes `verification_implementation`, not `execution_implementation`.

The verification code executes with the following top-level context:

| Property | Value |
|---|---|
| code source | code resolved from `verification_implementation` |
| `ADDRESS` | structured account address (`resolved_target`) |
| account storage | structured account storage |
| `CALLER` | EIP-8141 `ENTRY_POINT` |
| `CALLVALUE` | `0` |
| calldata | `frame.data`, unchanged |
| static mode | enabled, as for an ordinary EIP-8141 `VERIFY` frame |
| gas pools | the frame's declared execution and state limits, subject to EIP-8141 rules |

Code resolution is one hop. If `verification_implementation` is empty, a precompile, an EIP-7702 delegation indicator, or another structured-account designator, no further indirection is followed. The resulting frame cannot approve the transaction unless executable code actually invokes `APPROVE` successfully.

The verification implementation MAY:

- read protocol-validated signature metadata with `SIGPARAM`;
- read `ARBITRARY` witness bytes with `SIGDATACOPY`;
- inspect transaction and frame data using EIP-8141 introspection;
- read the structured account's own storage;
- call a keystore, verifier, or other authority contract subject to static execution and EIP-8141 validation rules; and
- call `APPROVE` after it has established authorization.

`frame.data` is opaque to the protocol. It may use Solidity ABI encoding, packed bytes, RLP, SSZ, or any implementation-defined encoding.

The verification implementation itself calls `APPROVE`. This works because the code executes with `ADDRESS == resolved_target`. An external contract reached through `CALL` or `STATICCALL` does not become the frame's resolved target and cannot approve on behalf of the account; it must return its result to the verification implementation, which performs the final check and calls `APPROVE` from the account context.

The frame remains subject to every existing EIP-8141 `VERIFY` requirement. In particular:

- the frame executes statically;
- failure, revert, exceptional halt, or absence of the required `APPROVE` makes the frame transaction invalid;
- the scope passed to `APPROVE` must match the approval scope declared by `frame.flags`; and
- public-mempool trace and dependency rules continue to apply unless a node uses an equivalent direct evaluator as described below.

During this delegated verification execution:

- `CODESIZE` and `CODECOPY` observe the verification implementation's code;
- `EXTCODESIZE`, `EXTCODECOPY`, and `EXTCODEHASH` of the structured account observe the 43-byte structured descriptor; and
- storage operations address the structured account's storage.

A minimal keystore adapter can conceptually perform:

```text
read signature index from frame.data
read (verifier, key_id) through SIGPARAM
call transport-agnostic keystore with (account, verifier, key_id)
check returned scope / expiry
APPROVE(requested_scope)
```

The keystore does not need to know EIP-8141. Only the verification implementation acts as the transport adapter and uses EIP-8141 introspection and `APPROVE`.

### `CONFIGURE` frame

A structured account may replace its authority type, execution implementation, and authority payload through `CONFIGURE`.

Configuration is authorized against the current descriptor, not the proposed descriptor. `CONFIGURE` requires transaction payment to have already been established, so unsuccessful configuration work is paid for and lies outside the public-mempool validation prefix.

The frame data is:

```text
new_descriptor_length   (2 bytes, uint16 big-endian)
new_descriptor          (new_descriptor_length bytes, begins with 0xef02)
authorization_data      (remaining bytes)
```

`new_descriptor_length` MUST be nonzero, MUST fit within the remaining frame data, and MUST identify a complete valid structured descriptor under an authority type active at the current fork.

A `CONFIGURE` frame is structurally valid only when:

1. `resolved_target == tx.sender`.
2. `tx.sender` currently contains a valid structured descriptor.
3. `payer != None` before the frame begins.
4. `frame.flags & APPROVE_SCOPE_MASK == 0`.
5. No undefined flag bit is set.
6. `frame.value == 0`.
7. `len(frame.data) >= CONFIGURE_LENGTH_BYTES + 1`.
8. At most one `CONFIGURE` frame appears in the transaction.
9. No `SENDER` frame precedes it.

The current authority type authorizes configuration as follows.

#### Inline-root configuration

For an `INLINE_ROOT` account, `authorization_data` MUST contain exactly one unsigned 32-bit big-endian signature index.

The referenced signature MUST:

- be within `tx.signatures`;
- use the canonical frame-transaction signing hash; and
- produce an `AuthenticationResult` matching the current inline root.

Because the canonical signing hash commits to the complete frame list and `frame.data`, the root signature commits to the proposed descriptor.

#### Verification-implementation configuration

For a `VERIFY_IMPLEMENTATION` account, the current `verification_implementation` is executed in the structured account's context with:

- `frame.data` as calldata, unchanged;
- `ADDRESS` and storage set to the structured account;
- `CALLER` set to `ENTRY_POINT`;
- static mode enabled; and
- the frame's execution-gas limit.

The code can distinguish this path through `FRAMEPARAM(..., mode) == CONFIGURE_MODE`. It may interpret `authorization_data` however it chooses and may inspect the complete proposed descriptor.

Configuration authorization succeeds only if execution returns exactly 32 bytes equal to `CONFIGURE_SUCCESS`.

`APPROVE` is not a configuration-authorization mechanism. Calling `APPROVE` during a `CONFIGURE` frame is invalid because the frame declares no approval scope. The verification implementation must return `CONFIGURE_SUCCESS` after its own root, admin, recovery, or keystore check succeeds.

An adapter for an actor keystore would ordinarily require an admin actor for this path, while allowing less privileged actors to approve ordinary execution or payment. These semantics belong to the verification implementation or its companion profile, not this core EIP.

#### Applying configuration

Conceptually:

```python
def execute_structured_configure(frame, descriptor, tx, state):
    assert resolved_target(frame) == tx.sender
    assert payer is not None
    assert frame.flags & APPROVE_SCOPE_MASK == 0
    assert frame.value == 0

    new_length = int.from_bytes(frame.data[0:2], "big")
    assert new_length > 0
    assert 2 + new_length <= len(frame.data)

    new_descriptor = frame.data[2:2 + new_length]
    authorization_data = frame.data[2 + new_length:]
    parse_structured_account(new_descriptor)

    if descriptor.authority_type == INLINE_ROOT:
        assert len(authorization_data) == 4
        signature_index = int.from_bytes(authorization_data, "big")
        sig = tx.signatures[signature_index]
        assert len(sig.msg) == 0
        assert authorize_inline_root(
            descriptor,
            structured_authentication_result(sig),
        )

    elif descriptor.authority_type == VERIFY_IMPLEMENTATION:
        result = execute_verification_implementation(
            account=tx.sender,
            implementation=descriptor.verification_implementation,
            mode=CONFIGURE,
            calldata=frame.data,
            static=True,
            gas=frame.limits.execution,
        )
        assert result == CONFIGURE_SUCCESS

    else:
        invalid_structured_account()

    state[tx.sender].code = new_descriptor
```

Structural failures make the transaction invalid. An authorization failure, revert, exceptional halt, or wrong return value makes the paid `CONFIGURE` frame fail without replacing code. Ordinary frame and atomic-batch rollback rules apply.

The new descriptor is visible to later frames in the same transaction. A wallet MAY place `CONFIGURE` and later execution frames in one atomic batch so that a failed action restores the previous descriptor.

### `SETDESCRIPTOR` instruction

`SETDESCRIPTOR` provides a one-way migration path from existing account code or EIP-7702 delegated code into a structured descriptor.

The instruction takes two stack items:

```text
[..., offset, length]
```

and returns:

```text
[..., success]
```

The memory range `[offset, offset + length)` is interpreted as the complete proposed structured descriptor beginning with `0xef02`.

Execution causes an exceptional halt when:

- executed in static mode;
- executed from initcode; or
- the current execution-context account is already a structured account.

Otherwise:

1. Charge `SETDESCRIPTOR_BASE_GAS` plus memory expansion and the active state/code-write cost.
2. Parse the proposed descriptor.
3. If it is invalid, push `0` and make no state change.
4. If it is valid, replace the current execution-context account's code with the descriptor and push `1`.

The current execution-context account is the account returned by `ADDRESS`. Code reached through EIP-7702 delegation can therefore migrate the delegating account, and a conventional smart account can expose an account-authorized migration function.

The current execution frame continues running the code already loaded for that frame. Later calls observe the new structured descriptor.

State changes follow ordinary revert semantics.

`SETDESCRIPTOR` is deliberately disabled once an account is structured. Structured authority can then be changed only through `CONFIGURE`, so ordinary execution code cannot bypass the current authority path.

### Ordinary execution delegation

For every code-executing operation targeting a structured account outside `VERIFY` and `CONFIGURE`, the EVM loads code from `execution_implementation` and executes it in the structured account's context.

The affected operations are the same as EIP-7702:

- a transaction whose destination is the structured account;
- `CALL`;
- `CALLCODE`;
- `DELEGATECALL`; and
- `STATICCALL`.

Resolution is one hop only. If `execution_implementation` is empty, a precompile, an EIP-7702 delegation indicator, or another structured-account designator, it is treated as empty code for this resolution path.

During delegated execution:

- `ADDRESS` returns the structured account address;
- storage operations access the structured account's storage;
- `EXTCODESIZE`, `EXTCODECOPY`, and `EXTCODEHASH` observe the structured descriptor; and
- `CODESIZE` and `CODECOPY` observe the loaded execution implementation code.

The execution implementation address is not code-hash pinned by this proposal. Changing code at that address changes account execution behavior but does not directly change the authority payload.

### Code installation and replacement restrictions

EIP-3541 is modified to permit creation-time installation of code beginning with `0xef02` only when the complete code is a valid structured descriptor under an authority type active at the current fork.

Unknown or malformed `0xef02` code remains invalid for contract creation.

EIP-7702 authorization processing MUST NOT overwrite a structured account. This follows from EIP-7702 accepting only empty code or an existing EIP-7702 delegation indicator.

EIP-8298 `SETCODEFROM` MUST fail without changing code when the current execution-context account is structured. Without this restriction, execution implementation code could replace the descriptor and bypass structured authority.

A structured descriptor MUST NOT be a valid source for EIP-8298 `SETCODEFROM`.

`SETDESCRIPTOR` MUST fail for an already structured account.

Any future account-code replacement mechanism MUST explicitly specify whether it can replace structured-account code. The default is that it cannot.

### EIP-3607 transaction origination

Structured accounts have non-empty code and therefore cannot originate legacy ECDSA transactions under EIP-3607.

They originate frame transactions through structured authorization, or another future transaction type that explicitly recognizes this account format.

### Gas accounting

Inline-root authorization charges:

```text
STRUCTURED_VERIFY_BASE_GAS
+ ordinary resolved-target account access cost
+ the referenced signature's protocol-validation cost
```

Verification-implementation authorization uses the frame's ordinary EIP-8141 execution-gas budget. In addition to the resolved-target account access, resolving `verification_implementation` charges the active warm or cold account/code access cost analogously to EIP-7702 delegation resolution. Calls made by the verification implementation, including keystore reads, are charged through normal EVM rules.

A direct evaluator MUST charge the same gas that equivalent EVM execution would charge. Direct evaluation is an execution optimization, not a pricing change.

`CONFIGURE` charges `CONFIGURE_BASE_GAS`, any verification-implementation execution cost, and the active state/code-update charge for replacing the descriptor.

`SETDESCRIPTOR` charges `SETDESCRIPTOR_BASE_GAS`, memory expansion, and the active state/code-update charge.

Ordinary execution delegation charges implementation account access exactly as EIP-7702 charges delegated-code resolution.

### Public mempool handling

An `INLINE_ROOT` `VERIFY` frame is directly evaluable from the account descriptor and referenced protocol-validated signature result.

A `VERIFY_IMPLEMENTATION` frame is consensus-valid by executing the named verification implementation under EIP-8141 `VERIFY` semantics. Public-mempool nodes have three compatible choices:

1. simulate and trace the verification implementation under the generic EIP-8141 rules;
2. recognize a verification-implementation code hash and directly evaluate semantics known to be equivalent to its EVM execution; or
3. decline to propagate transactions using unrecognized verification implementations as local or chain-specific admission policy.

Authority-type `0x01` does not make a keystore, ABI, or storage layout a consensus concept. A canonical keystore adapter may be specified separately by publishing:

- verification implementation bytecode and code hash;
- its frame-data encoding;
- the keystore calls or storage dependencies it uses;
- an equivalent direct evaluator; and
- any L2 admission policy.

A chain that requires fully static validation MAY admit only approved verification-implementation code hashes. This allowlist contains validation adapters, not arbitrary wallet execution implementations. The account remains free to select any execution implementation because that code does not run in the validation prefix.

For a recognized verification implementation, nodes SHOULD index pending transactions by the exact dependency set defined by its direct-evaluation profile. For a generic implementation, dependencies are obtained from its validation trace under EIP-8141.

The current code hash at `verification_implementation` is always a dependency. Pending transactions MUST be revalidated if that code changes.

Because `CONFIGURE` requires `payer != None`, it lies outside the public-mempool validation prefix.

## Rationale

### Why authority types are a tagged union

`INLINE_ROOT` and `VERIFY_IMPLEMENTATION` are not successive revisions of one account. They are alternative validation representations that can coexist.

An account selects exactly one authority type. It does not simultaneously combine inline-root authorization and a verification implementation. Switching representations requires an authorized `CONFIGURE` operation.

### Why execution implementation has a fixed offset

Every authority type keeps `execution_implementation` at bytes `3..22`.

Ordinary call dispatch therefore does not need to understand authority payloads. Clients can resolve execution from the common header, while `VERIFY` dispatches on `authority_type`.

### Why inline root stores `(verifier, key_id)`

A fixed 32-byte key identifier avoids variable-length public keys in account code and matches authenticator-based identity models.

The verifier defines how a proof maps to `key_id`:

- ECDSA produces an address-derived identifier;
- P-256 produces a hash of the full public key;
- EIP-8397 authenticators return `key_id` directly; and
- future PQ, aggregate, or stateless multisig schemes can use the same identity surface.

The descriptor remains 75 bytes regardless of the underlying public-key or proof size.

### Why a separate verification implementation

A wallet's validation surface is usually much smaller and more standardized than its complete execution surface.

Separating the two allows:

- arbitrary account execution implementations;
- a small auditable validation adapter;
- code-hash-based mempool admission and native direct evaluation;
- a keystore or actor registry without enshrining that registry in the core protocol; and
- existing wallet execution code to evolve without changing validation semantics.

This corresponds to a two-code-section account: one implementation runs normally and another runs for verification.

### Why verification code executes in account context

EIP-8141 requires the approving code to act from the frame's resolved target. An ordinary call to an external verifier or keystore cannot approve on behalf of the account.

Loading the verification implementation while retaining the structured account as `ADDRESS` solves this without an account-code wrapper:

```text
VERIFY account
  -> load verification implementation code
  -> execute with ADDRESS = account
  -> call external authority if needed
  -> account-context code calls APPROVE
```

The execution implementation is never entered during validation.

### Why the protocol does not know an ABI

`frame.data` is passed unchanged to the verification implementation. The core protocol needs only the verification implementation address and normal EVM dispatch semantics.

A canonical adapter may define a compact four-byte signature index, Solidity ABI, or another encoding, but that choice belongs to the adapter profile. Replacing an adapter's calldata format does not require changing the structured-account envelope.

### Keystore compatibility

A transport-agnostic keystore can continue to expose its existing contract interface and storage model. A small EIP-8141-aware verification implementation adapts frame signature metadata to that interface and calls `APPROVE` after the keystore authorizes an actor.

Responsibilities are therefore:

```text
EIP-8141 signature list / EIP-8397
  -> authentication result

verification implementation
  -> frame-aware adapter and final APPROVE

keystore
  -> transport-agnostic actor authorization

execution implementation
  -> ordinary wallet behavior
```

The keystore itself does not need EIP-8141 opcodes.

### Session keys and richer authority

A session key, recovery path, multisig, or scoped actor does not require additional entries in the structured descriptor.

A verification implementation may read account storage or call an external authority contract containing multiple actors, scope, expiry, thresholds, or recovery state. It then calls only the EIP-8141 approval scope authorized by that state.

Application-specific execution restrictions such as target allowlists and token-spend limits may remain in post-payment execution logic. A canonical adapter profile may define a stronger session-policy path without changing this core EIP.

### Why no mandatory keystore type

Defining actor-slot derivation, packing, expiry, scope constants, and update digests in the core EIP would make one wallet authority model consensus-critical.

`VERIFY_IMPLEMENTATION` preserves a raw-EVM implementation path while allowing a chain to optimize a canonical keystore adapter by code hash. Different chains may recognize different fast paths without changing the account envelope.

### Why direct evaluation is optional

Direct evaluation and EVM execution must be behaviorally equivalent. A base layer can accept arbitrary verification implementations and execute them normally. A high-throughput L2 can restrict its public mempool to a small set of known code hashes and avoid tracing those paths.

Restrictiveness is therefore an admission policy layered on a permissive consensus mechanism.

### Why signatures remain outside calldata

The structured descriptor changes how accounts consume authentication results; it does not replace EIP-8141's signature list.

Keeping signatures in the transaction signature list preserves independent validation, witness elision, future aggregation, and use of signatures during ordinary execution such as ERC-1271, permits, and admin operations.

### Why `CONFIGURE` uses a return value

Ordinary EIP-8141 `APPROVE` represents execution and payment approval. Configuration authority is a distinct account-level operation and should not be conflated with either scope.

A dedicated `CONFIGURE` frame executes the current verification implementation statically and requires a fixed return value. This lets the implementation distinguish an admin or recovery path from ordinary session execution without adding keystore-specific scope constants to the core protocol.

### Why `SETDESCRIPTOR` is one-way

Existing accounts need a migration path, but allowing the ordinary execution implementation of an already structured account to rewrite its descriptor would put ultimate authority back into arbitrary execution code.

`SETDESCRIPTOR` is therefore available only before structured authority is installed. Once structured, all updates use `CONFIGURE` and the current authority path.

### Validation after execution

This proposal does not require every `VERIFY` frame to precede every execution frame. Post-execution assertions and revert-protection schemes remain an orthogonal EIP-8141 concern.

A `SENDER` frame still requires sender approval before it executes. A later `VERIFY` frame may assert a postcondition only where the active transaction and mempool rules permit such ordering.

## Backwards Compatibility

This proposal requires a network upgrade because it assigns special semantics to `0xef02`, adds an EIP-8141 frame mode, and introduces an EVM instruction.

EIP-3541 currently prevents newly deployed code beginning with `0xef`, so no currently deployable regular contract is reinterpreted as a structured account.

Pre-upgrade clients reject creation of these descriptors and do not understand `CONFIGURE` or `SETDESCRIPTOR`.

## Test Cases

Implementations MUST cover at least the following cases.

### Common descriptor parsing

1. Reject code not beginning with `0xef02` when parsed as structured code.
2. Reject a zero execution implementation.
3. Reject an unknown authority type.
4. Confirm the execution implementation is always read from bytes `3..22`.

### Inline root

1. Accept exactly `0xef0200 || execution_implementation || verifier || key_id` with valid nonzero fields.
2. Reject every length other than 75 bytes.
3. Accept a matching secp256k1 authentication result.
4. Reject another ECDSA address.
5. Accept a matching P-256 `keccak256(qx || qy)` key ID.
6. Accept a matching EIP-8397 authenticator and `key_id`.
7. Reject a matching `key_id` from a different verifier.
8. Reject an `ARBITRARY` signature entry as an inline root.

### Verification implementation

1. Accept exactly `0xef0201 || execution_implementation || verification_implementation` with nonzero addresses.
2. Reject every length other than 43 bytes.
3. Confirm a `VERIFY` frame loads verification code rather than execution code.
4. Confirm `ADDRESS` and storage context equal the structured account.
5. Confirm `CALLER == ENTRY_POINT` and calldata equals `frame.data` byte-for-byte.
6. Confirm `CODESIZE` observes verification implementation code while `EXTCODESIZE(ADDRESS)` observes 43 bytes.
7. Have the verification implementation read a signature with `SIGPARAM`, authorize it, call `APPROVE`, and succeed.
8. Return normally without `APPROVE` and reject the frame transaction under EIP-8141 rules.
9. Call `APPROVE` with a scope different from `frame.flags` and reject.
10. Call an external keystore, receive an authorization result, then call `APPROVE` from the account context.
11. Attempt to call `APPROVE` from the external keystore itself and reject it because the keystore is not the resolved target.
12. Verify that an `ARBITRARY` witness can be consumed through `SIGDATACOPY`.

### Execution separation

1. Confirm a `SENDER` or ordinary call executes `execution_implementation`, not `verification_implementation`.
2. Confirm ordinary delegated execution uses the structured account's address and storage.
3. Confirm changing execution-implementation code does not alter the descriptor's verification-implementation address.

### Configuration

1. Configure `INLINE_ROOT -> INLINE_ROOT` with a canonical-hash signature from the current root.
2. Configure `INLINE_ROOT -> VERIFY_IMPLEMENTATION` with the current root.
3. Execute the current verification implementation in `CONFIGURE` mode and accept exactly `CONFIGURE_SUCCESS`.
4. Reject a wrong-length or wrong-value configuration return.
5. Reject state writes attempted by the verification implementation during configuration.
6. Configure `VERIFY_IMPLEMENTATION -> INLINE_ROOT` after the verification implementation authorizes the exact new descriptor.
7. Configure `VERIFY_IMPLEMENTATION -> VERIFY_IMPLEMENTATION` and observe the new verification code in a later frame.
8. Reject configuration before payment is established.
9. Reject more than one `CONFIGURE` frame.
10. Reject `CONFIGURE` after a `SENDER` frame.
11. Place `CONFIGURE` and later execution in an atomic batch, fail the later frame, and restore the old descriptor.
12. Execute a non-atomic successful `CONFIGURE`, fail a later independent frame, and retain the new descriptor.

### Migration

1. Use `SETDESCRIPTOR` from regular account code and install a valid inline-root descriptor.
2. Use `SETDESCRIPTOR` while executing EIP-7702 delegated code and update the delegating account.
3. Install a verification-implementation descriptor from an existing smart account's authorized migration function.
4. Reject `SETDESCRIPTOR` from an already structured account.
5. Reject malformed descriptor input without changing code.
6. Confirm migration reverts when the containing frame reverts.

### Code replacement restrictions

1. Confirm EIP-7702 authorization cannot overwrite structured code.
2. Confirm EIP-8298 `SETCODEFROM` cannot replace a structured descriptor.
3. Confirm a structured descriptor cannot be used as an EIP-8298 source.

### Public mempool and direct evaluation

1. Simulate an unrecognized verification implementation under generic EIP-8141 rules.
2. Directly evaluate a recognized implementation and confirm identical success, gas, approval effects, and dependencies to EVM execution.
3. Change code at `verification_implementation` and revalidate pending transactions.
4. Confirm an L2 admission policy may reject an unrecognized verification code hash without changing block validity.
5. Confirm execution-implementation diversity does not affect recognition of the validation path.

## Security Considerations

### Inline-root compromise

The inline root has complete account authority. Compromise permits execution, payment, sponsorship, implementation replacement, authority-type replacement, and root rotation.

Wallets SHOULD protect an inline root as ultimate account authority.

### Verification-implementation correctness

A verification implementation defines the account's authorization policy. Code that accepts an unauthenticated witness, ignores the canonical transaction hash, misinterprets an external keystore result, or calls `APPROVE` with excessive scope compromises every account pointing to it.

Wallets and L2 fast paths MUST treat verification-implementation code as security-critical.

### Verification-implementation code changes

Authority type `0x01` stores a verification implementation address, not a code hash. If code at that address changes, account authorization semantics may change without changing the structured descriptor.

Wallets SHOULD use immutable verification implementations or treat upgrade authority over that address as equivalent to account root authority. Nodes MUST include the current verification code hash in validation caches and revalidate pending transactions after a change.

A later authority type may pin an expected verification code hash.

### Account-context execution

Verification code executes with the structured account as `ADDRESS` and with access to its storage. Static mode prevents writes during ordinary `VERIFY` and configuration authorization, but the code can read sensitive account state and can delegate to or call other code under the active EIP-8141 rules.

Libraries reached with `DELEGATECALL` execute in the same account context and can call `APPROVE`; they must be treated as fully trusted verification code.

### External authority contracts

An external keystore or verifier called by the verification implementation cannot itself approve the structured account. The verification implementation must validate the external return value and invoke `APPROVE` from the account context.

A malicious or upgradeable external authority contract can still cause the verification implementation to approve unauthorized actions if the adapter trusts its output. Its code and upgrade authority are part of the account's security boundary.

### Opaque calldata and wallet presentation

The protocol does not understand `frame.data` for authority type `0x01`. Wallets, explorers, and sequencers need implementation-specific parsers to explain which credential, keystore entry, or policy is being used.

Unknown verification implementations SHOULD be presented as unrecognized validation logic rather than decoded using another implementation's ABI.

### Configuration authorization

A verification implementation returning `CONFIGURE_SUCCESS` must bind its authorization to the exact proposed descriptor and transaction context. Validating a detached message that does not commit to the new descriptor, chain, account, and replay domain may allow unauthorized configuration or replay.

For inline roots, this EIP requires the canonical transaction signing hash, which commits to `frame.data`.

### Configuration ordering

A successful non-atomic `CONFIGURE` remains applied if an independent later frame fails. Wallets requiring all-or-nothing rotation and execution MUST place the relevant frames in an atomic batch.

### Migration authorization

`SETDESCRIPTOR` relies on the existing account code to decide who may reach the instruction. A bug in a pre-migration smart account or EIP-7702 implementation may permit unauthorized permanent migration.

After migration, `SETDESCRIPTOR` is disabled and only the structured configuration path may update authority.

### Execution-implementation risk

The execution implementation runs with the structured account's address, balance, and storage. Malicious execution code can transfer assets or corrupt wallet state during an authorized action.

It cannot directly replace an already structured descriptor through `SETDESCRIPTOR` or `SETCODEFROM`, but users must still treat implementation changes as full wallet-code upgrades.

### Client consistency

Clients must agree on descriptor parsing, type dispatch, authentication-result normalization, delegated verification context, `APPROVE` caller semantics, configuration return handling, code-replacement behavior, gas accounting, and rollback semantics. Divergence is consensus-critical.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
