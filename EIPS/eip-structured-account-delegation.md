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

This proposal extends EIP-8141 with a structured-account code format that separates ordinary account execution from transaction authorization.

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

`VERIFY_IMPLEMENTATION` loads code from `verification_implementation` while retaining the structured account as the EVM execution context. The verification implementation receives frame calldata unchanged, chooses where and how authority state is stored, and invokes EIP-8141 `APPROVE` from the account context. Ordinary calls execute the independent `execution_implementation`.

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

The common single-root case requires no state lookup beyond the account descriptor. Richer accounts may select a dedicated verification implementation that uses account storage, a per-account authority contract, a shared keystore, immutable code data, a Merkle commitment, or another authority representation.

The core protocol deliberately does not select among those storage models. The chosen verification implementation owns its ABI, state layout, actor mapping, scope model, expiry model, and update mechanism. A chain may recognize selected verification implementation code hashes for public-mempool admission or equivalent direct evaluation without constraining the account's ordinary execution implementation.

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
| `STRUCTURED_VERIFY_BASE_GAS` | `500` |
| `CONFIGURE_BASE_GAS` | `5000` |

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

For a frame whose `resolved_target` is a structured account:

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

The code bytes are loaded directly from the selected implementation address without recursively resolving an EIP-7702 indicator or another structured descriptor at that address.

While the current frame mode is `VERIFY` or `CONFIGURE`, a nested code-executing operation targeting that frame's `resolved_target` MUST select the same verification implementation rather than the execution implementation. This prevents a self-call from switching the validation path into arbitrary wallet execution code.

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

The frame remains subject to EIP-8141 `VERIFY` semantics. Revert, exceptional halt, or failure to invoke the required approval makes the frame transaction invalid. The approved scope MUST be permitted by `frame.flags`.

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

### `CONFIGURE` frame

EIP-8141's frame mode table is extended with:

| `mode` | Name | Summary |
|---|---|---|
| `0x03` | `CONFIGURE` | install or replace a structured descriptor after authorization by the current account model |

The static frame constraint becomes:

```python
assert frame.mode < 4
```

A `CONFIGURE` frame targets `tx.sender`, carries no value or approval scope, and requires transaction payment to have already been established. The atomic-batch flag is permitted.

Its data is:

```text
new_descriptor_length   (2 bytes, uint16 big-endian)
new_descriptor          (new_descriptor_length bytes)
authorization_data      (remaining bytes)
```

The frame is structurally valid only when:

1. `resolved_target == tx.sender`.
2. `payer != None` before the frame begins.
3. `frame.flags & APPROVE_SCOPE_MASK == 0`.
4. no undefined flag bit is set.
5. `frame.value == 0`.
6. `new_descriptor` parses under an active authority type.
7. at most one `CONFIGURE` frame appears in the transaction.
8. no `SENDER` frame precedes it.

Authorization uses the current account model, not the proposed descriptor.

#### Installing from an unstructured account

If `tx.sender` is not yet structured:

- `sender_approved` MUST already be true;
- `authorization_data` MUST be empty; and
- the prior EIP-8141 validation path is treated as authorization to install the descriptor.

The canonical transaction signing hash commits to the complete frame list and proposed descriptor. A code-less sender may therefore install structured authority after default-account approval, and a frame-aware smart account may migrate after its existing validation code approves the transaction.

An existing account that cannot yet send EIP-8141 frame transactions requires an account-specific upgrade or migration path outside this proposal.

#### Replacing an inline-root descriptor

For `INLINE_ROOT`, `authorization_data` is one 4-byte signature index. The referenced canonical-hash signature MUST produce an `AuthenticationResult` matching the current inline root.

#### Replacing a verification-implementation descriptor

For `VERIFY_IMPLEMENTATION`, the current verification implementation executes in account context under `CONFIGURE_MODE`, static mode, and the complete `frame.data` calldata.

It may perform a root, admin, recovery, multisig, or keystore check. Authorization succeeds only when top-level execution returns exactly 32 bytes equal to `CONFIGURE_SUCCESS`.

`APPROVE` is invalid in `CONFIGURE` because the frame declares no approval scope. The verification implementation MUST bind its success to the exact new descriptor and any account, chain, nonce, or replay domain required by its authority model.

On success, protocol replaces `tx.sender` code with `new_descriptor`. The new descriptor is immediately visible to later frames and follows ordinary frame and atomic-batch rollback semantics.

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

A direct evaluator MUST reproduce equivalent EVM gas, warmness, returndata, failure behavior, and approval effects. Direct evaluation is an optimization, not a repricing.

`CONFIGURE` charges `CONFIGURE_BASE_GAS`, any current-authority verification cost, and the active code-write or state-growth charge for the new descriptor.

### Public mempool

An `INLINE_ROOT` `VERIFY` frame is directly evaluable from the account descriptor and referenced authenticated signature result.

A `VERIFY_IMPLEMENTATION` frame is consensus-valid by executing its selected code under EIP-8141 `VERIFY` semantics. Generic EIP-8141 public-mempool tracing rules apply unless a network recognizes an implementation-specific profile.

A chain MAY admit only verification implementations whose current runtime code hash belongs to a configured set. Such a policy applies to verification code, not arbitrary wallet execution code.

A code hash identifies the initial verification bytecode. A no-tracing profile additionally SHOULD specify any constraints required by that bytecode, including permitted external authority calls, bounded state dependencies, environmental dependencies, gas bounds, calldata parsing, and revalidation conditions. These are properties of the selected implementation profile, not fields of the structured account envelope.

A profile MAY provide an equivalent direct evaluator. The current runtime code hash at `verification_implementation` is always a validation dependency; pending transactions MUST be revalidated when it changes.

A verification implementation that calls an external keystore may be block-valid while failing the generic EIP-8141 public-mempool rule against external mutable storage. A companion profile or public-mempool EIP may admit the exact bounded external dependencies of a canonical actor-authority implementation.

Because `CONFIGURE` requires `payer != None`, descriptor installation and replacement occur outside the public-mempool validation prefix.

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

### Existing non-frame accounts

`CONFIGURE` can migrate code-less accounts and smart accounts that already support EIP-8141 validation. ERC-4337-only accounts that cannot approve a frame transaction still need an implementation-specific upgrade or migration path.

### Pre-validation authority changes

The current model validates existing authority before applying paid configuration. Atomic rotation and action are possible under the old authority, but first-use by a newly installed key and pre-validation actor changes require a separate construction.

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

### Why signatures remain in the EIP-8141 list

The signature list provides one location for protocol validation, witness elision, future aggregation, and signatures consumed during ordinary execution. Structured authority changes how authenticated results are authorized; it does not create a second signature container.

### Why configuration has a separate success result

Execution or payment approval does not imply root or recovery authority. A session actor may approve execution but must not necessarily replace the account descriptor. `CONFIGURE_SUCCESS` lets the current verification implementation apply its own admin or recovery rules without adding keystore-specific scopes to core protocol.

### Validation after execution

Account authority must be established before a `SENDER` frame. Post-execution assertions, zero-slippage protection, and similar revert-protection schemes are orthogonal and may be evaluated later where EIP-8141 ordering and public-mempool policy permit.

## Backwards Compatibility

This proposal requires a network upgrade because it assigns special semantics to `0xef02`, extends EIP-8141 signature introspection, and adds a frame mode.

EIP-3541 prevents newly deployed ordinary code beginning with `0xef`, so existing deployable EVM contracts are not reinterpreted as structured accounts.

Pre-upgrade clients reject structured descriptors and do not understand the new signature attributes or `CONFIGURE` mode.

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
7. Confirm an external authority contract cannot invoke `APPROVE` for the account.
8. Confirm verification code can validate the external result and invoke `APPROVE` itself.
9. Confirm ordinary `SENDER` execution uses `execution_implementation` rather than verification code.

### Configuration

1. Install structured authority from a code-less account after default-account approval and payment.
2. Install it from an unstructured frame-aware smart account after its existing validation approves the transaction.
3. Rotate an inline root with a canonical-hash signature from the current root.
4. Switch from inline root to verification implementation.
5. Authorize replacement through the current verification implementation and return `CONFIGURE_SUCCESS`.
6. Reject a configuration result not bound to the exact proposed descriptor.
7. Roll back configuration with a failed atomic batch.
8. Keep a successful non-atomic configuration when a later independent frame fails.

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

A verification implementation decides whether `APPROVE` or configuration succeeds. A bug that ignores the transaction hash, misparses a key ID, trusts an unauthenticated external result, or grants excessive scope compromises every account using it.

### Authority storage is implementation-defined

If verification reads authority from structured-account storage, ordinary execution code may be able to modify that state. If this is not intended, the verification implementation must use a protected external authority contract, immutable descriptor data, cryptographic commitments, or another design that prevents unauthorized execution-layer mutation.

### Verification implementation code changes

The descriptor names an address rather than a code hash. Code changes at that address alter authorization semantics. Nodes must revalidate pending transactions, and wallets should prefer immutable verification deployments or treat their upgrade authority as account root authority.

### Transitive code execution

Code reached through `DELEGATECALL` or `CALLCODE` runs with the structured account address and may invoke `APPROVE`. A chain recognizing only the top-level code hash must ensure that the selected implementation's transitive behavior satisfies its admission policy.

### External authority contracts

An external keystore or authority service cannot approve directly, but a malicious or upgradeable service can return forged authorization to an adapter that trusts it. Its code, state, and upgrade authority are part of the account's security boundary.

### Opaque calldata

Core protocol does not parse `frame.data` for `VERIFY_IMPLEMENTATION`. Wallets and explorers need a parser associated with the selected implementation or profile. Unknown verification code must not be decoded under another implementation's ABI.

### Configuration authorization

`CONFIGURE_SUCCESS` must be returned only after authorization commits to the exact new descriptor and any required account, chain, nonce, and replay domain. Detached or weakly bound admin signatures may permit replay or descriptor substitution.

### Legacy signatures

Installing structured authority disables legacy transaction origination but does not revoke message signatures recognized by third-party contracts. Descriptor rotation must not be represented as universal retirement of an old ECDSA identity.

### Client consistency

Clients must agree on descriptor parsing, authentication-result derivation, mode-sensitive code selection, account-context execution, `APPROVE` caller checks, configuration behavior, gas accounting, and rollback semantics. Divergence is consensus-critical.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
