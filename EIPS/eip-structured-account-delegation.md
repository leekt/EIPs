---
title: Structured Account Authority
description: Separate account execution code from protocol-readable typed authority.
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
|| authority_type       (1 byte)
|| implementation       (20 bytes)
|| authority_payload    (type-defined, fixed length)
```

The designator separates the code used for account execution from the authority model used to validate frame transactions. The execution implementation has the same position for every authority type, while `authority_type` selects a protocol-understood authorization backend.

Two authority types are defined initially:

```text
0x00 INLINE_ROOT
0xef0200
|| implementation       (20 bytes)
|| verifier             (20 bytes)
|| key_id               (32 bytes)
```

and:

```text
0x01 KEYSTORE
0xef0201
|| implementation       (20 bytes)
|| keystore             (20 bytes)
```

`INLINE_ROOT` is the common single-root case. Authentication resolves a `(verifier, key_id)` pair and protocol directly compares it with the descriptor.

`KEYSTORE` supports multiple actors without embedding an actor list in account code. Authentication resolves a `(verifier, key_id)` pair and protocol directly reads one actor-configuration slot from the named keystore. The keystore contract is not executed during validation.

Non-validation calls execute `implementation` in the structured account's context using one-hop delegation semantics. A `CONFIGURE` frame replaces the descriptor after direct admin authentication. A `SETDESCRIPTOR` instruction provides a one-way migration path from an existing non-structured account; it cannot update an account that is already structured.

## Motivation

EIP-8141 allows arbitrary account code to validate frame transactions. This preserves account programmability, but makes account authorization dependent on executing and tracing wallet code.

EIP-8397 separates expensive cryptographic authentication from account policy by producing authenticated credential identity before frame execution. That solves the expensive cryptography problem, but a general EIP-8141 account still decides authorization in arbitrary account code.

The common case should be statically understandable without forcing every account into one universal authority model. In particular:

- a simple account should be able to keep one root credential directly with the account;
- an account that needs multiple independently mutable actors, session keys, or expiry should be able to select a keystore authority model;
- both forms should use the same transaction transport and the same execution delegation semantics; and
- adding richer authority models later should not require changing the execution representation.

The structured account therefore acts as a tagged union:

```text
account code
  ├── authority type
  ├── execution implementation
  └── authority-type payload
```

For the inline-root case, one account-code fetch contains all authorization state. For the keystore case, validation requires exactly one additional account-specific keystore slot. No authority list is scanned and no wallet validation code is executed.

This proposal intentionally does not put spending limits, target allowlists, token hooks, recovery workflows, or application-specific session policies into the account descriptor. Those remain execution-layer concerns.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

### Constants

| Name | Value |
|---|---:|
| `STRUCTURED_ACCOUNT_MAGIC` | `0xef02` |
| `INLINE_ROOT` | `0x00` |
| `KEYSTORE` | `0x01` |
| `STRUCTURED_ACCOUNT_COMMON_LENGTH` | `23` |
| `INLINE_ROOT_CODE_LENGTH` | `75` |
| `KEYSTORE_CODE_LENGTH` | `43` |
| `ECRECOVER_VERIFIER` | `address(0x01)` |
| `P256_VERIFIER` | `address(0x100)` |
| `ROOT_VERIFY_DATA_LENGTH` | `4` |
| `CONFIGURE_MODE` | `0x03` |
| `SETDESCRIPTOR_OPCODE` | `TBD` |
| `STRUCTURED_VERIFY_BASE_GAS` | `500` |
| `CONFIGURE_BASE_GAS` | `5000` |
| `SETDESCRIPTOR_BASE_GAS` | `5000` |
| `KEYSTORE_ACTOR_DOMAIN` | `keccak256("STRUCTURED_ACCOUNT_KEYSTORE_ACTOR_V0")` |
| `SCOPE_SEND` | `0x0001` |
| `SCOPE_SELF_PAY` | `0x0002` |
| `SCOPE_SPONSOR_PAY` | `0x0004` |
| `SCOPE_KNOWN_MASK` | `0x0007` |

`STRUCTURED_VERIFY_BASE_GAS`, `CONFIGURE_BASE_GAS`, and `SETDESCRIPTOR_BASE_GAS` are provisional values pending client benchmarks.

### Structured account envelope

Every structured account begins with:

```text
0xef02
|| authority_type       (1 byte)
|| implementation       (20 bytes)
```

The byte offsets common to every authority type are:

| Bytes | Field |
|---|---|
| `0..1` | `STRUCTURED_ACCOUNT_MAGIC` |
| `2` | `authority_type` |
| `3..22` | `implementation` |
| `23..` | `authority_payload` |

The `implementation` MUST be nonzero.

`authority_type` is not a version number. It selects an authority backend with its own fixed payload format and authorization semantics. Multiple authority types may coexist at the same fork. An incompatible authority representation receives a new `authority_type` value.

Unknown authority types are invalid structured account code until assigned by a later EIP.

Conceptually:

```python
def parse_structured_account(code):
    assert len(code) >= STRUCTURED_ACCOUNT_COMMON_LENGTH
    assert code[0:2] == STRUCTURED_ACCOUNT_MAGIC

    authority_type = code[2]
    implementation = address(code[3:23])
    assert implementation != address(0)

    if authority_type == INLINE_ROOT:
        return parse_inline_root(code)
    if authority_type == KEYSTORE:
        return parse_keystore(code)

    invalid_structured_account()
```

### Authentication result

Structured authorization consumes a normalized authentication result:

```text
AuthenticationResult {
    verifier    address
    key_id      bytes32
}
```

The result is produced by protocol signature validation and is immutable for the remainder of the transaction.

For EIP-8141 signature schemes, normalization is:

| Signature scheme | `verifier` | `key_id` |
|---|---|---|
| `SECP256K1` | `ECRECOVER_VERIFIER` | recovered Ethereum address right-aligned in 32 bytes |
| `P256` | `P256_VERIFIER` | `keccak256(qx || qy)` |
| EIP-8397 `AUTHENTICATOR` | authenticator address | authenticated EIP-8397 `key_id` |

`ARBITRARY` does not produce a structured authentication result and cannot directly authorize a structured account.

For `P256`, `qx || qy` is the 64-byte public key contained in the protocol-validated signature entry. The EVM does not gain access to the raw signature bytes merely because protocol computes `key_id`.

Future protocol-validated signature schemes MAY define a `(verifier, key_id)` normalization through a later EIP.

### Authority type `0x00`: inline root

An inline-root account has exactly 75 bytes of code:

```text
0xef0200
|| implementation       (20 bytes)
|| verifier             (20 bytes)
|| key_id               (32 bytes)
```

The offsets are:

| Bytes | Field |
|---|---|
| `0..2` | `0xef0200` |
| `3..22` | `implementation` |
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

The configured `(verifier, key_id)` is the account's root authority. It is implicitly authorized for all structured-account protocol verbs:

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

### Authority type `0x01`: keystore

A keystore account has exactly 43 bytes of code:

```text
0xef0201
|| implementation       (20 bytes)
|| keystore             (20 bytes)
```

The offsets are:

| Bytes | Field |
|---|---|
| `0..2` | `0xef0201` |
| `3..22` | `implementation` |
| `23..42` | `keystore` |

A valid keystore descriptor requires:

```python
assert len(code) == KEYSTORE_CODE_LENGTH
assert code[0:3] == b"\xef\x02\x01"
assert address(code[3:23]) != address(0)
assert address(code[23:43]) != address(0)
```

The `keystore` address identifies the account whose storage contains actor configuration. Protocol does not execute keystore bytecode during structured validation.

#### Actor slot

For structured account `account` and authenticated `key_id`, the actor slot is:

```python
def actor_slot(account, key_id):
    return keccak256(
        KEYSTORE_ACTOR_DOMAIN
        + bytes32(uint256(uint160(account)))
        + key_id
    )
```

Protocol reads exactly one 32-byte word:

```text
state[keystore].storage[actor_slot(account, key_id)]
```

The word is packed as:

```text
verifier       (20 bytes)
valid_until    (6 bytes, uint48 big-endian)
scope          (2 bytes, uint16 big-endian)
reserved       (4 bytes)
```

A zero word means the actor is not authorized.

The actor configuration is valid only when:

- `verifier != address(0)`;
- the stored `verifier` equals the authentication result's `verifier`;
- `reserved == 0`; and
- `valid_until == 0` or `block.timestamp <= valid_until`.

#### Scope

`scope == 0x0000` denotes an admin actor. An admin actor satisfies every structured-account authorization purpose, including descriptor replacement.

For nonzero `scope`, the following grant bits are defined:

| Bit | Name | Meaning |
|---|---|---|
| `0x0001` | `SEND` | approve execution for this account |
| `0x0002` | `SELF_PAY` | approve payment when this account is the transaction sender |
| `0x0004` | `SPONSOR_PAY` | approve payment for another transaction sender |

Unknown scope bits grant no authority under this EIP. A future EIP may assign them additional meanings without changing the existing grants.

Authorization for an EIP-8141 `VERIFY` frame is:

```python
def authorize_keystore(descriptor, account, auth_result, approve_scope, tx, state):
    word = state[descriptor.keystore].storage[
        actor_slot(account, auth_result.key_id)
    ]
    config = decode_actor_config(word)

    assert config.verifier == auth_result.verifier
    assert config.reserved == 0
    assert config.valid_until == 0 or block.timestamp <= config.valid_until

    if config.scope == 0:
        return True

    required = 0

    if approve_scope & APPROVE_EXECUTION:
        required |= SCOPE_SEND

    if approve_scope & APPROVE_PAYMENT:
        if account == tx.sender:
            required |= SCOPE_SELF_PAY
        else:
            required |= SCOPE_SPONSOR_PAY

    return (config.scope & required) == required
```

A session key can therefore be represented as an actor with a non-admin scope and a finite `valid_until`. For example, an execution-only temporary session key uses `scope = SEND` and an expiry timestamp.

Stateful restrictions such as target allowlists, token spend limits, daily limits, or application-specific policies are deliberately not represented by these bits. They remain execution-layer policy after payment has been established.

#### Keystore mutation

This EIP standardizes the storage read required for frame authorization, not the complete keystore management API.

The contract at `keystore` is responsible for enforcing whatever update mechanism writes valid actor configuration into the canonical actor slots. A companion ERC or Core EIP may standardize signed actor changes, recovery, multichain updates, actor enumeration events, or additional storage used outside validation.

Because validation does not execute the keystore contract, changing keystore update logic does not change the validation algorithm as long as the canonical actor-slot contents remain compatible.

Wallets SHOULD use deterministic, audited keystore deployments. If keystore code is upgradeable, control over that upgrade is security-equivalent to control over every actor entry whose mutation it governs.

### EIP-8141 frame changes

The EIP-8141 frame-mode table is extended with:

| `mode` | Name | Summary |
|---|---|---|
| `0x03` | `CONFIGURE` | replace the sender's structured descriptor after admin authentication |

The static frame constraint becomes:

```python
assert frame.mode < 4
```

During dispatch, structured account code is recognized before ordinary EIP-7702 delegation handling:

```python
if frame.mode == CONFIGURE:
    execute_structured_configure(frame)
elif is_structured_account(resolved_target):
    if frame.mode == VERIFY:
        execute_structured_verify(frame)
    else:
        execute_structured_implementation(frame)
else:
    execute_existing_eip8141_dispatch(frame)
```

### Direct structured verification

A `VERIFY` frame targeting a structured account does not execute the account implementation.

Its `frame.data` contains exactly one unsigned 32-bit big-endian signature index:

```text
signature_index    (4 bytes)
```

The frame is valid only when:

1. `len(frame.data) == ROOT_VERIFY_DATA_LENGTH`.
2. `signature_index < len(tx.signatures)`.
3. The referenced signature uses the canonical frame-transaction signing hash, meaning `len(sig.msg) == 0`.
4. The referenced signature has a structured `AuthenticationResult`.
5. The current descriptor authorizes that authentication result for the frame's requested approval scope.
6. `frame.flags & APPROVE_SCOPE_MASK != 0`.
7. Every ordinary EIP-8141 structural rule for the requested approval scope holds.

On success, protocol applies the same effects as:

```text
APPROVE(frame.flags & APPROVE_SCOPE_MASK)
```

No account bytecode and, for `KEYSTORE`, no keystore bytecode is executed.

Conceptually:

```python
def execute_structured_verify(frame, tx, state):
    account = resolved_target(frame)
    descriptor = parse_structured_account(state[account].code)

    assert len(frame.data) == 4
    signature_index = int.from_bytes(frame.data, "big")
    assert signature_index < len(tx.signatures)

    sig = tx.signatures[signature_index]
    assert len(sig.msg) == 0

    auth_result = structured_authentication_result(sig)
    approve_scope = frame.flags & APPROVE_SCOPE_MASK
    assert approve_scope != 0

    if descriptor.authority_type == INLINE_ROOT:
        assert authorize_inline_root(descriptor, auth_result)
    elif descriptor.authority_type == KEYSTORE:
        assert authorize_keystore(
            descriptor,
            account,
            auth_result,
            approve_scope,
            tx,
            state,
        )
    else:
        invalid_transaction()

    apply_eip8141_approve(
        resolved_target=account,
        scope=approve_scope,
    )
```

### `CONFIGURE` frame

A structured account may replace its authority type, implementation, and authority payload through `CONFIGURE`.

`CONFIGURE` is authorized against the current descriptor, not the new descriptor.

Its frame data is:

```text
auth_signature_index    (4 bytes)
new_descriptor          (bytes beginning with 0xef02)
```

A `CONFIGURE` frame is valid only when:

1. `resolved_target == tx.sender`.
2. `tx.sender` currently contains a valid structured descriptor.
3. `payer != None` before the frame begins.
4. `frame.flags & APPROVE_SCOPE_MASK == 0`.
5. No undefined flag bit is set.
6. `frame.value == 0`.
7. `auth_signature_index < len(tx.signatures)`.
8. The referenced signature uses the canonical transaction signing hash.
9. The referenced signature produces a structured `AuthenticationResult`.
10. The current authority authorizes the authentication result for `ADMIN`.
11. `new_descriptor` is a valid structured descriptor under an active authority type.
12. At most one `CONFIGURE` frame appears in the transaction.
13. No `SENDER` frame precedes it.

Admin authorization is:

- for `INLINE_ROOT`, a matching `(verifier, key_id)`;
- for `KEYSTORE`, an actor whose configuration is valid and whose `scope == 0x0000`.

On success:

```python
state[tx.sender].code = new_descriptor
```

The new descriptor is visible to later frames in the same transaction and follows ordinary frame and atomic-batch rollback semantics.

The `ATOMIC_BATCH_FLAG` MAY be used with `CONFIGURE`. A wallet may therefore atomically rotate authority, change implementation, and execute under the new implementation.

A keystore session actor with `SEND` or payment scope cannot configure the account unless it is also the admin actor (`scope == 0`).

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

The current execution-context account is the account returned by `ADDRESS`. In particular, code reached through EIP-7702 delegation can migrate the delegating account.

State changes follow ordinary revert semantics.

`SETDESCRIPTOR` is deliberately disabled once an account is structured. Structured authority can then be changed only through `CONFIGURE`, so delegated execution code cannot bypass the current authority model.

### Execution delegation

For any code-executing operation targeting a structured account outside direct `VERIFY` and `CONFIGURE` handling, the EVM loads code from the descriptor's `implementation` and executes it in the structured account's context.

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
- `CODESIZE` and `CODECOPY` observe the loaded implementation code.

The implementation address is not code-hash pinned by this proposal. Changing code at the implementation address changes execution behavior but does not directly change authority data.

### Code installation and replacement restrictions

EIP-3541 is modified to permit creation-time installation of code beginning with `0xef02` only when the complete code is a valid structured descriptor under an authority type active at the current fork.

Unknown or malformed `0xef02` code remains invalid for contract creation.

EIP-7702 authorization processing MUST NOT overwrite a structured account. This follows from EIP-7702 accepting only empty code or an existing EIP-7702 delegation indicator.

EIP-8298 `SETCODEFROM` MUST fail without changing code when the current execution-context account is structured. Without this restriction, delegated execution code could replace the descriptor and bypass structured authority.

A structured descriptor MUST NOT be a valid source for EIP-8298 `SETCODEFROM`.

`SETDESCRIPTOR` MUST fail for an already structured account.

Any future account-code replacement mechanism MUST explicitly specify whether it can replace structured account code. The default is that it cannot.

### EIP-3607 transaction origination

Structured accounts have non-empty code and therefore cannot originate legacy ECDSA transactions under EIP-3607.

They originate frame transactions through structured direct authorization, or another future transaction type that explicitly recognizes this account format.

### Gas accounting

Structured authorization charges:

```text
STRUCTURED_VERIFY_BASE_GAS
+ ordinary resolved-target account access cost
+ the referenced signature's protocol-validation cost
```

For `KEYSTORE`, add the active cold/warm cost for the keystore account and one storage-slot read. No keystore EVM execution gas is charged because no keystore code executes during validation.

`CONFIGURE` charges `CONFIGURE_BASE_GAS` plus the active state/code-update charge for replacing the descriptor.

`SETDESCRIPTOR` charges `SETDESCRIPTOR_BASE_GAS` plus memory expansion and the active state/code-update charge.

Execution delegation charges implementation account access exactly as EIP-7702 charges delegated-code resolution.

### Public mempool handling

Structured `VERIFY` frames are directly evaluable.

For `INLINE_ROOT`, authorization dependencies are:

- the structured account's current code hash; and
- the referenced protocol-validated authentication result.

For `KEYSTORE`, authorization dependencies additionally include:

- the keystore address in the descriptor;
- exactly one actor slot `actor_slot(account, key_id)`; and
- the current block timestamp when `valid_until != 0`.

If the signature uses EIP-8397 `AUTHENTICATOR`, its verifier code hash remains an authentication dependency under EIP-8397.

Nodes SHOULD index pending transactions by these exact dependencies. An actor-slot change therefore invalidates transactions for that `(account, key_id)` rather than every account using the same keystore.

The `KEYSTORE` type does not permit arbitrary keystore storage reads during validation. Only the canonical actor slot defined by this EIP is read, bounding invalidation fan-out.

`CONFIGURE` requires payment to have been established and therefore executes after the public-mempool validation prefix.

## Rationale

### Why `authority_type` is not a version

`INLINE_ROOT` and `KEYSTORE` are not successive revisions of the same account. They are different authority backends that can coexist.

Using one type byte makes the account representation a tagged union and lets a later EIP add another authority model without changing execution delegation or reinterpreting existing accounts.

### Why implementation has a fixed offset

Every authority type keeps `implementation` at bytes `3..22`.

Code dispatch therefore does not need to understand authority payloads. Clients can resolve execution with the common header while validation dispatches on `authority_type`.

### Why inline root stores `(verifier, key_id)`

A fixed 32-byte key identifier avoids variable-length public keys in account code and matches authenticator-based identity models.

The verifier defines how a proof maps to `key_id`:

- ECDSA produces an address-derived identifier;
- P-256 produces a hash of the full public key;
- EIP-8397 authenticators return `key_id` directly; and
- future PQ or aggregate schemes can use the same 32-byte identity surface.

The descriptor remains 75 bytes regardless of cryptographic public-key size.

### Why keystore is a separate type

Putting multiple actors directly in account code would turn the descriptor into a miniature keystore and require rewriting account code every time a session key is added, expired, or revoked.

The `KEYSTORE` type keeps account code fixed while moving independently mutable actor state into keyed storage. Accounts that do not need this flexibility pay no additional state-read cost because they can use `INLINE_ROOT`.

### Why only one keystore slot is read

Public-mempool validation must avoid state changes that invalidate unbounded sets of pending transactions.

The actor slot is keyed by both structured account address and `key_id`. A change to one actor therefore has bounded impact even when many accounts share the same keystore contract.

### Session keys

A temporary session key is naturally represented by `KEYSTORE` rather than by another account-code entry:

```text
actor key_id
verifier
scope = SEND
valid_until = session expiry
```

This supports coarse protocol authorization and expiry without changing the structured descriptor.

Application-specific restrictions remain account execution policy. A later EIP may define a policy scope or a canonical way to bind an actor to a post-payment policy executor without changing the base structured-account envelope.

### Why custom cryptography is not another authority type

Cryptographic verification and account authorization are separate concerns.

EIP-8397 already provides a bounded custom-authentication path that resolves `(verifier, key_id)`. Both `INLINE_ROOT` and `KEYSTORE` consume that result. A new cryptographic scheme therefore does not require a new structured account authority type.

### Why `CONFIGURE` checks admin directly

Execution approval is not equivalent to account-administration authority once multiple actors exist.

A session actor may be permitted to send transactions but must not be able to replace the root authority or switch the account to another authority backend. `CONFIGURE` therefore performs a separate direct admin check against the current descriptor.

### Why `SETDESCRIPTOR` is one-way

Existing accounts need a migration path, but allowing the delegated implementation of an already structured account to replace its descriptor would put ultimate authority back into arbitrary execution code.

`SETDESCRIPTOR` is therefore usable only before structured authority is installed. After migration, `CONFIGURE` is the only update path defined by this EIP.

### Why not one mandatory keystore

Simple accounts should not pay an extra account and storage read merely to represent one root key.

Conversely, accounts that genuinely need multiple actors should not be forced to encode a mutable actor list in account code. Typed authority lets each account choose the appropriate representation while keeping the execution and transaction standards shared.

## Backwards Compatibility

This proposal requires a network upgrade because it assigns special semantics to `0xef02`, adds an EIP-8141 frame mode, and introduces an EVM instruction.

EIP-3541 currently prevents new deployed code starting with `0xef`, so no currently deployable regular contract is reinterpreted as a structured account.

Pre-upgrade clients reject creation of these descriptors and do not understand `CONFIGURE` or `SETDESCRIPTOR`.

## Test Cases

Implementations MUST cover at least the following cases.

### Common descriptor parsing

1. Reject code not beginning with `0xef02` when parsed as structured code.
2. Reject a zero implementation.
3. Reject an unknown authority type.
4. Confirm implementation is always read from bytes `3..22`.

### Inline root

1. Accept exactly `0xef0200 || implementation || verifier || key_id` with valid nonzero fields.
2. Reject every length other than 75 bytes.
3. Accept a matching secp256k1 authentication result.
4. Reject another ECDSA address.
5. Accept a matching P-256 `keccak256(qx || qy)` key ID.
6. Accept a matching EIP-8397 authenticator and `key_id`.
7. Reject a matching `key_id` from a different verifier.

### Keystore

1. Accept exactly `0xef0201 || implementation || keystore` with nonzero addresses.
2. Reject every length other than 43 bytes.
3. Install an actor slot and accept a matching `(verifier, key_id)`.
4. Reject an actor when the stored verifier differs.
5. Reject an expired actor.
6. Treat `scope == 0` as admin/full authority.
7. Accept `SEND` for execution and reject it for payment.
8. Accept `SELF_PAY` only when the keystore account is also `tx.sender`.
9. Accept `SPONSOR_PAY` for another sender.
10. Change one actor slot and confirm only transactions depending on that `(account, key_id)` require authorization revalidation.

### Session actor

1. Install a non-admin `SEND` actor with `valid_until` in the future and approve execution.
2. Advance the timestamp beyond `valid_until` and reject it.
3. Confirm the same actor cannot `CONFIGURE` the account.

### Configuration

1. Configure `INLINE_ROOT -> INLINE_ROOT` with the current root.
2. Configure `INLINE_ROOT -> KEYSTORE` with the current root.
3. Configure `KEYSTORE -> INLINE_ROOT` with an admin actor.
4. Configure `KEYSTORE -> KEYSTORE` with an admin actor.
5. Reject configuration by a non-admin keystore actor even if it has `SEND` and payment scopes.
6. Reject configuration before payment is established.
7. Confirm atomic-batch rollback restores the old descriptor when a later frame in the batch fails.

### Migration

1. Use `SETDESCRIPTOR` from regular account code and install a valid inline-root descriptor.
2. Use `SETDESCRIPTOR` while executing EIP-7702 delegated code and update the delegating account.
3. Reject `SETDESCRIPTOR` from a structured account.
4. Reject malformed descriptor input without changing code.
5. Confirm migration reverts when the containing frame reverts.

### Code replacement restrictions

1. Confirm EIP-7702 authorization cannot overwrite structured code.
2. Confirm EIP-8298 `SETCODEFROM` cannot replace a structured descriptor.
3. Confirm a structured descriptor cannot be used as an EIP-8298 source.

## Security Considerations

### Inline-root compromise

The inline root has complete account authority. Compromise permits execution, payment, sponsorship, implementation replacement, authority-type replacement, and root rotation.

Wallets SHOULD protect an inline root as ultimate account authority.

### Keystore admin compromise

A `KEYSTORE` admin actor can authorize every protocol verb and replace the structured descriptor. Compromise is equivalent to root compromise.

### Session actors

A `SEND` session actor grants unrestricted protocol-level execution approval. This EIP does not itself impose target or token-spend restrictions on such an actor.

Wallets requiring restricted sessions MUST enforce those restrictions in execution policy or use a later standardized policy mechanism.

### Keystore update security

Protocol reads actor configuration directly from keystore storage but does not define every method by which that storage is changed.

A bug or malicious upgrade in the keystore's mutation logic can therefore install unauthorized actors. Wallets must treat keystore code and its upgrade authority as part of their security boundary.

### Keystore storage collisions

Keystore implementations MUST reserve the canonical actor slots defined by this EIP and MUST NOT use those slots for unrelated state.

### Verifier identity

Authorization binds both `verifier` and `key_id`. Comparing only `key_id` would let another verifier claim the same identifier under different cryptographic semantics.

### Authenticator changes

When authentication uses EIP-8397, verifier code changes are handled by EIP-8397 authentication dependency and cache rules. Clients must not reuse cached authentication results across verifier code changes.

### Implementation risk

The delegated implementation executes with the structured account's address, balance, and storage. Malicious implementation code can transfer assets or corrupt wallet state during an authorized execution.

Structured authority prevents implementation code from directly replacing an already structured descriptor through `SETDESCRIPTOR` or `SETCODEFROM`, but users must still treat implementation changes as security-sensitive.

### Configuration ordering

A successful non-atomic `CONFIGURE` remains applied if an independent later frame fails. Wallets requiring all-or-nothing rotation and execution MUST place the relevant frames in an atomic batch.

### Client consistency

Clients must agree on descriptor parsing, authentication-result normalization, keystore slot derivation, actor-config decoding, scope semantics, expiry checks, direct approval effects, code-replacement behavior, and rollback semantics. Divergence is consensus-critical.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
