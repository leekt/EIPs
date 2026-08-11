# EIP-8141 registered-static signature and VERIFY path

This document proposes a focused extension to EIP-8141. It is intended to be folded into `EIPS/eip-8141.md` after design review.

## Summary

Reserve signature scheme `0x03` as `REGISTERED_STATIC`.

A `REGISTERED_STATIC` signature identifies an account whose root credential is stored in a canonical registry. Clients read that bounded registry entry, verify the signature with protocol-defined secp256k1 or P256 logic, and cache the result before frame execution.

A `VERIFY` frame that consumes the validated `REGISTERED_STATIC` signature is evaluated directly by the protocol. The client checks the frame target and requested approval scope, applies the ordinary `APPROVE` effects, and does not load or execute the target account's code.

The separation is:

```text
signature scheme 0x03
    registry entry -> key type and public key
    witness + canonical tx hash -> valid or invalid

VERIFY frame
    target + requested scope + validated signature -> APPROVE effects
```

The signature does not modify transaction context merely by appearing in the signature list. Approval remains attached to a particular `VERIFY` frame. However, that frame has protocol-defined semantics and therefore requires no smart-account simulation.

## Motivation

EIP-8141 permits arbitrary EVM validation, but an L2 sequencer may be unable to safely admit a transaction when determining whether it approves execution or payment requires executing arbitrary account code. Proxy routing, validator modules, nonce lanes, and mutable dependencies can make the admission cost difficult to predict and create denial-of-service risk.

A canonical registry gives an account an explicit opt-in root-credential path. For that path, a node can decide validity with one bounded state lookup and one protocol-supported cryptographic operation. The account remains a full smart account for ERC-1271, callbacks, upgrades, modules, and normal execution; only the selected EIP-8141 verification frame bypasses account code.

## Constants

```python
REGISTERED_STATIC = 0x03

REGISTERED_KEY_K1 = 0x01
REGISTERED_KEY_R1 = 0x02

REGISTERED_STATIC_REGISTRY = address(TBD)
REGISTERED_STATIC_SLOT_COLD_COST = 2100
REGISTERED_STATIC_SLOT_WARM_COST = 100
```

`REGISTERED_STATIC_REGISTRY`, its runtime semantics, its storage layout, and its storage-slot derivation function are consensus constants. A client MUST NOT use an implementation-configured registry or transaction-selected registry.

A deployment may reuse the canonical account-configuration registry and slot derivation specified by EIP-8130, provided the resulting entry has the exact semantics below.

## Registry entry

Version 0 defines one registered static root credential per account:

```python
@dataclass(frozen=True)
class RegisteredStaticKey:
    key_type: int
    key_data: Bytes
    allowed_scope: int
    valid_after: int
    valid_until: int
    reserved: int
```

The canonical registry exposes the conceptual lookup:

```python
def registered_static_key(account: Address) -> RegisteredStaticKey
```

This is a direct consensus state lookup. It is not an EVM call and does not execute registry or account code.

The supported key encodings are:

| `key_type` | `key_data` | Signature witness |
|---|---|---|
| `REGISTERED_KEY_K1` | 20-byte Ethereum address | `v || r || s` (65 bytes) |
| `REGISTERED_KEY_R1` | `qx || qy` (64 bytes) | `r || s` (64 bytes) |

For K1, the registry stores the address expected from `ecrecover`. For R1, the registry stores the complete affine public key so the transaction does not need to repeat it.

`allowed_scope` uses the EIP-8141 approval-scope bit values. A registry implementation MAY import EIP-8130's sender, self-payer, and sponsor-payer scope model, but the mapping to EIP-8141 approval requests MUST be consensus-defined.

`valid_after == 0` means immediately valid. `valid_until == 0` means no expiry. `reserved` MUST be zero.

Only the account itself may create, replace, or revoke its entry. Registration is therefore the account's explicit opt-in to the following rule:

> A live signature from the registered root credential may authorize EIP-8141 execution or payment without executing the account's validation code.

## Signature object

The existing signature object shape is unchanged:

```text
[scheme, signer, msg, signature]
```

For `REGISTERED_STATIC`:

- `scheme` is `0x03`.
- `signer` is the account whose canonical registry entry is authoritative. If empty, `tx.sender` is used.
- `msg` follows the existing EIP-8141 rules. Direct frame approval requires it to be empty, meaning the signature authorizes `compute_sig_hash(tx)`.
- `signature` contains only the witness encoding selected by the registered key type.

The account address and scheme remain committed by `compute_sig_hash(tx)`. For an empty `msg`, the raw witness bytes are elided in the same manner as other protocol-validated signatures.

### Static shape checks

```python
for sig in tx.signatures:
    if sig.scheme == REGISTERED_STATIC:
        assert len(sig.signer) == 0 or len(sig.signer) == 20
        # The exact witness length is checked after the registry lookup,
        # because key_type is canonical registry state.
```

## Signature validation

Signature-list validation occurs before frame execution. Consequently, the registry subject is `resolved_signer`, not a currently executing frame field. The later direct-VERIFY rule binds the result to the frame's `resolved_target`.

```python
@dataclass(frozen=True)
class RegisteredStaticValidation:
    account: Address
    key_type: int
    allowed_scope: int
    valid_after: int
    valid_until: int
    storage_slot: Bytes32

@dataclass(frozen=True)
class SignatureValidation:
    registered_static: Optional[RegisteredStaticValidation] = None


def validate_registered_static(sig, tx_sender, msg, state):
    if len(sig.signer) == 0:
        account = tx_sender
    elif len(sig.signer) == 20:
        account = sig.signer
    else:
        return None

    storage_slot = registered_static_slot(account)
    config = state.sload(REGISTERED_STATIC_REGISTRY, storage_slot)

    if config.is_empty or config.reserved != 0:
        return None
    if config.valid_after != 0 and block.timestamp < config.valid_after:
        return None
    if config.valid_until != 0 and block.timestamp > config.valid_until:
        return None

    if config.key_type == REGISTERED_KEY_K1:
        if len(config.key_data) != 20 or len(sig.signature) != 65:
            return None

        v = sig.signature[0]
        r = int.from_bytes(sig.signature[1:33], "big")
        s = int.from_bytes(sig.signature[33:65], "big")

        if v > 1:
            return None
        if not (0 < r < SECP256K1N):
            return None
        if not (0 < s <= SECP256K1N // 2):
            return None

        recovered = ecrecover(msg, v, r, s)
        if recovered == address(0) or recovered != config.key_data:
            return None

    elif config.key_type == REGISTERED_KEY_R1:
        if len(config.key_data) != 64 or len(sig.signature) != 64:
            return None

        r = int.from_bytes(sig.signature[0:32], "big")
        s = int.from_bytes(sig.signature[32:64], "big")
        qx = config.key_data[0:32]
        qy = config.key_data[32:64]

        if not (0 < r < SECP256R1N):
            return None
        if not (0 < s <= SECP256R1N // 2):
            return None
        if not P256VERIFY(msg, r, s, qx, qy):
            return None

    else:
        return None

    return SignatureValidation(
        registered_static=RegisteredStaticValidation(
            account=account,
            key_type=config.key_type,
            allowed_scope=config.allowed_scope,
            valid_after=config.valid_after,
            valid_until=config.valid_until,
            storage_slot=storage_slot,
        )
    )
```

This is equivalent to the following high-level dispatch:

```python
if sig.scheme == REGISTERED_STATIC:
    key_type, public_key = CANONICAL_REGISTRY.fetch(resolved_signer)

    if key_type == REGISTERED_KEY_K1:
        validate_as_secp256k1(msg, public_key, sig.signature)
    elif key_type == REGISTERED_KEY_R1:
        validate_as_p256(msg, public_key, sig.signature)
    else:
        invalid_transaction()
```

Clients MAY implement the cryptographic routines natively or through an equivalent enshrined primitive. Consensus validity and gas charging MUST be identical.

No account code, proxy implementation, validation module, or arbitrary authenticator contract is read or executed by this validation path.

## Direct registered-static VERIFY frame

A `VERIFY` frame is a **direct registered-static VERIFY frame** when the deterministic signature entry selected for that frame has `scheme == REGISTERED_STATIC`.

Version 0 preserves the existing deterministic signature-index convention:

```python
def signature_index_for_verify(frame):
    requested_scope = frame.flags & APPROVE_SCOPE_MASK
    if requested_scope & APPROVE_EXECUTION:
        return 0
    return 1
```

A direct registered-static VERIFY frame MUST satisfy:

- `frame.mode == VERIFY`;
- `frame.value == 0`;
- `frame.data` is empty;
- the atomic-batch flag is not set;
- `requested_scope = frame.flags & APPROVE_SCOPE_MASK` is not zero;
- the selected signature exists and has `scheme == REGISTERED_STATIC`;
- the selected signature has empty `msg`;
- the selected validation result's `account` equals the frame's `resolved_target`;
- the requested scope is permitted by the registry entry; and
- all ordinary `APPROVE(requested_scope)` preconditions hold.

The frame is evaluated as follows:

```python
def evaluate_registered_static_verify(tx, frame, validation_results):
    assert frame.mode == VERIFY
    assert frame.value == 0
    assert frame.data == Bytes()
    assert not (frame.flags & ATOMIC_BATCH_FLAG)

    resolved_target = (
        tx.sender if frame.target is None else frame.target
    )
    requested_scope = frame.flags & APPROVE_SCOPE_MASK
    if requested_scope == APPROVE_NONE:
        invalid_transaction()

    sig_index = signature_index_for_verify(frame)
    if sig_index >= len(tx.signatures):
        invalid_transaction()

    sig = tx.signatures[sig_index]
    result = validation_results[sig_index].registered_static

    if sig.scheme != REGISTERED_STATIC or result is None:
        # Not a direct registered-static frame. Execute the ordinary
        # EIP-8141 VERIFY path instead.
        return NOT_APPLICABLE

    if sig.msg != Bytes():
        invalid_transaction()
    if result.account != resolved_target:
        invalid_transaction()
    if not registry_scope_allows(
        result.allowed_scope,
        requested_scope,
        resolved_target,
        tx.sender,
    ):
        invalid_transaction()

    # Apply exactly the existing APPROVE state-transition rules.
    apply_approve(resolved_target, requested_scope)
    return SUCCESS
```

When the function returns `SUCCESS`:

- the client MUST NOT read or execute `resolved_target` account code;
- the client MUST NOT execute an EVM `STATICCALL` for the frame;
- the frame succeeds with empty return data and no logs;
- the receipt records a successful frame;
- the frame's EVM gas used is zero; and
- registry access and signature verification are charged through the signature-verification cost described below.

When the function returns `NOT_APPLICABLE`, the existing EIP-8141 behavior is unchanged and the target account's ordinary `VERIFY` code executes.

This direct path applies to accounts with deployed code and to EIP-7702 delegated accounts. The presence, implementation, proxy shape, or code hash of the account does not alter the registered-static authorization result.

## Approval scope

`registry_scope_allows` MUST be defined in consensus. A version importing EIP-8130 scopes can use:

```python
def registry_scope_allows(scope, requested, target, sender):
    if scope & EIP8130_SCOPE_POLICY:
        return False

    if requested & APPROVE_EXECUTION:
        if target != sender:
            return False
        if scope != 0 and not (scope & EIP8130_SCOPE_SENDER):
            return False

    if requested & APPROVE_PAYMENT:
        if target == sender:
            if scope != 0 and not (scope & EIP8130_SCOPE_SELF_PAYER):
                return False
        else:
            if scope != 0 and not (scope & EIP8130_SCOPE_SPONSOR_PAYER):
                return False

    return True
```

`POLICY` actors are excluded because direct evaluation cannot enforce an external policy manager or per-call restrictions.

A first implementation MAY further restrict the direct path to `resolved_target == tx.sender` and approval scopes containing `APPROVE_EXECUTION`. That narrower form covers sender verification while leaving registered external payers to a separate guarantor or payer proposal.

## Relationship to default code

Default code and direct registered-static verification share the same signature selection, target binding, empty-message requirement, scope checks, and `APPROVE` effects.

The difference is only account-code presence:

- existing default code provides protocol-defined verification when the target has no code;
- this extension provides protocol-defined verification for a smart account that has opted into the canonical registry.

Implementations SHOULD share one helper for consuming a registered-static signature so the two paths cannot diverge.

## Gas accounting

The validation cost is bounded by one exact registry-slot access and one supported cryptographic operation.

```python
def registered_static_signature_gas(config, slot_was_warm):
    access_cost = (
        REGISTERED_STATIC_SLOT_WARM_COST
        if slot_was_warm
        else REGISTERED_STATIC_SLOT_COLD_COST
    )

    if config.key_type == REGISTERED_KEY_K1:
        return access_cost + 2800
    if config.key_type == REGISTERED_KEY_R1:
        return access_cost + 6700
    invalid_transaction()
```

The cost is included in the transaction signature-verification cost and in `MAX_VERIFY_GAS`. A deployment that prefers a transaction-derived fixed cost MAY charge every `REGISTERED_STATIC` signature the maximum supported branch, but it must specify that rule as consensus behavior.

The direct VERIFY frame consumes no EVM execution gas. Its transaction-context effects are charged consistently with existing EIP-8141 `APPROVE` handling.

## Public mempool

A direct registered-static VERIFY frame is a protocol-defined frame. Nodes may evaluate it directly without simulating the target smart account.

The dependency set for each `REGISTERED_STATIC` signature is:

```text
(REGISTERED_STATIC_REGISTRY, registered_static_slot(account))
entry validity timestamps
current block timestamp when a time bound is present
```

The usual sender nonce and payer balance dependencies still apply.

Nodes MUST index pending transactions by the exact registry slot. A mutation of that slot or passage outside its validity interval triggers revalidation or eviction without executing account code.

One registry slot may otherwise invalidate transactions from many senders, especially when used by an external payer. Public-mempool policy MUST bound that fanout. A conservative rule is:

```text
MAX_PENDING_TXS_PER_REGISTERED_STATIC_SLOT = 1
```

This is a propagation rule, not a consensus-validity rule. A sender-only deployment may rely additionally on EIP-8141's one-pending-transaction-per-sender policy.

For public relay, every `REGISTERED_STATIC` entry SHOULD:

- use empty `msg`;
- be consumed by a direct registered-static VERIFY frame in the validation prefix;
- not appear unused or only after payer approval; and
- remain within the total `MAX_VERIFY_GAS` budget.

## Key rotation and revocation

Replacing or revoking an account's registry entry immediately changes consensus validation against the next state. Pending transactions signed by the old key become invalid and must be evicted when the exact slot is touched.

Version 0 deliberately supports one active static root credential per account. This avoids an unsigned or ambiguously committed key selector. A future multi-key extension MUST place `credential_id` in signature metadata that remains committed by `compute_sig_hash(tx)`; placing it only in elided witness bytes is insufficient.

## Deployment behavior

A direct registered-static transaction requires the registry entry to exist in pre-execution state. Version 0 does not allow a deployment frame to create the registry entry and then use it to validate the same transaction.

A future extension may define a deterministic deployment-and-registration path, but it must preserve bounded admission work and unambiguous authorization.

## Security considerations

### Registry authority is root authority

The account's registry write explicitly installs a root authorization path. Once a direct frame grants `APPROVE_EXECUTION`, all subsequent `SENDER` frames are authorized under existing EIP-8141 semantics.

For this reason direct approval requires `sig.msg` to be empty: the signature then commits to the canonical transaction hash and the complete frame list. An explicit digest cannot authorize this path.

### Account code is intentionally bypassed

The account cannot override or add checks to a direct registered-static frame through its runtime code. This is the feature that makes validation bounded, but it also means a registered root key bypasses multisig thresholds, spending limits, session policies, guardians, and validator modules unless those restrictions are represented by the canonical registry semantics.

Accounts should register only credentials intended to have that authority. Complex authorization continues to use the ordinary EVM `VERIFY` path.

### Canonical registry only

A transaction-selected registry, arbitrary authenticator address, or node-local allowlist would allow nodes to disagree about validity or reintroduce unbounded code execution. The registry address, supported key types, encodings, verification rules, and gas costs must all be consensus constants.

### State-dependent validity

The registry is mutable state. Key rotation, revocation, expiry, or account-controlled scope changes invalidate pending transactions. Exact-slot dependency indexing and bounded per-slot mempool exposure are therefore required.

### Unsupported key types

Any key type other than K1 or R1 is invalid in version 0. Adding WebAuthn, post-quantum, aggregate, or other schemes requires a separate consensus change defining its key encoding, witness encoding, verification routine, gas charge, and aggregation/introspection behavior.

## Backwards compatibility

Transactions without `REGISTERED_STATIC` signatures are unchanged.

Smart accounts that do not register a static root credential continue to execute their ordinary `VERIFY` code.

Registration is opt-in and does not alter ERC-1271, callbacks, upgrades, or execution behavior outside direct EIP-8141 verification frames.

## Open questions

1. Whether the first version should support registered external payers or only sender/self-payer approval.
2. Whether to reuse EIP-8130's actor configuration slot exactly or define a smaller one-root-key entry.
3. Whether gas should be charged by the state-selected key type or at a fixed maximum registered-static cost.
4. Whether `0x03` should be named `REGISTERED_STATIC`, `EIP8130_ACTOR`, or another registry-neutral term.
5. Whether deterministic signature indices are sufficient or a future committed signature-index field should be introduced.
