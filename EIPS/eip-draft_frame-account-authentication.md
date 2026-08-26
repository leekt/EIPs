---
title: Frame Authenticator Signatures
description: Adds a bounded, state-independent authenticator signature scheme to frame transactions.
author: Taek (@leekt)
discussions-to: TBD
status: Draft
type: Standards Track
category: Core
created: 2026-08-26
requires: 2929, 7702, 7928, 8141
---

## Abstract

This proposal extends [EIP-8141](./eip-8141.md) with an `AUTHENTICATOR` signature scheme. The signature entry's `signer` is an authenticator contract. The protocol executes the authenticator in a bounded, state-independent context; it verifies the proof against the digest and returns the authenticated key identifier. Account code then authorizes `(authenticator, key_id)` under its own policy inside its `VERIFY` frame.

```text
signature.signer = authenticator
        |
        | authenticate(digest, proof)
        v
     key_id
        |
        v
account VERIFY frame authorizes (authenticator, key_id)
        |
        v
     APPROVE
```

## Motivation

EIP-8141 validates secp256k1 and P-256 signatures in protocol. Any other scheme must be carried as `ARBITRARY` and verified by account code inside a `VERIFY` frame. This mixes expensive state-independent cryptography with cheap stateful account authorization, and makes the expensive work hard for a sequencer to bound or cache independently of account state.

`AUTHENTICATOR` moves only the expensive, state-independent part into protocol validation. Registration, rotation, and revocation of keys remain stateful account policy and stay in the `VERIFY` frame, where EIP-8141 already bounds and tracks them.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

This specification is a delta against EIP-8141.

### Constants

| Name | Value |
|---|---:|
| `AUTHENTICATOR` | `0x03` |
| `AUTHENTICATOR_HEADER_LENGTH` | `32` |
| `AUTHENTICATOR_BASE_COST` | `2600` |
| `AUTHENTICATOR_GAS_LIMIT` | `50000` |
| `AUTHENTICATOR_COST` | `52600` |

`AUTHENTICATOR_HEADER_LENGTH` is the length of `key_id`. `AUTHENTICATOR_BASE_COST` conservatively charges one cold account access under [EIP-2929](./eip-2929.md) for the authenticator. `AUTHENTICATOR_COST = AUTHENTICATOR_BASE_COST + AUTHENTICATOR_GAS_LIMIT` is the fixed, protocol-defined cost of one `AUTHENTICATOR` signature; the transaction does not choose the authenticator gas budget.

### Transaction structural changes

The EIP-8141 signature-scheme table is extended with:

| `scheme` | Name | `signer` encoding | `signature` encoding | Gas cost |
|---|---|---|---|---|
| `0x03` | `AUTHENTICATOR` | 20-byte authenticator address | `key_id || proof` | `AUTHENTICATOR_COST` |

Values `0x04` through `0xff` remain reserved.

EIP-8141's static constraints are extended equivalently to:

```python
for sig in tx.signatures:
    if sig.scheme == AUTHENTICATOR:
        assert len(sig.signer) == 20
        assert len(sig.signature) >= AUTHENTICATOR_HEADER_LENGTH
    # Existing scheme-specific constraints remain unchanged.
```

### `AUTHENTICATOR` signature scheme

#### Wire format

```text
[scheme, signer, msg, signature]

scheme    = AUTHENTICATOR
signer    = authenticator address     (20 bytes)
signature = key_id                    (32 bytes)
         || proof                     (variable bytes)
```

```python
authenticator = address(sig.signer)
key_id = sig.signature[0:32]
proof = sig.signature[32:]
```

The `signer` MUST be present and MUST be the authenticator; unlike `SECP256K1` and `P256`, an absent `signer` does not default to `tx.sender`. The `msg` field retains the EIP-8141 meaning: an empty value selects the canonical frame-transaction signature hash and a 32-byte value selects that explicit digest.

An `AUTHENTICATOR` signature is structurally valid only if:

```python
assert len(sig.signer) == 20
assert authenticator != address(0)
assert len(sig.signature) >= AUTHENTICATOR_HEADER_LENGTH
assert key_id != bytes32(0)
```

The authenticator MUST contain regular deployed code, MUST NOT be a precompile, and MUST NOT contain an [EIP-7702](./eip-7702.md) delegation indicator. The code currently deployed at the address is what runs.

#### Authenticator execution

```solidity
pragma solidity ^0.8.0;

interface IFrameAuthenticator {
    function authenticate(bytes32 digest, bytes calldata proof)
        external
        view
        returns (bytes32 keyId);
}
```

The protocol calls `authenticate(digest, proof)` in the [pure authentication context](#pure-authentication-context) with `AUTHENTICATOR_GAS_LIMIT` gas. The authenticator MUST derive the key identity from the proof and return it. The call MUST return exactly 32 bytes equal to the `key_id` in the signature. A zero or different result, malformed return data, revert, exceptional halt, out-of-gas condition, or forbidden operation makes the signature invalid.

#### Signature validation

```python
def validate_authenticator(sig, sig_hash, state):
    authenticator, key_id, proof = parse_authenticator(sig)

    if len(sig.msg) == 0:
        digest = sig_hash
    elif len(sig.msg) == 32 and sig.msg != bytes32(0):
        digest = sig.msg
    else:
        return INVALID

    require_regular_code(state, authenticator)

    resolved_key_id = pure_authenticator_call(
        target=authenticator,
        calldata=abi_encode_authenticate(digest, proof),
        gas=AUTHENTICATOR_GAS_LIMIT,
    )
    if resolved_key_id != key_id:
        return INVALID

    return VALID(resolved_signer=authenticator)
```

`SIGPARAM(0x00)` returns the authenticator address because the authenticator is the entry's resolved `signer`.

EIP-8141's `compute_sig_hash` is not modified. For a canonical-hash `AUTHENTICATOR` entry the entire `signature` field is elided exactly like every other EIP-8141 witness, so `key_id` and `proof` are intentionally unsigned, replaceable witness data. Their integrity comes from the validation chain: `proof` must authenticate under the named authenticator, the `key_id` the authenticator derives from the proof must equal the claimed one, and the verifying account must have authorized `(authenticator, key_id)` for itself.

Unlike `SECP256K1` and `P256`, `AUTHENTICATOR` signatures are introspectable: `SIGDATACOPY` and `SIGPARAM(0x03)` are defined for `AUTHENTICATOR` entries exactly as for `ARBITRARY`, over the full `signature` bytes.

There is no fallback from `AUTHENTICATOR` to `ARBITRARY`, account-code signature verification, or another signature scheme.

### Pure authentication context

Authenticator execution is expensive, state-independent, and bounded. Its top-level environment is:

| Property | Value |
|---|---|
| `ADDRESS` | authenticator address |
| `CALLER` | EIP-8141 `ENTRY_POINT` |
| `CALLVALUE` | `0` |
| calldata | ABI-encoded `authenticate(digest, proof)` |
| static mode | enabled |
| gas limit | `AUTHENTICATOR_GAS_LIMIT` |

Every opcode not listed as forbidden below is allowed, including `GAS`, `CHAINID`, `ADDRESS`, `CALLER`, `CALLVALUE`, and code-local `CODESIZE` and `CODECOPY`.

The following operations are forbidden and make the signature invalid:

- world-state reads or writes: `BALANCE`, `SELFBALANCE`, `SLOAD`, `SSTORE`, `TLOAD`, `TSTORE`, `EXTCODESIZE`, `EXTCODECOPY`, `EXTCODEHASH`, and `SELFDESTRUCT`;
- block-dependent reads: `BLOCKHASH`, `COINBASE`, `TIMESTAMP`, `NUMBER`, `PREVRANDAO`, `GASLIMIT`, `BASEFEE`, `BLOBHASH`, and `BLOBBASEFEE`;
- transaction-price or origin reads: `GASPRICE` and `ORIGIN`;
- contract creation or non-precompile calls: `CREATE`, `CREATE2`, `CALL`, `CALLCODE`, and `DELEGATECALL`;
- logs: `LOG0` through `LOG4`.

`STATICCALL` is allowed only when its target is an active protocol precompile. A `STATICCALL` to any other address makes the signature invalid. Precompile gas charging and return behavior are unchanged.

An opcode introduced after this proposal is forbidden in the pure authentication context unless a later EIP explicitly permits it.

### Access accounting

Signature validation runs before any frame. It does not read or modify the transaction's `accessed_addresses` or `accessed_storage_keys`. The authenticator is cold in the first frame that touches it, exactly as if signature validation had not run.

Validation accesses do not appear in the block-level access list. As with EIP-8141's native signature schemes, signature validation does not happen in EVM execution.

### Signature gas and data accounting

Existing EIP-8141 signature schemes retain their existing costs. For `AUTHENTICATOR`, `signature_gas(sig) = AUTHENTICATOR_COST`. The complete fixed amount is execution gas and is charged if the signature validates, even when the call returns with unused gas. It is also used in maximum transaction cost, payer reservation, and public-mempool verification-gas accounting.

Because the `signature` field is not committed by the canonical hash, its bytes are charged at the worst-case nonzero-byte rate so that the payer's fee does not depend on witness contents:

```python
def authenticator_signature_tokens(sig):
    return 4 * len(sig.signature)
```

When EIP-8141 computes `signature_data_cost` and `calldata_tokens`, it MUST use `authenticator_signature_tokens(sig)` in place of `tokens_in(sig.signature)` for `AUTHENTICATOR`. The `signer` and `msg` fields retain ordinary transaction-data pricing. The fee still depends on the witness length; an authenticator SHOULD reject a proof whose length is not exactly what its scheme requires, so that a relayer cannot pad the proof.

### Account authorization

No new `SIGPARAM` value is introduced. Account code reads the authenticator with `SIGPARAM(0x00)` and `key_id` with `SIGDATACOPY`. A minimal shape is:

```solidity
pragma solidity ^0.8.0;

interface IFrameAccount {
    function validateFrame(uint256 signatureIndex) external;
}
```

conceptually doing:

```text
require(SIGPARAM(0x01, signatureIndex) == AUTHENTICATOR)
require(SIGPARAM(0x02, signatureIndex) == 0)   // canonical transaction hash
authenticator = SIGPARAM(0x00, signatureIndex)
key_id = SIGDATACOPY(signatureIndex, 0, 32)
require(isAuthorized[authenticator][key_id])
APPROVE(scope)
```

An account MAY delegate the `isAuthorized` lookup to an external keystore contract via `STATICCALL` inside its `VERIFY` frame; that call is ordinary frame execution under EIP-8141's existing gas and public-mempool rules. Key rotation policy, recovery, guardians, sessions, locks, storage layout, and wallet presentation are not standardized here; they belong to account implementations or a companion ERC.

### Public mempool

Consensus validity and public-mempool eligibility are separate: every rule in this section is mempool policy and never affects block validity.

`AUTHENTICATOR` validation counts `AUTHENTICATOR_COST` toward EIP-8141's `MAX_VERIFY_GAS`, not observed execution gas.

The only validation dependency of a pending `AUTHENTICATOR` transaction is the authenticator address and its current code. Authenticator execution creates no mutable state dependency. Nodes MUST revalidate pending `AUTHENTICATOR` transactions when the authenticator's code changes.

Consensus places no restriction on which authenticator an `AUTHENTICATOR` signature names. Which ones a node propagates, and which ones a block builder or sequencer includes, is that node's own policy. Each node, builder, or sequencer MAY select its own accepted set of authenticators, identified by address or by runtime code, and MAY reject or deprioritize any `AUTHENTICATOR` transaction outside that set without affecting the transaction's validity elsewhere. Because authenticator execution is state-independent and gas-bounded, a node that admits every authenticator is exposed to at most `AUTHENTICATOR_GAS_LIMIT` of wasted work per invalid signature, comparable to an `ARBITRARY` signature verified in a `VERIFY` frame.

An account that does not want its authentication path subject to builder or sequencer selection is not forced through `AUTHENTICATOR`. It can carry the same proof as an `ARBITRARY` signature and verify it in account code during its `VERIFY` frame under EIP-8141's generic public-mempool rules, at the cost of executing the authentication itself.

## Rationale

### Two layers

The scheme separates two operations with different cost and state profiles:

1. Authenticator execution: expensive, state-independent, bounded by `AUTHENTICATOR_GAS_LIMIT`.
2. Account authorization: cheap, stateful, account-specific, inside the ordinary `VERIFY` frame.

The authenticator proves possession of a key. The account decides whether `(authenticator, key_id)` is currently authorized. Sequencers can cache authentication by `(authenticator, digest, proof)` and re-run only the stateful `VERIFY` frame when account state changes.

### Why `signer` is the authenticator

EIP-8141's `signer` identifies the verifying identity of a protocol-validated entry: the recovered address for `SECP256K1`, the public key for `P256`. For `AUTHENTICATOR` the verifying identity is the authenticator code together with the key it derives, so `signer = authenticator` and the witness carries `key_id`. Registration authority is not a property of the signature; it is account policy, and EIP-8141 already places account policy in the `VERIFY` frame.

### Why there is no in-protocol keystore step

An earlier draft resolved `(account, key_id)` to an authenticator through a keystore contract during signature validation. That step is cheap and stateful, exactly the kind of work `VERIFY` frames already handle, and the account must re-check the same authorization in its `VERIFY` frame regardless, since the protocol cannot know which keystore an account trusts. Executing it in protocol added a second restricted execution context, storage-read caps, a mempool dependency on shared storage slots, and an unsigned `account` witness field that every account had to defensively compare against `address(this)`. Moving the lookup into the `VERIFY` frame removes all of that with no loss of capability: an account that wants a shared or upgradeable keystore calls it with `STATICCALL`, and rotation between authenticators is a storage write in the keystore.

### Why the witness carries `key_id`

The account needs a stable identifier for the credential that does not depend on proof encoding. The authenticator derives it from the proof (for example, a hash of the public key or a credential identifier), and the protocol requires the result to equal the `key_id` claimed in the witness. Carrying `key_id` in the witness lets account code read it with the existing `SIGDATACOPY` instruction instead of a new `SIGPARAM` value, and lets nodes know the credential before executing the authenticator. A relayer cannot substitute a proof for a different key: the authenticator's result would not match the claimed `key_id`, and changing the claimed `key_id` yields a pair the account has not authorized.

### Why authenticator gas is protocol-fixed

A per-signature gas budget would make `AUTHENTICATOR` cost depend on witness contents, complicating intrinsic-gas computation and public-mempool bounding. A single `AUTHENTICATOR_GAS_LIMIT` gives every `AUTHENTICATOR` signature the same statically known maximum cost, in the same way native schemes have fixed costs.

### Why a signature scheme instead of a pure frame

A separate pure frame would require wallet and account code to coordinate a signature index, pure-frame index, result format, and subsequent `VERIFY` frame. Keeping the witness in the signature list preserves one authentication namespace.

### Why authenticator selection is left to builders

Enshrining a canonical authenticator set in consensus would require a network upgrade to add a scheme and would make the protocol the gatekeeper of authentication methods. Leaving the accepted set to each node, builder, or sequencer keeps consensus neutral. Because `ARBITRARY` remains available for every account, this selection is an optimization path, not a permission to transact.

### Why `AUTHENTICATOR` is introspectable

EIP-8141 hides the raw bytes of protocol-validated schemes to keep future aggregation possible. An authenticator proof is interpreted by arbitrary authenticator code and cannot be aggregated by the protocol, so hiding it buys nothing.

### Why validation accesses stay out of the block access list

EIP-8141 excludes validation-time accesses from the [EIP-7928](./eip-7928.md) block-level access list because signature validation does not happen in EVM execution. Authenticator execution reads only the authenticator's own code, so the only access to account for is the code read, which follows the same rule.

## Backwards Compatibility

This proposal assigns signature scheme `0x03`, which EIP-8141 currently reserves, and defines `SIGDATACOPY` and `SIGPARAM(0x03)` for it. Activation requires a coordinated network upgrade. Pre-upgrade nodes reject transactions using these values; existing EIP-8141 transactions retain their prior behavior.

## Test Cases

Full executable state tests remain to be added. Implementations MUST cover at least the cases below.

### Authentication success

1. Deploy a regular non-delegated authenticator.
2. Set `signer` to the authenticator and supply `key_id` and a proof whose authenticator result equals `key_id`.
3. Assert that validation succeeds and `SIGPARAM(0x00)` returns the authenticator.
4. Repeat with the signature consumed by a sponsor's `VERIFY` frame rather than the sender's and assert that validation succeeds.
5. Assert that exactly `AUTHENTICATOR_COST` execution gas is charged regardless of gas left unused by the call.

### Authenticator rejection

Each condition makes the signature invalid:

- `signer` is absent or not exactly 20 bytes;
- `signer` is the zero address;
- signature is shorter than `AUTHENTICATOR_HEADER_LENGTH`;
- `key_id` is zero;
- authenticator is a precompile or delegated account;
- authenticator returns a different `key_id`;
- authenticator returns malformed data;
- authenticator reverts;
- authenticator reads state;
- authenticator calls a non-precompile;
- authenticator exceeds `AUTHENTICATOR_GAS_LIMIT`.

### Witness replacement and introspection

1. Produce two valid proofs for the same `key_id` and assert that they produce the same canonical transaction signature hash and, at equal length, the same fee.
2. Replace the proof with one authenticating a different key and assert that validation fails.
3. Replace `key_id` with another key the account has not authorized, together with a matching proof, and assert that the account's `VERIFY` frame rejects it.
4. Assert that `SIGDATACOPY` and `SIGPARAM(0x03)` return the full `AUTHENTICATOR` signature bytes and length.

### Access accounting

1. Assert that the authenticator is cold in the first frame that touches it.
2. Assert that no validation access appears in the block-level access list.

## Security Considerations

### Authenticator trust

An account that authorizes `(authenticator, key_id)` trusts the authenticator's code to correctly verify possession and to bind `key_id` to the proof. A flawed authenticator that returns a `key_id` not bound to the proof allows anyone to satisfy the account's authorization check. Accounts should authorize only audited authenticators.

### Unsigned witness

`key_id` and `proof` are not committed by the canonical hash and may be replaced by anyone. A replacement cannot select another credential: the authenticator must derive `key_id` from the proof rather than echo the claimed value, the result must equal the claimed `key_id`, and a different `key_id` is a pair the account has not authorized. Authenticators MUST NOT accept a proof that does not bind the returned `key_id`, and SHOULD reject proofs of unexpected length so a relayer cannot inflate the payer's data cost.

### Code upgrade risk

Code is not pinned. An authenticator whose address can be recreated with different runtime code can change behavior under a previously reviewed address. Wallets should only recognize authenticators deployed without that pattern.

### Builder selection and censorship

Because builders and sequencers may choose which authenticators they accept, an `AUTHENTICATOR` transaction may be valid yet not included by a given builder. This is inclusion policy of the same kind builders already apply to any transaction, and a user retains `ARBITRARY`, which is subject to no authenticator selection at all.

### Context consistency

Clients must identically enforce pure-authentication opcodes, returndata validation, gas boundaries, and access accounting. Differences may cause consensus failures.

### Account authorization

Accounts must authorize the pair `(authenticator, key_id)`. Authorizing only `key_id` or only the authenticator address loses domain separation and can admit an unintended credential.

### Explicit-message signatures

A nonempty `msg` does not necessarily commit to the frame transaction. Accounts approving execution or payment must reject such signatures unless they independently prove an exact commitment to every security-relevant transaction field.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
