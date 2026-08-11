from pathlib import Path

PATH = Path("EIPS/eip-8141.md")
text = PATH.read_text()


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected exactly one match, found {count}: {old[:160]!r}")
    text = text.replace(old, new, 1)


def replace_between(start: str, end: str, replacement: str) -> None:
    global text
    if text.count(start) != 1 or text.count(end) < 1:
        raise RuntimeError(f"invalid range markers: {start!r} .. {end!r}")
    start_index = text.index(start)
    end_index = text.index(end, start_index)
    text = text[:start_index] + replacement + text[end_index:]


replace_once(
    "| 0x4..255   | reserved            | reserved                                                  | reserved |",
    "| 0x04..0xff | reserved            | reserved                                                  | reserved |",
)

replace_between(
    "##### Registered Root Key Registry\n",
    "\n#### Receipt Encoding\n",
    r'''##### Registered Root Key Registry

EIP-8141 defines a canonical state-backed root-key registry. Its account-indexed configuration model is inspired by [EIP-8130](./eip-8130.md), but the registry is independent from EIP-8130 and does not import its actors, authenticators, delegates, scopes, expiry, or policy-manager semantics.

The registry contains at most one active registered root credential for each account. A registered credential is intentionally unrestricted: it may authorize any approval scope that the account itself could authorize through `APPROVE`. Restricted credentials and programmable policy remain the responsibility of ordinary account-code validation.

`REGISTERED_KEY_REGISTRY` is a stateful system precompile. Calls to this address are dispatched to the protocol-defined behavior below before EIP-8141 default-code handling. No account code or transaction-selected implementation is executed.

The precompile has the following ABI:

```solidity
function setK1(address keyAddress) external;
function setR1(bytes32 qx, bytes32 qy) external;
function clear() external;
function getRegisteredKey(address account)
    external
    view
    returns (uint8 keyType, bytes32 key0, bytes32 key1);
```

Mutating methods are valid only through `CALL`; invoking them through `STATICCALL`, `DELEGATECALL`, or `CALLCODE` reverts. Calls with non-zero value, malformed calldata, or an unknown selector also revert.

Each mutating method updates only the entry belonging to the immediate EVM `CALLER`:

- `setK1` requires `keyAddress != address(0)` and replaces the caller's entry with that secp256k1 root address.
- `setR1` requires `qx` and `qy` to encode a valid non-infinity secp256r1 affine point and replaces the caller's entry with that root public key.
- `clear` removes the caller's registered root.

The three mutating methods return empty data and emit no logs. `getRegisteredKey` returns `(REGISTERED_KEY_NONE, 0, 0)` for an empty or malformed entry, `(REGISTERED_KEY_K1, bytes32(uint256(uint160(keyAddress))), 0)` for K1, and `(REGISTERED_KEY_R1, qx, qy)` for R1.

No proof of possession is required during registration: authorization comes from the call already executing with the account as `CALLER`. An EOA may register through an ordinary transaction or an approved `SENDER` frame. A smart account may register through a `SENDER` frame approved by its ordinary `VERIFY` logic or by an existing registered root. Replacing or clearing the entry performs key rotation or revocation.

The registry uses the following exact storage layout:

```python
def registered_key_base_slot(account):
    return keccak(left_pad_32(account) + REGISTERED_KEY_MAPPING_SLOT)
```

For `base = registered_key_base_slot(account)`, with slot addition modulo `2**256`:

- slot `base` is the header word;
- slot `base + 1` stores `qx` for an R1 entry; and
- slot `base + 2` stores `qy` for an R1 entry.

The low eight bits of the header contain `key_type`. For a K1 entry, bits `[8, 168)` contain the 160-bit key address and all higher bits are zero. For an R1 entry, the header is exactly `REGISTERED_KEY_R1`. A zero header means no registered key. Unknown key types, non-zero reserved bits, and a zero K1 address are malformed and are treated as no valid registration.

`setK1`, `setR1`, and `clear` write all three slots into canonical form, including clearing fields unused by the new key type. Calls use normal EVM call, calldata, memory, state-journaling, `SSTORE`, and refund rules; native dispatch adds no separate gas charge.

Consensus signature validation reads this layout directly rather than calling the precompile. The lookup uses the state immediately before transaction execution and does not warm the EVM account or storage access sets. K1 validation reads only `base`; R1 validation reads `base`, `base + 1`, and `base + 2`. Consequently, a transaction cannot register or rotate a root in one frame and consume the new key later in the same transaction.
''',
)

replace_between(
    "def read_registered_root(state, account):\n",
    "\ndef validate_signature(sig, tx_sender, sig_hash, pre_state) -> bool:\n",
    '''def read_registered_root(state, account):
    base = registered_key_base_slot(account)
    header = state.storage(REGISTERED_KEY_REGISTRY, base)
    key_type = header & 0xff

    if key_type == REGISTERED_KEY_K1:
        if header >> 168 != 0:
            return None
        key_address = address((header >> 8) & (2**160 - 1))
        if key_address == address(0):
            return None
        return (REGISTERED_KEY_K1, key_address, None)

    if key_type == REGISTERED_KEY_R1:
        if header != REGISTERED_KEY_R1:
            return None
        qx = state.storage(REGISTERED_KEY_REGISTRY, base + 1)
        qy = state.storage(REGISTERED_KEY_REGISTRY, base + 2)
        return (REGISTERED_KEY_R1, qx, qy)

    return None
''',
)

replace_between(
    "        if isinstance(root, RegisteredK1):\n",
    "        return False\n\n    elif sig.scheme == ARBITRARY:\n",
    '''        key_type, key0, key1 = root

        if key_type == REGISTERED_KEY_K1:
            if len(sig.signature) != 65:
                return False
            v = sig.signature[0]
            r = int.from_bytes(sig.signature[1:33], "big")
            s = int.from_bytes(sig.signature[33:65], "big")
            if v > 1 or not (0 < r < SECP256K1N) or not (0 < s <= SECP256K1N // 2):
                return False
            recovered = ecrecover(msg, v, r, s)
            return recovered != address(0) and recovered == key0

        if key_type == REGISTERED_KEY_R1:
            if len(sig.signature) != 64:
                return False
            r = int.from_bytes(sig.signature[0:32], "big")
            s = int.from_bytes(sig.signature[32:64], "big")
            if not (0 < r < SECP256R1N) or not (0 < s <= SECP256R1N // 2):
                return False
            return P256VERIFY(msg, r, s, key0, key1)

        return False
''',
)

replace_once(
    '''```\n\n#### Expiry Verifier Frame\n\n\n`REGISTERED_STATIC` is charged a fixed `REGISTERED_STATIC_SIGNATURE_COST`, independent of the registered key type or warm/cold state. The cost equals the current P256 verification cost plus three cold registry-slot reads, which is the maximum work performed by the R1 branch. Implementations may read only the K1 header slot when applicable, but do not receive a lower intrinsic charge.\n\nA `VERIFY` frame whose `frame.target` equals `EXPIRY_VERIFIER` is an **expiry verifier frame**.''',
    '''```\n\nFor `REGISTERED_STATIC`, `resolved_signer` is the registry account, not the registered K1 address or R1 public key. A successful validation records exactly the registry slots read as non-EVM-visible validation metadata for public-mempool dependency tracking.\n\n`REGISTERED_STATIC` is charged a fixed `REGISTERED_STATIC_SIGNATURE_COST`, independent of key type and warm/cold state. The cost is priced as the current P256 verification cost plus three cold-SLOAD-equivalent registry reads, which bounds the R1 branch. K1 validation may read only the header slot but receives no lower intrinsic charge. The direct registry lookup does not warm EVM state.\n\n#### Expiry Verifier Frame\n\nA `VERIFY` frame whose `frame.target` equals `EXPIRY_VERIFIER` is an **expiry verifier frame**.''',
)

replace_once(
    '''    - If `resolved_target` code hash is empty, i.e. `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`, execute the logic described in [default code](#default-code).
        - Otherwise, if `resolved_target` uses an [EIP-7702](./eip-7702.md) delegation indicator, execute according to [EIP-7702](./eip-7702.md)'s delegated-code semantics.
''',
    '''    - If `resolved_target == REGISTERED_KEY_REGISTRY`, execute the registered-key system precompile.
    - Otherwise, if `resolved_target` code hash is empty, i.e. `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`, execute the logic described in [default code](#default-code).
        - Otherwise, if `resolved_target` uses an [EIP-7702](./eip-7702.md) delegation indicator, execute according to [EIP-7702](./eip-7702.md)'s delegated-code semantics.
''',
)

replace_once(
    '''After execution, return `payer_refund` to the payer. This is the `resolved_target` that called `APPROVE(APPROVE_PAYMENT)` or `APPROVE(APPROVE_EXECUTION_AND_PAYMENT)`. Return `max_gas - gas_used` to the block gas pool.''',
    '''After execution, return `payer_refund` to the payer. This is the `resolved_target` that produced payment approval through `APPROVE(APPROVE_PAYMENT)`, `APPROVE(APPROVE_EXECUTION_AND_PAYMENT)`, or the registered-static equivalent. Return `max_gas - gas_used` to the block gas pool.''',
)

replace_once(
    "#### Paymasters\n\nA paymaster can choose to sponsor a transaction's gas.",
    "#### Paymasters\n\nA registered-static payment frame does not execute paymaster code and is therefore not classified as a canonical or non-canonical paymaster frame. It remains subject to ordinary per-payer balance reservation and to registered-root dependency tracking and revalidation.\n\nA paymaster can choose to sponsor a transaction's gas.",
)

replace_once(
    '''A transaction using a paymaster is eligible for public mempool propagation only if the `pay` frame targets a canonical paymaster instance and the node can reserve the maximum transaction cost against that paymaster.''',
    '''A transaction whose `pay` frame executes canonical paymaster code is eligible for public mempool propagation only if the node can reserve the maximum transaction cost against that paymaster.''',
)

replace_once(
    '''For non-canonical paymasters, `pending_withdrawal_amount` is not meaningful since they may not support timelocked withdrawals.  Instead, we keep the mempool safe by enforcing that each non-canonical paymaster can only be used with no more than `MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER` pending transactions.''',
    '''For EVM-executed non-canonical paymaster frames, `pending_withdrawal_amount` is not meaningful since they may not support timelocked withdrawals. Instead, we keep the mempool safe by enforcing that each such paymaster can only be used with no more than `MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER` pending transactions.''',
)

replace_once(
    '''The `MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER` cap continues to apply to `pay` frames whose target carries code that is not the canonical paymaster implementation; a `pay` frame whose target has the empty code hash (a default-code sponsor) is not a paymaster and is governed by the per-payer exposure rule alone.''',
    '''The `MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER` cap applies only when a `pay` frame executes target code that is not the canonical paymaster implementation. It does not apply to a registered-static `pay` frame because target code is not loaded or executed. A `pay` frame whose target has the empty code hash and uses default code is likewise governed by the per-payer exposure rule alone.''',
)

replace_once(
    '''- Frame 4 (optional): Check unpaid gas, refund tokens, possibly convert tokens to ETH on an AMM.

Note: to be included in the public mempool under the current model,''',
    '''- Frame 4 (optional): Check unpaid gas, refund tokens, possibly convert tokens to ETH on an AMM.

If signature entry `1` uses `REGISTERED_STATIC`, frame 1 instead has empty data and the sponsor's registered root signs the complete canonical frame transaction. The protocol applies `APPROVE_PAYMENT` without loading or executing sponsor code, regardless of whether the sponsor account has deployed or delegated code.

Note: to be included in the public mempool under the current model,''',
)

# Remove accidental double spacing around newly inserted headings.
text = text.replace("\n\n\n##### Registered Root Key Registry", "\n\n##### Registered Root Key Registry")
text = text.replace("\n\n\nA `REGISTERED_STATIC` signature selected", "\n\nA `REGISTERED_STATIC` signature selected")
text = text.replace("\n\n\n### Registered Root Key Fast Path", "\n\n### Registered Root Key Fast Path")
text = text.replace("\n\n\n#### Example 1c", "\n\n#### Example 1c")
text = text.replace("## Security Considerations\n\n\n### Registered", "## Security Considerations\n\n### Registered")

for forbidden in ["RegisteredK1", "RegisteredR1", "EIP8130_ACTOR", "EIP8130_SCOPE_"]:
    if forbidden in text:
        raise RuntimeError(f"discarded or undefined design remains: {forbidden}")

for required in [
    "stateful system precompile",
    "getRegisteredKey",
    "MUST NOT fall back",
    "external sponsor",
    "registered-static equivalent",
    "does not apply to a registered-static `pay` frame",
]:
    if required not in text:
        raise RuntimeError(f"missing required refinement: {required}")

PATH.write_text(text)
print(f"refined {PATH}: {len(text.splitlines())} lines, {len(text)} bytes")
