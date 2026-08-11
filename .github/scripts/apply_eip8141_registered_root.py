from pathlib import Path

PATH = Path("EIPS/eip-8141.md")
text = PATH.read_text()


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected exactly one match, found {count}: {old[:120]!r}")
    text = text.replace(old, new, 1)


def insert_after(anchor: str, addition: str) -> None:
    replace_once(anchor, anchor + addition)


# Constants.
insert_after(
    "| `VERSIONED_HASH_VERSION_KZG` | `Bytes1(0x01)` |\n",
    "| `REGISTERED_KEY_REGISTRY`   | `address(0x8142)` |\n"
    "| `REGISTERED_STATIC`         | `0x03`            |\n"
    "| `REGISTERED_STATIC_SIGNATURE_COST` | `13000` |\n"
    "| `REGISTERED_KEY_NONE`       | `0x00`            |\n"
    "| `REGISTERED_KEY_K1`         | `0x01`            |\n"
    "| `REGISTERED_KEY_R1`         | `0x02`            |\n"
    "| `REGISTERED_KEY_MAPPING_SLOT` | `Bytes32(0x00)` |\n",
)

# Signature metadata and stateless constraints.
replace_once(
    "- `signer` -- scheme-dependent signer metadata; for `SECP256K1` and `P256`, this is a 20-byte address.\n",
    "- `signer` -- scheme-dependent signer metadata; for `SECP256K1`, `P256`, and `REGISTERED_STATIC`, this is a 20-byte address.\n",
)

replace_once(
    """for sig in tx.signatures:
    if sig.scheme in [SECP256K1, P256]:
        assert len(sig.signer) == 0 or len(sig.signer) == 20
    elif sig.scheme == ARBITRARY:
        assert len(sig.signer) == 0
    else:
        invalid_transaction()
    if len(sig.msg) == 0:
        assert sig.msg == Bytes()
    elif len(sig.msg) == 32:
        assert sig.msg != b"\\x00" * 32
    else:
        invalid_transaction()
""",
    """for sig in tx.signatures:
    if sig.scheme in [SECP256K1, P256, REGISTERED_STATIC]:
        assert len(sig.signer) == 0 or len(sig.signer) == 20
    elif sig.scheme == ARBITRARY:
        assert len(sig.signer) == 0
    else:
        invalid_transaction()

    if sig.scheme == REGISTERED_STATIC:
        assert sig.msg == Bytes()
        assert len(sig.signature) in [64, 65]
    elif len(sig.msg) == 0:
        assert sig.msg == Bytes()
    elif len(sig.msg) == 32:
        assert sig.msg != b"\\x00" * 32
    else:
        invalid_transaction()
""",
)

# Signature schemes.
replace_once(
    """| `scheme`   | Name         | `signature` encoding                           | Gas cost |
|------------|--------------|------------------------------------------------|----------|
| 0x0        | `ARBITRARY`  | arbitrary bytes                                | 100      |
| 0x1        | `SECP256K1`  | `v (1 byte) || r (32 bytes) || s (32 bytes)`   | 2800     |
| 0x2        | `P256`       | `r || s || qx || qy` (32 bytes each)           | 6700     |
| 0x3..255   | reserved     | reserved                                       | reserved |
""",
    """| `scheme`   | Name                | `signature` encoding                                      | Gas cost |
|------------|---------------------|-----------------------------------------------------------|----------|
| 0x0        | `ARBITRARY`         | arbitrary bytes                                           | 100      |
| 0x1        | `SECP256K1`         | `v (1 byte) || r (32 bytes) || s (32 bytes)`              | 2800     |
| 0x2        | `P256`              | `r || s || qx || qy` (32 bytes each)                      | 6700     |
| 0x3        | `REGISTERED_STATIC` | K1: `v || r || s`; R1: `r || s`, selected from registry   | 13000    |
| 0x4..255   | reserved            | reserved                                                  | reserved |
""",
)

replace_once(
    """For `SECP256K1` and `P256`, the `signer` is a 20-byte Ethereum address. If absent, `tx.sender` is used (for introspections as well).
For `ARBITRARY`, `signer` MUST be empty. The protocol does not assign a resolved signer address to `ARBITRARY` entries.
""",
    """For `SECP256K1` and `P256`, the `signer` is a 20-byte Ethereum address. If absent, `tx.sender` is used (for introspections as well).
For `REGISTERED_STATIC`, the `signer` is the account whose canonical registered root key is authoritative. If absent, `tx.sender` is used. Its `msg` MUST be empty.
For `ARBITRARY`, `signer` MUST be empty. The protocol does not assign a resolved signer address to `ARBITRARY` entries.
""",
)

# Canonical registry, intentionally independent from EIP-8130.
insert_after(
    "For `P256`, the signer address must be `keccak256(qx || qy)[12:]`.\n",
    r'''

##### Registered Root Key Registry

EIP-8141 installs a canonical state-backed registry at `REGISTERED_KEY_REGISTRY`. The design is inspired by [EIP-8130](./eip-8130.md)'s canonical account-configuration model, but is independent from it. It does not use EIP-8130 actors, authenticators, delegates, scopes, expiry, or policy managers.

The registry stores exactly one active root credential for each account. A root credential authorizes every approval scope that the account could authorize through `APPROVE`; restricted credentials and programmable policy remain the responsibility of ordinary account-code validation.

`REGISTERED_KEY_REGISTRY` is a protocol-defined system contract with the following ABI:

```solidity
function setK1(address keyAddress) external;
function setR1(bytes32 qx, bytes32 qy) external;
function clear() external;
```

Each method updates only the entry belonging to the immediate EVM `CALLER`. A caller cannot register or clear a key for another account. Calls with non-zero value or malformed calldata revert.

- `setK1` requires `keyAddress != address(0)` and replaces the caller's entry with a secp256k1 root address.
- `setR1` replaces the caller's entry with the supplied P256 affine coordinates. Invalid coordinates remain unusable because `P256VERIFY` rejects them.
- `clear` removes the caller's registered root.

No proof of possession is required during registration: the call itself must already execute with the account as `CALLER`. A code-less account can reach the registry through a `SENDER` frame approved by default code, while a smart account can use its ordinary `VERIFY` logic to approve the registering `SENDER` frame. Replacing or clearing an entry is key rotation or revocation.

The registry uses the following exact storage layout:

```python
def registered_key_base_slot(account):
    return keccak(left_pad_32(account) + REGISTERED_KEY_MAPPING_SLOT)
```

For `base = registered_key_base_slot(account)`:

- slot `base` is the header word;
- slot `base + 1` stores `qx` for an R1 entry; and
- slot `base + 2` stores `qy` for an R1 entry.

The low eight bits of the header contain `key_type`. For a K1 entry, bits `[8, 168)` contain the 160-bit key address and every higher bit is zero. For an R1 entry, the header is exactly `REGISTERED_KEY_R1`. A zero header means no registered key. Unknown key types, non-zero reserved bits, and a zero K1 address are treated as no valid registration.

`setK1`, `setR1`, and `clear` write all three slots into their canonical form, including clearing fields unused by the new key type. Calls to the system contract charge normal call-data, account-access, and `SSTORE` gas for the slots they modify.

Consensus validation reads this layout directly. It MUST NOT execute registry code or make an EVM call. The lookup uses transaction pre-execution state and does not warm EVM account or storage access. Consequently, a transaction cannot register or rotate a root key in one frame and consume the new key in the same transaction.
''',
)

# Signature validation.
replace_once(
    """ARBITRARY = 0x0
SECP256K1 = 0x1
P256      = 0x2

def validate_signature(sig, tx_sender, sig_hash) -> bool:
""",
    """ARBITRARY        = 0x0
SECP256K1        = 0x1
P256             = 0x2
REGISTERED_STATIC = 0x3

def read_registered_root(state, account):
    base = registered_key_base_slot(account)
    header = state.storage(REGISTERED_KEY_REGISTRY, base)
    key_type = header & 0xff

    if key_type == REGISTERED_KEY_K1:
        if header >> 168 != 0:
            return None
        key_address = address((header >> 8) & (2**160 - 1))
        if key_address == address(0):
            return None
        return RegisteredK1(key_address=key_address, slots=[base])

    if key_type == REGISTERED_KEY_R1:
        if header != REGISTERED_KEY_R1:
            return None
        qx = state.storage(REGISTERED_KEY_REGISTRY, base + 1)
        qy = state.storage(REGISTERED_KEY_REGISTRY, base + 2)
        return RegisteredR1(qx=qx, qy=qy, slots=[base, base + 1, base + 2])

    return None

def validate_signature(sig, tx_sender, sig_hash, pre_state) -> bool:
""",
)

replace_once(
    """    elif sig.scheme == ARBITRARY:
        return len(sig.signer) == 0

    else:
        return False
""",
    """    elif sig.scheme == REGISTERED_STATIC:
        # REGISTERED_STATIC always signs the canonical transaction hash.
        if sig.msg != Bytes():
            return False

        root = read_registered_root(pre_state, resolved_signer)
        if root is None:
            return False

        if isinstance(root, RegisteredK1):
            if len(sig.signature) != 65:
                return False
            v = sig.signature[0]
            r = int.from_bytes(sig.signature[1:33], "big")
            s = int.from_bytes(sig.signature[33:65], "big")
            if v > 1 or not (0 < r < SECP256K1N) or not (0 < s <= SECP256K1N // 2):
                return False
            recovered = ecrecover(msg, v, r, s)
            return recovered != address(0) and recovered == root.key_address

        if isinstance(root, RegisteredR1):
            if len(sig.signature) != 64:
                return False
            r = int.from_bytes(sig.signature[0:32], "big")
            s = int.from_bytes(sig.signature[32:64], "big")
            if not (0 < r < SECP256R1N) or not (0 < s <= SECP256R1N // 2):
                return False
            return P256VERIFY(msg, r, s, root.qx, root.qy)

        return False

    elif sig.scheme == ARBITRARY:
        return len(sig.signer) == 0

    else:
        return False
""",
)

insert_after(
    "```\n\n#### Expiry Verifier Frame\n",
    """

`REGISTERED_STATIC` is charged a fixed `REGISTERED_STATIC_SIGNATURE_COST`, independent of the registered key type or warm/cold state. The cost equals the current P256 verification cost plus three cold registry-slot reads, which is the maximum work performed by the R1 branch. Implementations may read only the K1 header slot when applicable, but do not receive a lower intrinsic charge.
""",
)

# The insertion above targets the first closing fence before Expiry Verifier, which is the
# signature-validation code block. Verify it did not accidentally land elsewhere.
if text.count("`REGISTERED_STATIC` is charged a fixed") != 1:
    raise RuntimeError("registered-static gas paragraph inserted incorrectly")

# Behavior: pass pre-state to signature validation and add direct VERIFY consumption.
replace_once(
    "1. For each `sig` in `tx.signatures`, ensure `validate_signature(sig, tx.sender, sig_hash) == true`.\n",
    "1. For each `sig` in `tx.signatures`, ensure `validate_signature(sig, tx.sender, sig_hash, pre_state) == true`.\n",
)

insert_after(
    """    - `payer = None`
    - `sender_approved = false`
""",
    r'''

A `VERIFY` frame selects the same deterministic signature index used by default code: index `0` when execution approval is requested, otherwise index `1`. Before account-code lookup, process a selected `REGISTERED_STATIC` signature as follows:

```python
def process_registered_static_verify(tx, frame, resolved_target):
    if frame.mode != VERIFY:
        return False

    allowed_scope = frame.flags & APPROVE_SCOPE_MASK
    if allowed_scope == APPROVE_SCOPE_NONE:
        return False

    sig_index = 0 if allowed_scope & APPROVE_EXECUTION else 1
    if sig_index >= len(tx.signatures):
        return False

    sig = tx.signatures[sig_index]
    if sig.scheme != REGISTERED_STATIC:
        return False

    # Selection of REGISTERED_STATIC makes this path mandatory.
    # Failure MUST NOT fall back to account-code execution.
    if frame.data != Bytes():
        invalid_transaction()
    if sig.msg != Bytes():
        invalid_transaction()
    if resolved_signer(sig, tx.sender) != resolved_target:
        invalid_transaction()

    apply_approve(
        frame=frame,
        resolved_target=resolved_target,
        scope=allowed_scope,
    )
    return True
```

`apply_approve` performs exactly the validity checks and transaction-context effects of `APPROVE(scope)` as though code executing with `ADDRESS == resolved_target` had invoked it. This includes approval ordering, sender-target binding, payer uniqueness, balance checks, nonce increment, maximum-cost collection, and every other rule in the [`APPROVE` instruction](#approve-instruction-0xaa).

A payment-only registered-static frame may target an account other than `tx.sender`; this is the direct root-key path for an external sponsor. The ordinary `APPROVE_PAYMENT` ordering and solvency rules still apply.
''',
)

replace_once(
    "1. Execute a call with the specified `mode`, `flags`, `target`, `gas_limit`, `value`, and `data`.\n",
    "1. Process a frame with the specified `mode`, `flags`, `target`, `gas_limit`, `value`, and `data`.\n",
)

insert_after(
    """    - Let `resolved_target = frame.target if frame.target is not None else tx.sender`
        - Unless otherwise stated, checks that refer to the target account during execution use the resolved target.
""",
    """    - Evaluate `process_registered_static_verify(tx, frame, resolved_target)` before caller setup, account-code lookup, or EIP-7702 delegation resolution.
        - If it returns `true`, append a successful frame receipt with empty return data, `gas_used = 0`, and no logs, then continue to the next frame.
        - The target account's code and EIP-7702 delegation are not loaded or executed.
        - If the deterministic signature uses `REGISTERED_STATIC` but a registered-static requirement fails, the transaction is invalid. Implementations MUST NOT fall back to ordinary `VERIFY` execution.
""",
)

replace_once(
    "1. If frame has mode `VERIFY` the following additional requirements are imposed:\n",
    "1. If frame has mode `VERIFY` and was not processed as registered-static, the following additional requirements are imposed:\n",
)

# Signature gas.
replace_once(
    """    if sig.scheme == P256:
        return 6700
    if sig.scheme == ARBITRARY:
        return 100
""",
    """    if sig.scheme == P256:
        return 6700
    if sig.scheme == REGISTERED_STATIC:
        return REGISTERED_STATIC_SIGNATURE_COST
    if sig.scheme == ARBITRARY:
        return 100
""",
)

insert_after(
    """- If `mode` is `SENDER` or `DEFAULT`:
  - Return successfully as if calling empty code.
""",
    """

A `REGISTERED_STATIC` signature selected by a `VERIFY` frame is consumed before default-code dispatch. Default code therefore continues to accept only the ordinary `SECP256K1` path described above.
""",
)

# Public mempool dependency and structural rules.
replace_once(
    """6. the code of any other existing non-delegated contracts reached during validation via `CALL*` or `EXTCODE*`, provided the resulting trace does not access disallowed mutable state.
""",
    """6. the code of any other existing non-delegated contracts reached during validation via `CALL*` or `EXTCODE*`, provided the resulting trace does not access disallowed mutable state, and
7. the exact canonical-registry slots read while validating each `REGISTERED_STATIC` signature.
""",
)

replace_once(
    """3. `self_verify` and `only_verify` must execute in `VERIFY` mode, target `tx.sender` (either explicitly or via a null target), must successfully call `APPROVE`, and `frame.flags` must match the scope of the `APPROVE` call.
    - `self_verify` must call `APPROVE(APPROVE_EXECUTION_AND_PAYMENT)`.
    - `only_verify` must call `APPROVE(APPROVE_EXECUTION)`.
4. `pay` must execute in `VERIFY` mode, have flags set to `APPROVE_PAYMENT`, and must successfully call `APPROVE(APPROVE_PAYMENT)`
5. No frame in the validation prefix may have the `ATOMIC_BATCH_FLAG` set.
6. The sum of `gas_limit` values across the validation prefix, plus the intrinsic cost of validating `tx.signatures`, must not exceed `MAX_VERIFY_GAS`.
7. Nodes should stop simulation immediately once `payer` has been set and the associated `VERIFY` frame completes successfully.
8. There must not be `VERIFY` frame after validation prefix.
""",
    """3. `self_verify` and `only_verify` must execute in `VERIFY` mode, target `tx.sender` (either explicitly or via a null target), and produce the approval requested by `frame.flags` through either `APPROVE` or registered-static evaluation.
    - `self_verify` must produce `APPROVE_EXECUTION_AND_PAYMENT`.
    - `only_verify` must produce `APPROVE_EXECUTION`.
4. `pay` must execute in `VERIFY` mode, have flags set to `APPROVE_PAYMENT`, and produce `APPROVE_PAYMENT` through either `APPROVE` or registered-static evaluation.
5. No frame in the validation prefix may have the `ATOMIC_BATCH_FLAG` set.
6. The sum of `gas_limit` values across the validation prefix, plus the intrinsic cost of validating `tx.signatures`, must not exceed `MAX_VERIFY_GAS`.
7. Nodes should stop simulation or direct evaluation immediately once `payer` has been set and the associated `VERIFY` frame completes successfully.
8. There must not be `VERIFY` frame after validation prefix.
9. Every `REGISTERED_STATIC` signature must be selected by a registered-static `VERIFY` frame in the validation prefix. Unused entries and entries selected only after the validation prefix are not eligible for public propagation.
""",
)

replace_once(
    """Three frame species in the validation prefix have fully protocol-defined semantics, leaving no deployed code whose behavior a node would need to discover by execution: a frame whose resolved target has the empty code hash (default code), an expiry verifier frame whose runtime code at `EXPIRY_VERIFIER` matches the canonical expiry verifier code, and a `pay` frame admitted by canonical paymaster code match per the previous section.
""",
    """Four frame species in the validation prefix have fully protocol-defined semantics, leaving no deployed code whose behavior a node would need to discover by execution: a registered-static `VERIFY` frame, a frame whose resolved target has the empty code hash (default code), an expiry verifier frame whose runtime code at `EXPIRY_VERIFIER` matches the canonical expiry verifier code, and a `pay` frame admitted by canonical paymaster code match per the previous section.
""",
)

replace_once(
    """The complete state dependency set of such a validation prefix is: the sender's code hash and nonce, the payer's code hash and balance (or the canonical paymaster's tracked state), the runtime code at `EXPIRY_VERIFIER` together with the frame's deadline when an expiry verifier frame is present, and the current block timestamp. Nodes SHOULD index pending transactions by this set so that head-of-chain changes are revalidated without re-execution.
""",
    """The complete state dependency set of such a validation prefix is: the sender's nonce; code hashes for frames whose semantics actually load code; the payer's balance and, when applicable, code hash or canonical-paymaster tracked state; the runtime code at `EXPIRY_VERIFIER` together with the frame's deadline when an expiry verifier frame is present; the exact registry slots read for every `REGISTERED_STATIC` signature; and the current block timestamp. A registered-static frame does not depend on its target's code hash because that code is never loaded. Nodes SHOULD index pending transactions by this set so that head-of-chain changes are revalidated without re-execution.
""",
)

replace_once(
    "A public mempool node must simulate the validation prefix and reject the transaction if any of the following occurs before `payer` has been set:\n",
    "A public mempool node must simulate the validation prefix, directly evaluate its protocol-defined frames, or combine both approaches, and reject the transaction if any of the following occurs before `payer` has been set:\n",
)

replace_once(
    "- a `self_verify`, `only_verify`, or `pay` frame exits without its required `APPROVE`\n",
    "- a `self_verify`, `only_verify`, or `pay` frame exits without its required approval effect\n",
)

replace_once(
    "For `VERIFY` frames, the usual `STATICCALL` restrictions apply except for the protocol-defined effects of `APPROVE`. In addition, the following opcodes are banned during the validation prefix, with a few caveats:\n",
    "Registered-static `VERIFY` frames do not enter the EVM. For every other `VERIFY` frame, the usual `STATICCALL` restrictions apply except for the protocol-defined effects of `APPROVE`. In addition, the following opcodes are banned during EVM execution in the validation prefix, with a few caveats:\n",
)

replace_once(
    """1. A transaction is received over the wire and the node decides whether to accept or reject it.
2. The node validates all protocol-validated signatures and structurally checks all `ARBITRARY` signatures. If any signature is malformed or invalid, reject.
3. The node analyzes the frame structure and determines the validation prefix. If the prefix is not one of the recognized prefixes, reject.
4. The node simulates the validation prefix and enforces the structural and trace rules above, except that a `pay` frame whose target runtime code exactly matches the canonical paymaster implementation is handled via the canonical paymaster exception and the paymaster-specific rules below.
5. The node records the sender storage slots read during validation. Calls into helper contracts do not create additional mutable-state dependencies unless they cause disallowed storage access under the trace rules above.
6. If a canonical paymaster instance is used, the node verifies paymaster solvency using the reservation rule above.
7. A node should keep at most one pending frame transaction per sender in the public mempool. A new transaction from the same sender MAY replace the existing one only if it uses the same nonce and satisfies the replacement rules below.
8. If all checks pass, the transaction may be accepted into the public mempool and propagated to peers.
""",
    """1. A transaction is received over the wire and the node decides whether to accept or reject it.
2. The node performs stateless transaction checks, analyzes the frame structure, and determines the validation prefix. If the prefix is not recognized, reject. Confirm that every `REGISTERED_STATIC` signature has empty `msg` and a candidate registered-static `VERIFY` frame at its deterministic signature index in the validation prefix.
3. The node validates all protocol-validated signatures and structurally checks all `ARBITRARY` signatures. If any signature is malformed or invalid, reject.
4. The node directly evaluates registered-static frames and otherwise simulates the validation prefix, enforcing the structural and trace rules above. A `pay` frame whose target runtime code exactly matches the canonical paymaster implementation is handled via the canonical paymaster exception and the paymaster-specific rules below. Confirm that every `REGISTERED_STATIC` signature was actually consumed by registered-static verification.
5. The node records the sender storage slots read during EVM validation and the exact registry slots read during registered-static signature validation. Calls into helper contracts do not create additional mutable-state dependencies unless they cause disallowed storage access under the trace rules above.
6. If a canonical paymaster instance is used, the node verifies paymaster solvency using the reservation rule above.
7. A node should keep at most one pending frame transaction per sender in the public mempool. A new transaction from the same sender MAY replace the existing one only if it uses the same nonce and satisfies the replacement rules below.
8. If all checks pass, the transaction may be accepted into the public mempool and propagated to peers.
""",
)

replace_once(
    """When a new canonical block is accepted, the node removes any included frame transactions from the public mempool, updates paymaster reservations accordingly, and identifies the remaining pending transactions whose tracked dependencies were touched by the block. This includes at least transactions for the same sender, transactions whose recorded sender storage slots changed, transactions that reference a canonical paymaster instance whose balance, code, or delayed-withdrawal state changed, and transactions whose payer's balance or code changed. The node then re-simulates the validation prefix of only those affected transactions against the new head and evicts any transaction that no longer satisfies the public mempool rules.
""",
    """When a new canonical block is accepted, the node removes any included frame transactions from the public mempool, updates paymaster reservations accordingly, and identifies the remaining pending transactions whose tracked dependencies were touched by the block. This includes at least transactions for the same sender, transactions whose recorded sender storage slots changed, transactions that reference a canonical paymaster instance whose balance, code, or delayed-withdrawal state changed, transactions whose payer's balance or code changed, and transactions whose exact registered-root slots changed. The node then re-simulates or directly re-evaluates the validation prefix of only those affected transactions against the new head and evicts any transaction that no longer satisfies the public mempool rules.
""",
)

# Rationale.
insert_after(
    """That extension could also define a `PUBLISHPK` instruction to validate a public key, wrap it in the canonical alias-code format, derive the alias address, and install the alias code.
""",
    r'''

### Registered Root Key Fast Path

`REGISTERED_STATIC` gives an account an optional bounded validation path without changing the ordinary programmable `VERIFY` path. The canonical registry model is inspired by EIP-8130, but this EIP deliberately keeps only the minimal root-key property: one active K1 or R1 root per account.

The registry is defined directly in EIP-8141 so that clients have one fixed address, storage layout, key-type set, verification algorithm, and gas cost. No transaction-selected registry or authenticator contract is permitted. Validation is therefore one protocol-supported signature check plus at most three fixed state reads.

Registration is explicit opt-in to bypass account validation code. There is no scope field because a registered credential is a root, not a session key or policy credential. Multisig, spending limits, guardians, session permissions, passkeys, custom cryptography, and other restricted authorization continue to use ordinary account-code `VERIFY` frames.

The `VERIFY` frame remains the authorization consumer. It selects the account through its resolved target and selects execution and/or payment through its approval flags. This preserves the existing EIP-8141 frame structure, including direct root-key sponsorship by an account other than `tx.sender`.
''',
)

# Example.
insert_after(
    """The first frame would call the [EIP-7997](./eip-7997.md) deterministic factory predeploy. The deployer determines the address in a deterministic way from the salt and initcode. However, since the transaction sender is not authenticated at this point, the user must choose an initcode which is safe to deploy by anyone.
""",
    r'''

#### Example 1c: Registered Smart Account Root

| Frame | Mode   | Caller      | Flags                         | Target        | Value | Data      |
| ----- | ------ | ----------- | ----------------------------- | ------------- | ----- | --------- |
| 0     | VERIFY | ENTRY_POINT | APPROVE_EXECUTION_AND_PAYMENT | Null (sender) | 0     | Empty     |
| 1     | SENDER | Sender      | APPROVE_SCOPE_NONE            | Target        | 0     | Call data |

Signature entry `0` uses `REGISTERED_STATIC`, has empty `msg`, and is signed by the sender's registered K1 or R1 root. The protocol reads the sender's registry entry from pre-execution state, validates the signature, binds it to frame 0's resolved target, and applies `APPROVE_EXECUTION_AND_PAYMENT` without loading or executing the sender account's code. The same account can instead use an `ARBITRARY` signature and ordinary `VERIFY` execution when it needs programmable policy.
''',
)

# Security considerations.
insert_after(
    "## Security Considerations\n",
    r'''

### Registered Root Key Authority

A registered root key bypasses the account's ordinary validation code for any transaction that explicitly selects `REGISTERED_STATIC`. Wallets MUST treat registration, replacement, and removal with the same severity as changing the account owner. Compromise of the registered key grants full execution and payment authority; there are intentionally no protocol-level scopes or policy restrictions.

A registered-static signature must use empty `msg`, so it commits to the canonical hash of the complete frame transaction. The consuming `VERIFY` frame additionally binds the registered account to the frame's resolved target. These requirements prevent an explicit-digest signature from being reused with different execution frames or for another account.

Registry configuration is read from transaction pre-execution state. Registering, rotating, or clearing a root after signing invalidates the affected transaction, and a registry update earlier in the same frame transaction cannot authorize a later registered-static frame. Public mempool implementations must track the exact registry slots read and revalidate affected transactions when those slots change.

Registered-static validation cannot enforce multisig thresholds, guardians, recovery delays, session limits, spending policy, or custom cryptography. Accounts requiring any such rule MUST use ordinary EVM-backed `VERIFY` validation instead.
''',
)

# Sanity checks against accidental retention of the discarded EIP-8130 actor design.
for forbidden in [
    "EIP8130_ACTOR",
    "ActorValidation",
    "EIP8130_SCOPE_",
    "MAX_PENDING_TXS_PER_ACTOR_SLOT",
]:
    if forbidden in text:
        raise RuntimeError(f"discarded actor design remains: {forbidden}")

# Core invariants expected in the resulting draft.
for required in [
    "REGISTERED_STATIC",
    "Registered Root Key Registry",
    "one active root credential",
    "MUST NOT fall back",
    "external sponsor",
    "inspired by [EIP-8130]",
]:
    if required not in text:
        raise RuntimeError(f"missing required concept: {required}")

PATH.write_text(text)
print(f"updated {PATH}: {len(text.splitlines())} lines, {len(text)} bytes")
