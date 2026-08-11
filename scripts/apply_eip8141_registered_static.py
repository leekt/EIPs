from pathlib import Path

PATH = Path("EIPS/eip-8141.md")
text = PATH.read_text(encoding="utf-8")


def replace_once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    text = text.replace(old, new, 1)


replace_once(
    "After native authentication, the protocol reads exactly one EIP-8130 configuration slot at `ACCOUNT_CONFIG_ADDRESS`. It applies EIP-8130's native secp256k1 self-actor rule when applicable; every other actor uses `actor_config(resolved_signer, actor_id)`. Validation returns and caches `actor_id`, `scope`, `expiry`, and the exact 32-byte storage slot read. This proves only that the actor is registered and live; it does not grant any frame context. Default code applies the cached scope to the requested approval context. The slot is used consistently for gas accounting and mempool revalidation.",
    "After native authentication, the protocol reads exactly one EIP-8130 configuration slot at `ACCOUNT_CONFIG_ADDRESS`. It applies EIP-8130's native secp256k1 self-actor rule when applicable; every other actor uses `actor_config(resolved_signer, actor_id)`. Validation returns and caches `actor_id`, `scope`, `expiry`, and the exact 32-byte storage slot read. Signature validation by itself does not modify the transaction approval context. A `VERIFY` frame that selects this signature at the deterministic signature index defined below is a **registered-static VERIFY frame**. Such a frame applies the cached scope to the requested approval context directly, without loading or executing `resolved_target` code. The slot is used consistently for gas accounting and mempool revalidation.",
    "actor scheme consumption",
)

replace_once(
    "The `ActorValidation` value is client-internal metadata. It is cached by signature index for default-code authorization, gas accounting, stateless witnesses, and mempool dependency tracking; it is not exposed through `SIGPARAM`. The validation SLOAD warms exactly `(ACCOUNT_CONFIG_ADDRESS, storage_slot)` in the transaction-wide accessed-state journal. It does not touch the authenticator address as an account and does not execute Account Configuration Contract or authenticator code.",
    "The `ActorValidation` value is client-internal metadata. It is cached by signature index for registered-static VERIFY authorization, gas accounting, stateless witnesses, and mempool dependency tracking; it is not exposed through `SIGPARAM`. The validation SLOAD warms exactly `(ACCOUNT_CONFIG_ADDRESS, storage_slot)` in the transaction-wide accessed-state journal. It does not touch the authenticator address as an account and does not execute Account Configuration Contract or authenticator code.",
    "actor validation cache",
)

replace_once(
    "1. Initialize transaction-scoped variables:\n    - `payer = None`\n    - `sender_approved = false`\n\nThen for each frame:",
    """1. Initialize transaction-scoped variables:
    - `payer = None`
    - `sender_approved = false`

A `VERIFY` frame is evaluated as a **registered-static VERIFY frame** when the signature at its deterministic approval index uses `EIP8130_ACTOR`. The index is selected in the same way as default code: index `0` when execution approval is requested, otherwise index `1`.

```python
def registered_static_approval(frame, resolved_target, tx, validation_results):
    if frame.mode != VERIFY:
        return None

    allowed_scope = frame.flags & APPROVE_SCOPE_MASK
    if allowed_scope == APPROVE_SCOPE_NONE:
        return None

    sig_index = 0 if allowed_scope & APPROVE_EXECUTION else 1
    if sig_index >= len(tx.signatures):
        return None

    sig = tx.signatures[sig_index]
    if sig.scheme != EIP8130_ACTOR:
        return None

    # Once the deterministic signature selects this scheme, failure of any
    # registered-static condition reverts the VERIFY frame. There is no
    # fallback to account-code execution.
    require frame.data == Bytes()
    require resolved_signer(sig, tx.sender) == resolved_target
    require sig.msg == Bytes()

    actor = validation_results[sig_index].actor
    require actor is not None
    scope = actor.scope

    # POLICY actors require their EIP-8130 manager gate and are never a
    # protocol-level root authorization path.
    require (scope & EIP8130_SCOPE_POLICY) == 0

    if allowed_scope & APPROVE_EXECUTION:
        require scope == 0 or (scope & EIP8130_SCOPE_SENDER) != 0

    if allowed_scope & APPROVE_PAYMENT:
        if resolved_target == tx.sender:
            require scope == 0 or (scope & EIP8130_SCOPE_SELF_PAYER) != 0
        else:
            require scope == 0 or (scope & EIP8130_SCOPE_SPONSOR_PAYER) != 0

    return allowed_scope
```

When this function returns a scope, the client applies the same checks and transaction-context effects as `APPROVE(allowed_scope)` as if it had been executed by `resolved_target`. The frame succeeds with empty return data, no logs, and zero frame-execution gas used. Signature verification, the registry access, calldata, and the fixed per-frame cost remain charged elsewhere as specified in this EIP. The client MUST NOT load or execute the target account's code for this frame.

Registration is therefore an explicit account opt-in to a protocol-defined root authorization path. Accounts continue to use ordinary `VERIFY` execution for multisig, session policies, spending limits, guardians, unsupported authenticators, or any other validation that requires account code.

Then for each frame:""",
    "registered-static definition",
)

replace_once(
    """    - If `resolved_target` code hash is empty, i.e. `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`, execute the logic described in [default code](#default-code).
        - Otherwise, if `resolved_target` uses an [EIP-7702](./eip-7702.md) delegation indicator, execute according to [EIP-7702](./eip-7702.md)'s delegated-code semantics.
    - If a frame's execution reverts, its state changes are discarded. Additionally, if this frame has the atomic batch flag set, mark all subsequent frames in the same atomic group as skipped.
1. If frame has mode `VERIFY` the following additional requirements are imposed:
    - Execute the frame as a `STATICCALL`, disallowing state manipulation.
        - Only `APPROVE` can modify the state or transaction context in `VERIFY`.
    - If the frame reverts, the transaction is invalid. This would unroll any effects of `APPROVE`.""",
    """    - Evaluate `registered_static_approval(frame, resolved_target, tx, validation_results)` before resolving or loading target code.
        - If it returns a scope, apply the native approval effects described above and skip all account-code resolution and execution for this frame, including EIP-7702 delegated code.
        - Otherwise, if `resolved_target` code hash is empty, i.e. `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`, execute the logic described in [default code](#default-code).
        - Otherwise, if `resolved_target` uses an [EIP-7702](./eip-7702.md) delegation indicator, execute according to [EIP-7702](./eip-7702.md)'s delegated-code semantics.
    - If a frame's execution reverts, its state changes are discarded. Additionally, if this frame has the atomic batch flag set, mark all subsequent frames in the same atomic group as skipped.
1. If frame has mode `VERIFY` the following additional requirements are imposed:
    - A registered-static VERIFY frame is evaluated natively as described above and does not enter the EVM.
    - Every other VERIFY frame executes as a `STATICCALL`, disallowing state manipulation.
        - Only `APPROVE` can modify the state or transaction context in `VERIFY`.
    - If the frame reverts, the transaction is invalid. This would unroll any effects of `APPROVE`.""",
    "frame dispatch",
)

replace_once(
    """- If `mode` is `VERIFY`:
  - Read the allowed approval scope from the flags field: `allowed_scope = frame.flags & APPROVE_SCOPE_MASK`.
  - If `allowed_scope == APPROVE_SCOPE_NONE`, revert.
  - Let `sig_index = 0` if `allowed_scope & APPROVE_EXECUTION != 0`, else `sig_index = 1`.
  - If no signature exists at `sig_index`, revert. Let `sig` be that signature; the default code does not scan other indices.
  - Require `resolved_signer == resolved_target` and `sig.msg == Bytes()`.
  - If `sig.scheme == SECP256K1`, no further signature-specific check is required.
  - If `sig.scheme == EIP8130_ACTOR`, require its cached `ActorValidation` result and let `scope` be `result.scope`. Then:
    - If `(scope & EIP8130_SCOPE_POLICY) != 0`, revert, regardless of any other scope bits.
    - If execution approval is requested, require `scope == 0` or `(scope & EIP8130_SCOPE_SENDER) != 0`.
    - If payment approval is requested and `resolved_target == tx.sender`, require `scope == 0` or `(scope & EIP8130_SCOPE_SELF_PAYER) != 0`.
    - If payment approval is requested and `resolved_target != tx.sender`, require `scope == 0` or `(scope & EIP8130_SCOPE_SPONSOR_PAYER) != 0`.
  - If `sig.scheme` is neither `SECP256K1` nor `EIP8130_ACTOR`, revert.
  - Call `APPROVE(allowed_scope)`.
- If `mode` is `SENDER` or `DEFAULT`:
  - Return successfully as if calling empty code.

The empty-`msg` requirement is unconditional for default code: an explicit digest does not commit to the frame list and can never authorize execution or payment here. `POLICY` actors are also unconditionally rejected because default code cannot enforce their manager gate. Accounts that need policy execution or an unsupported authenticator must deploy or delegate validation code and use a `VERIFY` frame.""",
    """- If `mode` is `VERIFY`:
  - Read the allowed approval scope from the flags field: `allowed_scope = frame.flags & APPROVE_SCOPE_MASK`.
  - If `allowed_scope == APPROVE_SCOPE_NONE`, revert.
  - Let `sig_index = 0` if `allowed_scope & APPROVE_EXECUTION != 0`, else `sig_index = 1`.
  - If no signature exists at `sig_index`, revert. Let `sig` be that signature; the default code does not scan other indices.
  - Require `resolved_signer == resolved_target` and `sig.msg == Bytes()`.
  - Require `sig.scheme == SECP256K1`; every `EIP8130_ACTOR` signature selected at this index has already been consumed by the registered-static VERIFY path before default-code dispatch.
  - Call `APPROVE(allowed_scope)`.
- If `mode` is `SENDER` or `DEFAULT`:
  - Return successfully as if calling empty code.

The empty-`msg` requirement is unconditional for default code: an explicit digest does not commit to the frame list and can never authorize execution or payment here. Registered actors, including actors registered for accounts with deployed or delegated code, are handled by the protocol-defined registered-static VERIFY path. Accounts that need policy execution or an unsupported authenticator must use ordinary account-code validation in a `VERIFY` frame.""",
    "default code",
)

replace_once(
    "3. `self_verify` and `only_verify` must execute in `VERIFY` mode, target `tx.sender` (either explicitly or via a null target), must successfully call `APPROVE`, and `frame.flags` must match the scope of the `APPROVE` call.",
    "3. `self_verify` and `only_verify` must execute in `VERIFY` mode, target `tx.sender` (either explicitly or via a null target), and `frame.flags` must match the approval scope. They must either successfully call `APPROVE` or be registered-static VERIFY frames whose native evaluation applies the equivalent approval effects.",
    "mempool structural approval",
)

replace_once(
    "9. Every `EIP8130_ACTOR` entry must have empty `msg` and must be the signature at the deterministic index selected by a default-code `VERIFY` frame in the validation prefix. Reject unused entries, entries consumed only outside the validation prefix, and explicit-message entries.",
    "9. Every `EIP8130_ACTOR` entry must have empty `msg` and must be the signature at the deterministic index selected by a registered-static `VERIFY` frame in the validation prefix. The target may have empty, deployed, or delegated code because that code is not executed by this path. Reject unused entries, entries consumed only outside the validation prefix, and explicit-message entries.",
    "mempool actor consumption",
)

replace_once(
    """Three frame species in the validation prefix have fully protocol-defined semantics, leaving no deployed code whose behavior a node would need to discover by execution: a frame whose resolved target has the empty code hash (default code), an expiry verifier frame whose runtime code at `EXPIRY_VERIFIER` matches the canonical expiry verifier code, and a `pay` frame admitted by canonical paymaster code match per the previous section.

When every frame in the validation prefix is one of these, direct evaluation of the protocol-defined semantics is equivalent to simulation, and a node MAY use it to satisfy the validation requirements below. Direct evaluation MUST apply the same limits as simulation: signature validation and the evaluated frames' work count against `MAX_VERIFY_GAS`, and the paymaster accounting rules in this section apply unchanged.

The complete state dependency set of such a validation prefix is: the sender's code hash and nonce, the payer's code hash and balance (or the canonical paymaster's tracked state), the runtime code at `EXPIRY_VERIFIER` together with the frame's deadline when an expiry verifier frame is present, the exact `(ACCOUNT_CONFIG_ADDRESS, storage_slot)` and `expiry` returned by every `EIP8130_ACTOR` validation, and the current block timestamp. Nodes SHOULD index pending transactions by this set so that head-of-chain changes are revalidated without re-execution.""",
    """Four frame species in the validation prefix have fully protocol-defined semantics, leaving no deployed code whose behavior a node would need to discover by execution: a registered-static VERIFY frame, a frame whose resolved target has the empty code hash and uses ordinary default code, an expiry verifier frame whose runtime code at `EXPIRY_VERIFIER` matches the canonical expiry verifier code, and a `pay` frame admitted by canonical paymaster code match per the previous section.

When every frame in the validation prefix is one of these, direct evaluation of the protocol-defined semantics is equivalent to simulation, and a node MAY use it to satisfy the validation requirements below. Direct evaluation MUST apply the same limits as simulation: signature validation and the evaluated frames' work count against `MAX_VERIFY_GAS`, and the paymaster accounting rules in this section apply unchanged.

The complete state dependency set of such a validation prefix is: the sender's nonce; the sender's code hash only when a deploy or ordinary default-code decision depends on it; the payer's balance and, when relevant, code hash or canonical-paymaster tracked state; the runtime code at `EXPIRY_VERIFIER` together with the frame's deadline when an expiry verifier frame is present; the exact `(ACCOUNT_CONFIG_ADDRESS, storage_slot)` and `expiry` returned by every `EIP8130_ACTOR` validation; and the current block timestamp. A registered-static VERIFY frame does not depend on the target account's runtime or delegated code because clients MUST NOT load or execute it. Nodes SHOULD index pending transactions by this set so that head-of-chain changes are revalidated without re-execution.""",
    "direct evaluation",
)

replace_once(
    "The public mempool is narrower: every `EIP8130_ACTOR` entry must carry empty `msg` and be consumed by protocol-defined default code in the validation prefix. This prevents an unused signature over an explicit digest from being copied into unrelated transactions to reserve or create a revalidation dependency on another account's actor slot. Consensus-valid transactions outside this rule remain eligible only for local or private handling.",
    "The public mempool is narrower: every `EIP8130_ACTOR` entry must carry empty `msg` and be consumed by a protocol-defined registered-static VERIFY frame in the validation prefix. This prevents an unused signature over an explicit digest from being copied into unrelated transactions to reserve or create a revalidation dependency on another account's actor slot. Consensus-valid transactions outside this rule remain eligible only for local or private handling.",
    "actor dependency consumption",
)

replace_once(
    "2. The node performs all stateless transaction and signature-shape checks, analyzes the frame structure, and determines the validation prefix. If the prefix is not recognized, reject. For every `EIP8130_ACTOR` entry, also require empty `msg` and a candidate default-code `VERIFY` frame in the prefix that selects its deterministic signature index.",
    "2. The node performs all stateless transaction and signature-shape checks, analyzes the frame structure, and determines the validation prefix. If the prefix is not recognized, reject. For every `EIP8130_ACTOR` entry, also require empty `msg` and a candidate registered-static `VERIFY` frame in the prefix that selects its deterministic signature index.",
    "acceptance step 2",
)

replace_once(
    "4. The node simulates the validation prefix and enforces the structural and trace rules above, except that a `pay` frame whose target runtime code exactly matches the canonical paymaster implementation is handled via the canonical paymaster exception and the paymaster-specific rules below. Confirm that every `EIP8130_ACTOR` entry was actually consumed by default code; otherwise reject.",
    "4. The node simulates or directly evaluates the validation prefix and enforces the structural and trace rules above, except that registered-static VERIFY frames are evaluated natively and a `pay` frame whose target runtime code exactly matches the canonical paymaster implementation is handled via the canonical paymaster exception and the paymaster-specific rules below. Confirm that every `EIP8130_ACTOR` entry was actually consumed by registered-static VERIFY semantics; otherwise reject.",
    "acceptance step 4",
)

replace_once(
    "6. For every `EIP8130_ACTOR` entry, the node enforces the empty-message and default-code-consumption rule, records its exact actor-validation storage key and expiry, and enforces `MAX_PENDING_TXS_PER_ACTOR_SLOT`.",
    "6. For every `EIP8130_ACTOR` entry, the node enforces the empty-message and registered-static-consumption rule, records its exact actor-validation storage key and expiry, and enforces `MAX_PENDING_TXS_PER_ACTOR_SLOT`.",
    "acceptance step 6",
)

replace_once(
    """`EIP8130_ACTOR` lets code-less accounts reuse EIP-8130's actor authorization surface in default code. It does not move public keys out of the transaction: P256 still carries `qx` and `qy` in `data`. The state saving is the reuse of the actor's existing authenticator, scope, and expiry configuration rather than a second 8141-specific registry.

The consensus surface is deliberately smaller than EIP-8130's extensible authenticator model. A transaction cannot select a registry, clients never execute authenticator code during outer-signature validation, and only native secp256k1 and enshrined P256 are recognized. This makes validation exactly one fixed-cost cryptographic operation plus one exactly identified configuration SLOAD. Passkey, delegate, custom, and future authenticators stay in `VERIFY` frames until a separate proposal defines fixed byte-level and gas semantics for another native fast path.

The actor result is cached only for protocol-defined consumers. Avoiding a new EVM-visible actor ABI keeps the fast path from becoming a generic authorization primitive and leaves custom account policy in `VERIFY` code.""",
    """`EIP8130_ACTOR` lets any account, including a deployed or EIP-7702 delegated smart account, opt into an EIP-8130 registry-backed root authorization path. Selecting scheme `0x03` at the deterministic signature index tells clients to validate the registered K1 or P256 actor natively and apply the requested VERIFY approval scope without executing wallet code. The account's registration is the source of truth for whether that actor and authenticator are authorized.

The current EIP-8130 layout does not duplicate public-key bytes in the registry: P256 still carries `qx` and `qy` in `data`, while the registry binds the derived actor identity to its authenticator, scope, and expiry. A future registry layout may store the public key itself without changing the separation between native authentication and frame approval.

The consensus surface is deliberately smaller than EIP-8130's extensible authenticator model. A transaction cannot select a registry, clients never execute authenticator code during outer-signature validation, and only native secp256k1 and enshrined P256 are recognized. This makes validation exactly one fixed-cost cryptographic operation plus one exactly identified configuration SLOAD. Passkey, delegate, custom, and future authenticators stay in ordinary `VERIFY` frames until a separate proposal defines fixed byte-level and gas semantics for another native fast path.

Registration for a scope is an explicit opt-in to bypass account validation code for that scope. The registered-static path rejects every `POLICY` actor and exposes no generic actor ABI to EVM code. Multisig, session keys, spending limits, guardians, and other account-specific policy remain in ordinary `VERIFY` code.""",
    "actor fast-path rationale",
)

replace_once(
    """This example illustrates the initial deployment flow for a smart account at the `sender` address. Since the address needs to have code in order to validate the transaction, the transaction must deploy the code before verification.

The first frame would call the [EIP-7997](./eip-7997.md) deterministic factory predeploy. The deployer determines the address in a deterministic way from the salt and initcode. However, since the transaction sender is not authenticated at this point, the user must choose an initcode which is safe to deploy by anyone.

#### Example 2: Atomic Approve + Swap""",
    """This example illustrates the initial deployment flow for a smart account at the `sender` address. Since the address needs to have code in order to validate the transaction, the transaction must deploy the code before verification.

The first frame would call the [EIP-7997](./eip-7997.md) deterministic factory predeploy. The deployer determines the address in a deterministic way from the salt and initcode. However, since the transaction sender is not authenticated at this point, the user must choose an initcode which is safe to deploy by anyone.

#### Example 1c: Registered smart account fast path

| Frame | Mode   | Caller      | Flags                         | Target        | Value | Data  |
| ----- | ------ | ----------- | ----------------------------- | ------------- | ----- | ----- |
| 0     | VERIFY | ENTRY_POINT | APPROVE_EXECUTION_AND_PAYMENT | Null (sender) | 0     | Empty |
| 1     | SENDER | Sender      | APPROVE_SCOPE_NONE            | Target        | 0     | Call data |

The sender already has deployed or delegated smart-account code, but signature entry `0` uses `EIP8130_ACTOR` with empty `msg`. The protocol validates the K1 or P256 witness, reads the sender's exact actor configuration slot, checks its scope and expiry, and applies `APPROVE_EXECUTION_AND_PAYMENT` directly. It does not fetch or execute the smart account's validation code for frame 0. The same account can still choose an `ARBITRARY` signature and ordinary `VERIFY` execution for transactions requiring its programmable validation policy.

#### Example 2: Atomic Approve + Swap""",
    "registered account example",
)

replace_once(
    "Requiring every propagated entry to have empty `msg` and be consumed by default code prevents a reusable explicit-digest signature from being attached as an unused dependency to poison the slot reservation.",
    "Requiring every propagated entry to have empty `msg` and be consumed by registered-static VERIFY semantics prevents a reusable explicit-digest signature from being attached as an unused dependency to poison the slot reservation.",
    "security consumption",
)

replace_once(
    "Actor configuration is read at inclusion time. A configuration change after signing invalidates the transaction, as does passage beyond a nonzero actor expiry. The authenticator selector remains in `compute_sig_hash(tx)` for empty-message signatures, so a witness cannot be transplanted between the K1 and P256 validation rules. Default code additionally requires an empty message and rejects every `POLICY` actor, preventing an explicit-digest replay or bypass of EIP-8130's manager gate.",
    "Actor configuration is read at inclusion time. A configuration change after signing invalidates the transaction, as does passage beyond a nonzero actor expiry. The authenticator selector remains in `compute_sig_hash(tx)` for empty-message signatures, so a witness cannot be transplanted between the K1 and P256 validation rules. Registered-static VERIFY additionally requires an empty message and rejects every `POLICY` actor, preventing an explicit-digest replay or bypass of EIP-8130's manager gate.",
    "security scope",
)

security_anchor = "Unsupported authenticators execute only inside explicitly budgeted `VERIFY` frames. They are never called while consensus validates the outer signature list."
security_insert = security_anchor + """

#### Registered-static authorization is root authority

Registering an actor with sender or payer scope authorizes that actor to bypass the account's ordinary validation code whenever a transaction explicitly selects `EIP8130_ACTOR` at the deterministic VERIFY signature index. Wallets must treat such registrations as root credentials for the granted scope and protect rotation and revocation accordingly. The empty `msg` requirement binds approval to the complete canonical frame transaction, including every subsequent `SENDER` frame; it does not narrow approval to a single call. Complex or limited permissions must remain in ordinary account-code validation rather than this path."""
replace_once(security_anchor, security_insert, "root authority security")

# Guard against the most important stale statements that would contradict the
# new smart-account path.
stale = [
    "cached by signature index for default-code authorization",
    "consumed by protocol-defined default code in the validation prefix",
    "candidate default-code `VERIFY` frame",
    "actually consumed by default code",
    "empty-message and default-code-consumption rule",
    "lets code-less accounts reuse EIP-8130's actor authorization surface",
]
for phrase in stale:
    if phrase in text:
        raise RuntimeError(f"stale wording remains: {phrase}")

PATH.write_text(text, encoding="utf-8")
print("Updated EIPS/eip-8141.md with registered-static VERIFY semantics")
