from pathlib import Path

PATH = Path("EIPS/eip-8141.md")
text = PATH.read_text()


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected exactly one match, found {count}: {old[:180]!r}")
    text = text.replace(old, new, 1)


replace_once("| 0x0        | `ARBITRARY`", "| 0x00       | `ARBITRARY`")
replace_once("| 0x1        | `SECP256K1`", "| 0x01       | `SECP256K1`")
replace_once("| 0x2        | `P256`", "| 0x02       | `P256`")
replace_once("| 0x3        | `REGISTERED_STATIC`", "| 0x03       | `REGISTERED_STATIC`")

replace_once(
    "`REGISTERED_KEY_REGISTRY` is a stateful system precompile. Calls to this address are dispatched to the protocol-defined behavior below before EIP-8141 default-code handling. No account code or transaction-selected implementation is executed.\n",
    "`REGISTERED_KEY_REGISTRY` is a stateful system precompile. Calls to this address are dispatched to the protocol-defined behavior below before EIP-8141 default-code handling. No account code or transaction-selected implementation is executed. At activation, clients MUST set the address's code and storage to empty before enabling the precompile; any balance and nonce remain unchanged.\n",
)

replace_once(
    "Mutating methods are valid only through `CALL`; invoking them through `STATICCALL`, `DELEGATECALL`, or `CALLCODE` reverts.",
    "Mutating methods are valid only in an ordinary call context, including a top-level transaction call or EVM `CALL`; invoking them through `STATICCALL`, `DELEGATECALL`, or `CALLCODE` reverts.",
)

replace_once(
    "- `setR1` requires `qx` and `qy` to encode a valid non-infinity secp256r1 affine point and replaces the caller's entry with that root public key.",
    "- `setR1` replaces the caller's entry with `qx` and `qy`, using the same 32-byte big-endian field-element encoding as `P256VERIFY`. The precompile does not prove possession or validate the point during registration; unusable coordinates simply cannot produce a valid signature.",
)

replace_once(
    "Calls use normal EVM call, calldata, memory, state-journaling, `SSTORE`, and refund rules; native dispatch adds no separate gas charge.",
    "Calls use normal EVM call, calldata, memory, state-journaling, `SLOAD`, `SSTORE`, and refund rules; native dispatch adds no separate gas charge.",
)

replace_once(
    "        return False\n        return False\n\n    elif sig.scheme == ARBITRARY:",
    "        return False\n\n    elif sig.scheme == ARBITRARY:",
)

replace_once(
    "    - `sender_approved = false`\n\n\nA `VERIFY` frame selects",
    "    - `sender_approved = false`\n\nA `VERIFY` frame selects",
)

replace_once(
    "- execution reads storage outside `tx.sender`\n- execution performs `CALL*` or `EXTCODE*`",
    "- execution reads storage outside `tx.sender`\n- EVM execution calls `REGISTERED_KEY_REGISTRY`; the direct registry lookup performed while validating `REGISTERED_STATIC` is not EVM execution and is the only registry access admitted in the public validation prefix\n- execution performs `CALL*` or `EXTCODE*`",
)

replace_once(
    "## Backwards Compatibility\n\nThe `ORIGIN` opcode behavior changes",
    "## Backwards Compatibility\n\n`REGISTERED_KEY_REGISTRY` reserves `address(0x8142)` as a stateful system precompile. Networks activating this EIP must ensure the address is not relied upon as an ordinary account; activation clears its code and storage as specified above.\n\nThe `ORIGIN` opcode behavior changes",
)

# Mechanical sanity checks.
if "        return False\n        return False" in text:
    raise RuntimeError("duplicate return remains")
if text.count("##### Registered Root Key Registry") != 1:
    raise RuntimeError("registry section count changed")
if text.count("#### Expiry Verifier Frame") != 2:
    raise RuntimeError("unexpected expiry-verifier heading count")
if text.count("REGISTERED_STATIC") < 20:
    raise RuntimeError("registered-static coverage unexpectedly low")
if text.count("```") % 2 != 0:
    raise RuntimeError("unbalanced fenced code blocks")
for forbidden in ["EIP8130_ACTOR", "RegisteredK1", "RegisteredR1", "allowed_scope: EXECUTION"]:
    if forbidden in text:
        raise RuntimeError(f"discarded design remains: {forbidden}")

PATH.write_text(text)
print(f"finalized {PATH}: {len(text.splitlines())} lines, {len(text)} bytes")
