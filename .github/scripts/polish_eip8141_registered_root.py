from pathlib import Path

PATH = Path("EIPS/eip-8141.md")
text = PATH.read_text()


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected exactly one match, found {count}: {old!r}")
    text = text.replace(old, new, 1)


replace_once(
    "Its account-indexed configuration model is inspired by [EIP-8130](./eip-8130.md), but the registry is independent from [EIP-8130](./eip-8130.md) and does not import its actors, authenticators, delegates, scopes, expiry, or policy-manager semantics.",
    "Its account-indexed configuration model is inspired by [EIP-8130](./eip-8130.md), but it is otherwise independent and does not import EIP-8130 actors, authenticators, delegates, scopes, expiry, or policy-manager semantics.",
)

replace_once(
    "This preserves the existing this EIP frame structure, including direct root-key sponsorship by an account other than `tx.sender`.",
    "This preserves the existing frame structure defined by this EIP, including direct root-key sponsorship by an account other than `tx.sender`.",
)

replace_once(
    "#### Example 3: Sponsored Transaction (Fee Payment in ERC-20)",
    "#### Example 3: Sponsored Transaction (Fee Payment in [ERC-20](./eip-20.md))",
)

replace_once(
    "Once the validation prefix reaches payer approval via `APPROVE(APPROVE_PAYMENT)` or `APPROVE(APPROVE_EXECUTION_AND_PAYMENT)`, the transaction can be included in the mempool and propagated to peers safely.",
    "Once the validation prefix reaches payer approval via `APPROVE(APPROVE_PAYMENT)`, `APPROVE(APPROVE_EXECUTION_AND_PAYMENT)`, or the registered-static equivalent, the transaction can be included in the mempool and propagated to peers safely.",
)

for forbidden in [
    "existing this EIP frame structure",
    "independent from [EIP-8130]",
    "Fee Payment in ERC-20",
]:
    if forbidden in text:
        raise RuntimeError(f"unpolished wording remains: {forbidden}")

for required in [
    "otherwise independent",
    "frame structure defined by this EIP",
    "or the registered-static equivalent",
]:
    if required not in text:
        raise RuntimeError(f"required wording missing: {required}")

PATH.write_text(text)
print(f"polished {PATH}")
