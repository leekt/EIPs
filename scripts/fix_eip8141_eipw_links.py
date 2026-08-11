from pathlib import Path
import re

path = Path("EIPS/eip-8141.md")
text = path.read_text(encoding="utf-8")

link_targets = {
    "EIP-1559": "./eip-1559.md",
    "EIP-4844": "./eip-4844.md",
    "EIP-7702": "./eip-7702.md",
    "EIP-7623": "./eip-7623.md",
    "EIP-2929": "./eip-2929.md",
    "ERC-20": "./eip-20.md",
    "ERC-4337": "./eip-4337.md",
}

for label, target in link_targets.items():
    # Do not touch occurrences that are already the label of a Markdown link.
    pattern = re.compile(rf"(?<!\[)\b{re.escape(label)}\b(?!\]\()")
    replacement = f"[{label}]({target})"
    text, count = pattern.subn(replacement, text)
    if count == 0:
        raise RuntimeError(f"expected at least one unlinked occurrence of {label}")
    if pattern.search(text):
        raise RuntimeError(f"unlinked occurrence remains for {label}")
    print(f"linked {count} occurrence(s) of {label}")

replacements = [
    (
        "Consensus validation records one exact storage key for every entry, whether or not default code later consumes it.",
        "Consensus validation records one exact storage key for every entry before frame processing.",
    ),
    (
        "Once the validation prefix reaches payer approval via `APPROVE(APPROVE_PAYMENT)` or `APPROVE(APPROVE_EXECUTION_AND_PAYMENT)`, the transaction can be included in the mempool and propagated to peers safely.",
        "Once the validation prefix reaches payer approval via `APPROVE(APPROVE_PAYMENT)`, `APPROVE(APPROVE_EXECUTION_AND_PAYMENT)`, or the native registered-static equivalent, the transaction can be included in the mempool and propagated to peers safely.",
    ),
    (
        "This is the `resolved_target` that called `APPROVE(APPROVE_PAYMENT)` or `APPROVE(APPROVE_EXECUTION_AND_PAYMENT)`.",
        "This is the `resolved_target` that produced payment approval by calling `APPROVE(APPROVE_PAYMENT)` or `APPROVE(APPROVE_EXECUTION_AND_PAYMENT)`, or through the native registered-static equivalent.",
    ),
]

for old, new in replacements:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected one occurrence, found {count}: {old}")
    text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
print("Updated EIPS/eip-8141.md for eipw and wording consistency")
