from pathlib import Path

path = Path("EIPS/eip-8141.md")
text = path.read_text(encoding="utf-8")

replacements = [
    (
        "    - `self_verify` must call `APPROVE(APPROVE_EXECUTION_AND_PAYMENT)`.\n    - `only_verify` must call `APPROVE(APPROVE_EXECUTION)`.",
        "    - `self_verify` must approve `APPROVE_EXECUTION_AND_PAYMENT`.\n    - `only_verify` must approve `APPROVE_EXECUTION`.",
    ),
    (
        "4. `pay` must execute in `VERIFY` mode, have flags set to `APPROVE_PAYMENT`, and must successfully call `APPROVE(APPROVE_PAYMENT)`",
        "4. `pay` must execute in `VERIFY` mode, have flags set to `APPROVE_PAYMENT`, and must produce `APPROVE_PAYMENT` either by successfully calling `APPROVE(APPROVE_PAYMENT)` or through registered-static VERIFY semantics.",
    ),
    (
        "- a `self_verify`, `only_verify`, or `pay` frame exits without its required `APPROVE`",
        "- a `self_verify`, `only_verify`, or `pay` frame exits without producing its required approval",
    ),
]

for old, new in replacements:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected one occurrence, found {count}: {old}")
    text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
print("Finalized registered-static approval wording")
