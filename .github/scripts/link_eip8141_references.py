from __future__ import annotations

import re
from pathlib import Path

PATH = Path("EIPS/eip-8141.md")
text = PATH.read_text()


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected exactly one match, found {count}: {old!r}")
    text = text.replace(old, new, 1)


# Avoid self-links and keep the prose natural.
replace_once(
    "EIP-8141 defines a canonical state-backed root-key registry.",
    "This EIP defines a canonical state-backed root-key registry.",
)
replace_once(
    "before EIP-8141 default-code handling.",
    "before the default-code handling defined by this EIP.",
)
replace_once(
    "The registry is defined directly in EIP-8141",
    "The registry is defined directly in this EIP",
)

REFERENCE = re.compile(r"(?<![\[/])\b(EIP|ERC)-(\d+)\b", re.IGNORECASE)
LINK = re.compile(r"\[[^\]]*\]\([^)]*\)")


def link_segment(segment: str) -> str:
    """Link plain EIP/ERC references while preserving existing Markdown links."""
    pieces: list[str] = []
    cursor = 0
    for match in LINK.finditer(segment):
        pieces.append(link_plain(segment[cursor : match.start()]))
        pieces.append(match.group(0))
        cursor = match.end()
    pieces.append(link_plain(segment[cursor:]))
    return "".join(pieces)


def link_plain(segment: str) -> str:
    def repl(match: re.Match[str]) -> str:
        kind = match.group(1).upper()
        number = match.group(2)
        if number == "8141":
            raise RuntimeError(f"unhandled self-reference in prose: {match.group(0)!r}")
        return f"[{kind}-{number}](./eip-{number}.md)"

    return REFERENCE.sub(repl, segment)


lines = text.splitlines(keepends=True)
output: list[str] = []
in_fence = False

for line_number, line in enumerate(lines, 1):
    stripped = line.lstrip()
    if stripped.startswith("```"):
        in_fence = not in_fence
        output.append(line)
        continue

    # EIPW does not require references inside code or headings to be links;
    # preserving headings also preserves their existing anchors.
    if in_fence or stripped.startswith("#"):
        output.append(line)
        continue

    # Preserve inline-code spans. EIP-8141 uses ordinary single-backtick spans.
    parts = line.split("`")
    for index in range(0, len(parts), 2):
        parts[index] = link_segment(parts[index])
    output.append("`".join(parts))

if in_fence:
    raise RuntimeError("unclosed fenced code block")

text = "".join(output)

# Detect any remaining plain references outside code, headings, and inline code.
remaining: list[str] = []
in_fence = False
for line_number, line in enumerate(text.splitlines(), 1):
    stripped = line.lstrip()
    if stripped.startswith("```"):
        in_fence = not in_fence
        continue
    if in_fence or stripped.startswith("#"):
        continue
    parts = line.split("`")
    for index in range(0, len(parts), 2):
        segment = LINK.sub("", parts[index])
        if REFERENCE.search(segment):
            remaining.append(f"{line_number}: {line}")

if remaining:
    raise RuntimeError("unlinked references remain:\n" + "\n".join(remaining))

for required in [
    "[EIP-1559](./eip-1559.md)",
    "[EIP-4844](./eip-4844.md)",
    "[EIP-7702](./eip-7702.md)",
    "[EIP-8130](./eip-8130.md)",
    "[ERC-20](./eip-20.md)",
    "[ERC-4337](./eip-4337.md)",
]:
    if required not in text:
        raise RuntimeError(f"expected linked reference missing: {required}")

PATH.write_text(text)
print(f"linked references in {PATH}: {len(text.splitlines())} lines")
