---
name: Hidden terminal input
description: Preventing credentials from echoing when interactive terminal prompts first appear.
---

For interactive credential entry, enable raw/no-echo terminal mode before printing the prompt. Printing the prompt first creates a brief race where an operator can type while terminal echo is still enabled.

**Why:** A pseudo-terminal test reproduced this race by typing as soon as the prompt became visible, exposing the typed value in captured terminal output.

**How to apply:** For any hidden password, sigil, or token prompt, switch to no-echo mode first. Add a PTY regression check that submits input immediately after the prompt appears and asserts the entered value is absent from captured output.
