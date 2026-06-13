# Contributing to Hashcatizer

Thanks for your interest in contributing! This document explains how to add converters, fix bugs, and get your changes merged.

---

## Prerequisites

- [Rust](https://rustup.rs/) 1.75 or later
- Basic familiarity with binary file parsing

```bash
git clone https://github.com/nobody-Justheader/Hashcatizer.git
cd Hashcatizer
cargo build
```

---

## Adding a New Converter

### 1. Create the converter file

Add `src/converters/<name>.rs`. Every converter exposes a single public function:

```rust
pub fn convert(data: &[u8], path: &str) -> Option<Vec<String>> {
    // Return None if the file is not the right format.
    // Return Some(vec![...]) with one hashcat-ready hash string per entry.
}
```

Use helpers from `crate::common` for byte parsing:

```rust
use crate::common::{to_hex, u32_le, u32_be, u16_le, safe_slice, b64_decode};
```

### 2. Register the module

In `src/converters/mod.rs`, add two entries:

```rust
// At the top — module declaration
pub mod myformat;

// In the run() match — dispatch
"myformat" => myformat::convert(data, path),

// In all_names() — listing
"myformat",
```

### 3. Add auto-detection (optional but encouraged)

In `src/detect.rs`, add a detection rule so `hashcatizer <file>` works without specifying the converter name. Detection can use:

- **Magic bytes** — match a prefix in `MAGIC_MAP`
- **File extension** — add to the `ext` match block
- **Content heuristics** — add a check in the content-scanning section

### 4. Add a hashcat mode hint

In `src/main.rs`, add an entry to `hashcat_mode_hint()`:

```rust
"myformat" => Some("NNNNN"),
```

---

## Code Style

- Follow standard `rustfmt` formatting (`cargo fmt` before committing)
- Keep each converter self-contained in its own file
- Use `?` for propagating `Option` — converters should return `None` cleanly on malformed input, never panic
- No `unwrap()` on untrusted data; use `?` or explicit bounds checks
- Prefer `crate::common` helpers over reimplementing byte reads

Run checks before opening a PR:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo build --release
```

---

## Testing

There is no automated test suite for converter output yet (file formats require real encrypted fixtures). To manually verify your converter:

```bash
# Build
cargo build --release

# Test auto-detection
./target/release/hashcatizer /path/to/test/file

# Test explicit converter
./target/release/hashcatizer myformat /path/to/test/file

# Verify it appears in --list
./target/release/hashcatizer --list | grep myformat
```

The CI workflow (`.github/workflows/ci.yml`) builds the binary on Linux, macOS, and Windows for every PR. All three must pass before merging.

---

## Pull Request Guidelines

- One converter or fix per PR — keep changes focused
- Include the hashcat mode number in the PR description if applicable
- Reference the hashcat example hash or the original `*2john` script where relevant
- If the converter requires a new crate dependency, explain why an existing `crate::common` helper is insufficient

---

## Reporting Issues

Open a GitHub Issue with:
1. The file format / software version you are trying to convert
2. The output of `hashcatizer <file>` (redact any sensitive data)
3. The expected hashcat format (link to the hashcat example-hashes wiki if possible)
