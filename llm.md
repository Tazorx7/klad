# Local Development Notes (llm.md)

This file is for local AI/LLM development context. It should NOT be committed to the repository.

## Development Setup

### Prerequisites
- Rust 1.85+ (edition 2024)
- Cargo

### Building
```bash
cargo build          # Debug build
cargo build --release # Release build with optimizations
```

### Testing
```bash
cargo test           # Run all tests
cargo test -- --nocapture
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

### Running
```bash
cargo run -- -p .    # Scan current directory
cargo run -- --help
```

### Architecture Notes
- Single-pass discovery via `ignore` crate (respects .gitignore)
- Parallel scanning with Rayon
- Aho-Corasick prefilter for secret detection
- Deterministic sorted output

### Common Tasks
- Add new rule: update appropriate scanner in `src/scanner/`
- Add output format: update `main.rs`
- Add scanner: create module in `src/scanner/`, wire in `mod.rs`

## Tips
- Use `--output json` for debugging
- Use `--verbose` patterns in tests
- CI runs fmt, clippy, test, build on every PR
