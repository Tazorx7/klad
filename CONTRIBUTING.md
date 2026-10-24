# Contributing to klad

Thank you for your interest in contributing to klad! We welcome contributions from the community.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/klad.git`
3. Create a feature branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run tests: `cargo test`
6. Run clippy: `cargo clippy`
7. Commit your changes: `git commit -am 'Add some feature'`
8. Push to the branch: `git push origin feature/your-feature`
9. Open a Pull Request

## Development Guidelines

### Code Style
- Follow Rust standard formatting: run `cargo fmt` before committing
- Pass all clippy lints: `cargo clippy -- -D warnings`
- Add tests for new features and bug fixes
- Keep functions small and focused

### Adding New Rules

1. Add the rule to the appropriate scanner module
2. Use a unique rule ID following the existing pattern (DF-XXX, K8S-XXX, SEC-XXX)
3. Add appropriate severity level
4. Include clear title, description, and remediation
5. Add unit tests
6. Update README.md with the new rule

### Adding New Scanners

1. Create a new module in `src/scanner/`
2. Implement `is_candidate()` and `scan()` functions
3. Add to `src/scanner/mod.rs`
4. Add tests
5. Update README and documentation

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test dockerfile::tests
```

## Performance

klad prioritizes speed. When adding features:
- Use the single-pass discovery mechanism
- Avoid multiple file reads
- Use parallel processing where appropriate
- Consider using Aho-Corasick or byte-level operations for hot paths
- Add benchmarks if relevant

## Pull Request Process

1. Update the README.md with details of changes if applicable
2. Ensure all tests pass and clippy is clean
3. Update version numbers if needed (we use semver)
4. The PR will be reviewed by maintainers
5. Once approved, it will be merged

## Code of Conduct

Be respectful, inclusive, and professional in all interactions.

## Questions?

Feel free to open an issue for discussion before starting major work.
