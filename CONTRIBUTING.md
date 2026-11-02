# Contributing

Use a stable Rust toolchain (1.88 or newer). Run `make check` before submitting changes: it checks
formatting, runs Clippy with warnings denied and runs the tests with every feature enabled.

The auth layer (`src/*.rs`) is handwritten. The Admin, Management and Auth API clients in
`src/admin`, `src/management` and `src/auth_api` are generated from Lock's OpenAPI specs in
`openapi/spec`; never edit them by hand. Generation needs Java 21 or newer, Python 3 and `curl`.

- `make generate` regenerates the clients from the committed specs.
- `make sync-openapi` downloads Lock's specs first (`LOCK_REF=<branch|tag|commit>` selects the revision).
- `make check-generated` fails when the committed clients are stale.
- Public operation names live in `openapi/operations.json`; `bin/prepare-openapi.py` prepares the specs for the generator.

Tests run against a local fake authorization server (`tests/support`) and need no network.

Use Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`) for Release Please. Do not commit
`target/` or `Cargo.lock`.
