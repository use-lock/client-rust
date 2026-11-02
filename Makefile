.PHONY: generate sync-openapi check-generated test check

# Regenerate the Admin, Management and Auth API clients from the committed specifications.
generate:
	bash bin/generate

# Download the specifications from use-lock/lock (LOCK_REF selects a branch, tag or commit) and regenerate.
sync-openapi:
	bash bin/sync-openapi

# Fail when src/admin, src/management or src/auth_api differ from what the specs generate.
check-generated:
	bash bin/check-generated

test:
	cargo test --all-features

check:
	cargo fmt --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test --all-features
