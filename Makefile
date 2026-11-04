.PHONY: all check test lint fmt e2e docs dev-server clean

all: check test

check: fmt lint test

test:
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all --check

fmt-fix:
	cargo fmt --all

e2e:
	cargo test --test e2e -- --nocapture

docs:
	cargo doc --workspace --no-deps

dev-server:
	cargo run --bin sshkmad -- serve --config config/dev.toml

clean:
	cargo clean
