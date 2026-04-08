.PHONY: fmt check clean-state

fmt:
	cargo fmt

check:
	cargo fmt --check
	cargo check
	cargo test
	@! rg -n 'bigteam|BIGTEAM' AGENTS.md >/dev/null

clean-state:
	rm -rf .vcamp-state .vcamper-state
