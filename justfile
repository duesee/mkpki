_default:
	just -l --unsorted

install: install_lint

install_lint:
	go install github.com/zmap/zlint/v3/cmd/zlint@latest

docker_build:
	docker build . --tag pki

docker_run:
	docker run -it --rm -p3000:3000 pki

chain:
	#!/usr/bin/env bash
	set -euxo pipefail

	mkdir -p private
	cd private
	cargo run -- --seed root         root                                               DE Example example.org
	cargo run -- --seed intermediate intermediate root-key.pem         root.pem         DE Example intermediate.example.org
	cargo run -- --seed leaf         leaf         intermediate-key.pem intermediate.pem leaf.intermediate.example.org

lint: chain
	zlint -pretty -summary private/root.pem private/intermediate.pem private/leaf.pem
