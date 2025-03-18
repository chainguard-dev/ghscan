.PHONY: build docker fmt fmt-check test release sbom out/tjscan

out/tjscan:
	mkdir -p out
	go build -o out/tjscan ./cmd/tj-scan

keygen:
	melange keygen

melange: keygen
	melange build --arch arm64,x86_64 tj-scan.yaml --signing-key melange.rsa --git-repo-url  https://github.com/chainguard-dev/tj-scan --git-commit 10f3937a7a56ef01cfbbd3ed6edece2d3c3cd673

apko: melange
	apko build rsd.apko.yaml rsd:latest rsd.tar

tj-scan-docker:
	docker load < tj-scan.tar

docker:
	docker buildx build -t tj-scan:latest .

sbom:
	syft -o spdx-json . | jq . > sbom.json
