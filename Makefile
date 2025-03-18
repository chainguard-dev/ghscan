.PHONY: build docker fmt fmt-check test release sbom out/tjscan

out/tjscan:
	mkdir -p out
	go build -o out/tjscan ./cmd/tj-scan

keygen:
	melange keygen

melange: keygen
	melange build --arch arm64,x86_64 tj-scan.yaml --signing-key melange.rsa --git-repo-url  https://github.com/chainguard-dev/tj-scan --git-commit 3741c1c55ec24c9768546ab7796b453ffe630c1b

apko: melange
	apko build tjscan.apko.yaml tjscan:latest tjscan.tar

tj-scan-docker:
	docker load < tjscan.tar

sbom:
	syft -o spdx-json . | jq . > sbom.json
