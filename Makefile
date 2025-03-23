.PHONY: build docker fmt fmt-check test release sbom out/tjscan

out/tjscan:
	mkdir -p out
	go build -o out/tjscan ./cmd/tj-scan

keygen:
	melange keygen

melange: keygen
	melange build --arch arm64,x86_64 tj-scan.yaml --signing-key melange.rsa

apko: melange
	apko build tj-scan.apko.yaml tjscan:latest tjscan.tar

tj-scan-docker:
	docker load < tjscan.tar

sbom:
	syft -o spdx-json . | jq . > sbom.json
