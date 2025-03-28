.PHONY: build docker fmt fmt-check test release sbom out/ghscan

out/ghscan:
	mkdir -p out
	go build -o out/ghscan ./cmd/ghscan

keygen:
	melange keygen

melange: keygen
	melange build --arch arm64,x86_64 ghscan.yaml --signing-key melange.rsa

apko: melange
	apko build ghscan.apko.yaml ghscan:latest ghscan.tar

ghscan-docker:
	docker load < ghscan.tar

sbom:
	syft -o spdx-json . | jq . > sbom.json
