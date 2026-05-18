.PHONY: build docker fmt fmt-check test integration integration-verify release sbom verify out/ghscan

out/ghscan:
	mkdir -p out
	go build -o out/ghscan ./cmd/ghscan

test:
	go test -race -count=1 ./...

# integration runs the build-tag-gated end-to-end suite. It requires
# GHSCAN_INT=1 and GITHUB_TOKEN to be exported in the environment;
# without them the suite skips. The build tag itself is verified to
# compile here even when the env vars are unset.
integration:
	go test -tags=integration -count=1 ./...

verify:
	go vet ./...
	gofumpt -l . | tee /dev/stderr | (! read)
	golangci-lint run ./...
	nilaway ./...
	gosec -quiet ./...
	go test -race -count=1 ./...

integration-verify: verify
	GHSCAN_INT=1 go test -tags=integration -count=1 -race -timeout=5m -run TestIntegration ./internal/action/...

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
