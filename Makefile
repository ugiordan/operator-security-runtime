.PHONY: test lint vet

test:
	go test ./pkg/... -v -count=1

lint:
	golangci-lint run ./pkg/...

vet:
	go vet ./pkg/...
