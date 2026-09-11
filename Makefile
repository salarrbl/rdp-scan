.PHONY: build test clean install test-local test-sample check fmt

build:
	go build -o rdp-scan ./cmd/rdp-scan

test:
	go test ./...

clean:
	rm -f rdp-scan rdp_live.txt test-output.txt test-local-out.txt

install:
	go install ./cmd/rdp-scan

# Test with local listener
test-local:
	@test -f test-local.txt || (echo "missing test-local.txt"; exit 1)
	./rdp-scan test-local.txt -o test-local-out.txt -c 5 -t 1s
	@cat test-local-out.txt 2>/dev/null || echo "(no results)"

# Test with sample data
test-sample:
	./rdp-scan test-ranges.txt -o test-output.txt -c 10 -t 1s
	@echo "Results:"
	@cat test-output.txt 2>/dev/null || echo "(no results)"

# Quick syntax check
check:
	go vet ./...

# Format code
fmt:
	go fmt ./...
