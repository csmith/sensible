.PHONY: all sensible clean

all: sensible

sensible:
	go generate ./...
	go build -trimpath -o sensible ./cmd/sensible

clean:
	rm -f sensible internal/run/agents/*.gz
