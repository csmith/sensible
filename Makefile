PREFIX ?= /usr/local

.PHONY: all sensible install clean

all: sensible

sensible:
	go generate ./...
	go build -trimpath -o sensible ./cmd/sensible

install: sensible
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/bash-completion/completions $(DESTDIR)$(PREFIX)/share/zsh/site-functions
	install -m 755 sensible $(DESTDIR)$(PREFIX)/bin/sensible
	install -m 644 completions/sensible.bash $(DESTDIR)$(PREFIX)/share/bash-completion/completions/sensible
	install -m 644 completions/_sensible $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_sensible

clean:
	rm -f sensible internal/run/agents/*.gz
