PREFIX ?= /usr
LIBDIR ?= $(PREFIX)/lib/sigint
SYSCONFDIR ?= /etc/sigint
STATEDIR ?= /var/lib/sigint
RUNDIR ?= /run/sigint
SYSTEMDDIR ?= /usr/lib/systemd/system

ZIG ?= zig
ZIGFLAGS ?= -Doptimize=ReleaseSafe

.PHONY: all build test install install-binaries install-systemd install-dirs \
        install-config uninstall clean setup-users

all: build

build:
	$(ZIG) build $(ZIGFLAGS)

test:
	$(ZIG) build test

clean:
	rm -rf zig-out .zig-cache

# -- Installation --

install: install-dirs install-binaries install-systemd install-config

install-dirs:
	install -d -m 0755 $(DESTDIR)$(LIBDIR)
	install -d -m 0750 $(DESTDIR)$(SYSCONFDIR)
	install -d -m 0700 $(DESTDIR)$(STATEDIR)
	install -d -m 0700 $(DESTDIR)$(STATEDIR)/profiles
	install -d -m 0700 $(DESTDIR)$(STATEDIR)/drops

install-binaries: build
	install -m 0755 zig-out/bin/sigint-collector $(DESTDIR)$(LIBDIR)/
	install -m 0755 zig-out/bin/sigint-analyzer $(DESTDIR)$(LIBDIR)/
	install -m 0755 zig-out/bin/sigint-enforcer $(DESTDIR)$(LIBDIR)/
	install -m 0755 zig-out/bin/sigint-ctl $(DESTDIR)$(PREFIX)/bin/sigint-ctl

install-systemd:
	install -d -m 0755 $(DESTDIR)$(SYSTEMDDIR)
	install -m 0644 systemd/sigint-collector.service $(DESTDIR)$(SYSTEMDDIR)/
	install -m 0644 systemd/sigint-analyzer.service $(DESTDIR)$(SYSTEMDDIR)/
	install -m 0644 systemd/sigint-enforcer.service $(DESTDIR)$(SYSTEMDDIR)/

install-config:
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/policy.toml ]; then \
		install -m 0640 doc/policy-example.toml $(DESTDIR)$(SYSCONFDIR)/policy.toml; \
		echo "installed default policy to $(SYSCONFDIR)/policy.toml"; \
	else \
		echo "policy.toml exists, not overwriting"; \
	fi

# -- System user/group setup (requires root) --

setup-users:
	@echo "Creating system users and groups..."
	getent group sigint >/dev/null 2>&1 || groupadd -r sigint
	getent passwd sigint-collector >/dev/null 2>&1 || \
		useradd -r -g input -G sigint -s /sbin/nologin -d /nonexistent \
		-c "SIGINT Collector" sigint-collector
	getent passwd sigint-analyzer >/dev/null 2>&1 || \
		useradd -r -g sigint -s /sbin/nologin -d /nonexistent \
		-c "SIGINT Analyzer" sigint-analyzer
	getent passwd sigint-enforcer >/dev/null 2>&1 || \
		useradd -r -g sigint -s /sbin/nologin -d /nonexistent \
		-c "SIGINT Enforcer" sigint-enforcer
	chown sigint-analyzer:sigint $(STATEDIR)
	chown sigint-analyzer:sigint $(STATEDIR)/profiles
	@echo "Done."

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/sigint-collector
	rm -f $(DESTDIR)$(LIBDIR)/sigint-analyzer
	rm -f $(DESTDIR)$(LIBDIR)/sigint-enforcer
	rm -f $(DESTDIR)$(PREFIX)/bin/sigint-ctl
	rm -f $(DESTDIR)$(SYSTEMDDIR)/sigint-collector.service
	rm -f $(DESTDIR)$(SYSTEMDDIR)/sigint-analyzer.service
	rm -f $(DESTDIR)$(SYSTEMDDIR)/sigint-enforcer.service
	@echo "Binaries and services removed."
	@echo "Config ($(SYSCONFDIR)) and state ($(STATEDIR)) preserved."
	@echo "Run 'make uninstall-full' to remove everything."

uninstall-full: uninstall
	rm -rf $(DESTDIR)$(SYSCONFDIR)
	rm -rf $(DESTDIR)$(STATEDIR)
	rmdir $(DESTDIR)$(LIBDIR) 2>/dev/null || true
