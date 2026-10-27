GO ?= go
TAGS ?= production webkit2_41
DIST ?= dist

.PHONY: all build build-app build-daemon build-daemon-windows test dev clean

all: build

build: build-app build-daemon

$(DIST):
	@mkdir -p $(DIST)

# The Wails GUI. It never needs root and never links the privileged packages.
build-app: | $(DIST)
	$(GO) build -tags "$(TAGS)" -trimpath -o $(DIST)/warpalt .

# The daemon. Run it from systemd (Linux) or install it as a service (Windows).
build-daemon: | $(DIST)
	$(GO) build -trimpath -o $(DIST)/warpaltd ./cmd/warpaltd

build-daemon-windows: | $(DIST)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -o $(DIST)/warpaltd.exe ./cmd/warpaltd

test:
	$(GO) test ./...

dev:
	wails dev -browser -tags "webkit2_41"

clean:
	rm -rf $(DIST)
