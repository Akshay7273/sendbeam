module github.com/sendbeam/cli

go 1.25.0

require (
	github.com/coder/websocket v1.8.15
	github.com/pion/stun/v3 v3.1.7
	github.com/pion/webrtc/v4 v4.2.21
	github.com/sendbeam/engine v0.0.0
	github.com/sendbeam/wire v0.0.0
)

require (
	filippo.io/nistec v0.0.4 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/pion/datachannel v1.6.3 // indirect
	github.com/pion/dtls/v3 v3.1.9 // indirect
	github.com/pion/ice/v4 v4.4.4 // indirect
	github.com/pion/interceptor v0.1.49 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.2.1 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.18 // indirect
	github.com/pion/rtp v1.10.5 // indirect
	github.com/pion/sctp v1.11.3 // indirect
	github.com/pion/sdp/v3 v3.0.20 // indirect
	github.com/pion/srtp/v3 v3.1.0 // indirect
	github.com/pion/stun/v4 v4.0.1 // indirect
	github.com/pion/transport/v4 v4.1.0 // indirect
	github.com/pion/transport/v5 v5.1.1 // indirect
	github.com/pion/turn/v5 v5.1.2 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)

// The engine and wire crypto core are sibling modules in this repo. Local replaces keep them
// resolvable both under the go.work workspace and in standalone module builds (as CI runs each
// module).
replace github.com/sendbeam/engine => ../../packages/engine

replace github.com/sendbeam/wire => ../../packages/wire
