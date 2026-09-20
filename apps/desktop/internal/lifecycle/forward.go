// V20-PR07: single-instance share forwarding.
//
// When the desktop is launched a second time with file arguments (OS "Share"
// / "Send to" / "Open with" entry points, or a plain second launch), the new
// process must not start a duplicate engine. Instead it hands the share paths
// to the already-running instance over a token-authenticated loopback channel
// and exits. The running instance feeds them into the same composer flow as a
// drag-and-drop, so the user still reviews the files and picks a recipient —
// forwarding never auto-sends.
//
// The channel binds 127.0.0.1 on an ephemeral port. The address and a random
// token live in forward.json inside the app config dir (0700 dir, 0600 file),
// so only the same OS user can discover or use them. Requests are bounded in
// count and size, and paths are shape-validated; existence is validated by the
// transfer service before anything is staged.

package lifecycle

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// ForwardInfoFileName carries the running instance's forward-channel
	// address and token inside the app config dir.
	ForwardInfoFileName = "forward.json"
	// MaxForwardPaths caps how many share paths one forward request may carry.
	MaxForwardPaths = 256
	// MaxForwardPathLen caps a single share path in bytes.
	MaxForwardPathLen = 32 << 10
	// MaxForwardRequestBytes caps the wire size of one forward request line.
	MaxForwardRequestBytes = 1 << 20

	forwardDialTimeout = 3 * time.Second
	forwardIOTimeout   = 5 * time.Second
	forwardTokenBytes  = 32
)

// ForwardInfo describes how a second instance reaches the running one.
type ForwardInfo struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
}

type forwardRequest struct {
	Token string   `json:"token"`
	Paths []string `json:"paths"`
}

type forwardResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// WriteForwardInfo creates the forward channel for this (first) instance: it
// generates a random token, listens on 127.0.0.1 with an ephemeral port, and
// records the address and token in dir/forward.json (0600). The caller serves
// the listener with ServeForward and closes it on shutdown.
func WriteForwardInfo(dir string) (ForwardInfo, net.Listener, error) {
	if dir == "" {
		return ForwardInfo{}, nil, errors.New("forward info dir cannot be empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ForwardInfo{}, nil, fmt.Errorf("create forward info dir: %w", err)
	}
	raw := make([]byte, forwardTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return ForwardInfo{}, nil, fmt.Errorf("generate forward token: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return ForwardInfo{}, nil, fmt.Errorf("listen forward channel: %w", err)
	}
	info := ForwardInfo{
		Addr:  ln.Addr().String(),
		Token: base64.RawURLEncoding.EncodeToString(raw),
	}
	data, err := json.Marshal(info)
	if err != nil {
		_ = ln.Close()
		return ForwardInfo{}, nil, fmt.Errorf("encode forward info: %w", err)
	}
	path := filepath.Join(dir, ForwardInfoFileName)
	// Write atomically so a reader never sees a half-written file.
	tmp, err := os.CreateTemp(dir, "forward-*.tmp")
	if err != nil {
		_ = ln.Close()
		return ForwardInfo{}, nil, fmt.Errorf("create forward info temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		_ = ln.Close()
		return ForwardInfo{}, nil, fmt.Errorf("write forward info: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		_ = ln.Close()
		return ForwardInfo{}, nil, fmt.Errorf("close forward info: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		_ = ln.Close()
		return ForwardInfo{}, nil, fmt.Errorf("chmod forward info: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		_ = ln.Close()
		return ForwardInfo{}, nil, fmt.Errorf("publish forward info: %w", err)
	}
	return info, ln, nil
}

// ReadForwardInfo loads the running instance's forward channel description.
func ReadForwardInfo(dir string) (ForwardInfo, error) {
	data, err := os.ReadFile(filepath.Join(dir, ForwardInfoFileName))
	if err != nil {
		return ForwardInfo{}, fmt.Errorf("read forward info: %w", err)
	}
	var info ForwardInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return ForwardInfo{}, fmt.Errorf("decode forward info: %w", err)
	}
	if info.Addr == "" || info.Token == "" {
		return ForwardInfo{}, errors.New("forward info is incomplete")
	}
	return info, nil
}

// ClearForwardInfo removes the forward channel description on shutdown.
func ClearForwardInfo(dir string) error {
	if err := os.Remove(filepath.Join(dir, ForwardInfoFileName)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear forward info: %w", err)
	}
	return nil
}

// ServeForward accepts forward requests on ln until it is closed. Valid
// requests are acknowledged and handed to handle on a separate goroutine;
// invalid ones are rejected without invoking handle.
func ServeForward(ln net.Listener, info ForwardInfo, handle func([]string)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go serveForwardConn(conn, info, handle)
	}
}

func serveForwardConn(conn net.Conn, info ForwardInfo, handle func([]string)) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(forwardIOTimeout))
	respond := func(ok bool, msg string) {
		data, _ := json.Marshal(forwardResponse{OK: ok, Error: msg})
		_, _ = conn.Write(append(data, '\n'))
	}
	line, err := bufio.NewReader(io.LimitReader(conn, MaxForwardRequestBytes+1)).ReadString('\n')
	if err != nil {
		respond(false, "unreadable request")
		return
	}
	if len(line) > MaxForwardRequestBytes {
		respond(false, "request too large")
		return
	}
	var req forwardRequest
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		respond(false, "malformed request")
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(info.Token)) != 1 {
		respond(false, "unauthorized")
		return
	}
	if err := validateForwardPaths(req.Paths); err != nil {
		respond(false, err.Error())
		return
	}
	respond(true, "")
	handle(req.Paths)
}

// ForwardPaths delivers share paths to the running instance described by
// info. It returns nil only after the running instance acknowledged receipt.
func ForwardPaths(info ForwardInfo, paths []string) error {
	if info.Addr == "" || info.Token == "" {
		return errors.New("forward info is incomplete")
	}
	if err := validateForwardPaths(paths); err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", info.Addr, forwardDialTimeout)
	if err != nil {
		return fmt.Errorf("dial forward channel: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(forwardIOTimeout))
	data, err := json.Marshal(forwardRequest{Token: info.Token, Paths: paths})
	if err != nil {
		return fmt.Errorf("encode forward request: %w", err)
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write forward request: %w", err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read forward response: %w", err)
	}
	var resp forwardResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return fmt.Errorf("decode forward response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "rejected"
		}
		return fmt.Errorf("forward rejected: %s", resp.Error)
	}
	return nil
}

// validateForwardPaths enforces the wire shape of a share request. Existence
// and readability are validated later by the transfer service.
func validateForwardPaths(paths []string) error {
	if len(paths) == 0 {
		return errors.New("no paths to forward")
	}
	if len(paths) > MaxForwardPaths {
		return fmt.Errorf("too many paths: %d > %d", len(paths), MaxForwardPaths)
	}
	for _, p := range paths {
		if p == "" {
			return errors.New("empty path")
		}
		if strings.IndexByte(p, 0) >= 0 {
			return errors.New("path contains NUL byte")
		}
		if len(p) > MaxForwardPathLen {
			return fmt.Errorf("path too long: %d bytes", len(p))
		}
	}
	return nil
}

// SharePathsFromArgs extracts share paths from a process argument list
// (including os.Args). Flags are skipped; "--" switches to passthrough so
// dash-leading file names survive; file:// URLs (from %U desktop entries)
// are converted to plain paths.
func SharePathsFromArgs(args []string) []string {
	var out []string
	passthrough := false
	for i, a := range args {
		if i == 0 {
			continue
		}
		if !passthrough {
			if a == "--" {
				passthrough = true
				continue
			}
			if strings.HasPrefix(a, "-") && a != "-" {
				continue
			}
		}
		if p := sharePathFromArg(a); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sharePathFromArg(a string) string {
	a = strings.TrimSpace(a)
	if a == "" {
		return ""
	}
	if !strings.HasPrefix(a, "file://") {
		return a
	}
	u, err := url.Parse(a)
	if err != nil || u.Scheme != "file" {
		return ""
	}
	if u.Host != "" && u.Host != "localhost" {
		return ""
	}
	p := u.Path
	if runtime.GOOS == "windows" && len(p) > 2 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return p
}
