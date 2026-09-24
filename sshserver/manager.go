//go:build linux || darwin

package sshserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	gliderssh "github.com/gliderlabs/ssh"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

const (
	DefaultPort = 22022
	hostKeyFile = "ssh_host_ed25519_key"
)

// Manager owns the lifecycle of the embedded SSH server.
type Manager struct {
	mu                   sync.RWMutex
	identityMap          map[string]models.PeerIdentity
	authorizedIdentities map[string]models.SSHAuthorizedIdentity
	server               *gliderssh.Server
	listeners            map[string]net.Listener // keyed by IP string, one per bound WireGuard address
	sessions             map[string]*liveSession
}

// liveSession tracks one open shell/exec/sftp session so it can be revoked
// (its underlying process killed, its channel closed) if the peer's grant
// disappears or narrows on a later Start().
type liveSession struct {
	remoteAddr net.Addr
	osUser     string
	cancel     context.CancelFunc
}

var manager = &Manager{}

// GetManager returns the package-level SSH server manager singleton.
func GetManager() *Manager {
	return manager
}

// Start (re)records the manager's known peer identities and, if the
// server isn't already running, starts the listener.
func (m *Manager) Start(identityMap map[string]models.PeerIdentity, authorizedIdentities map[string]models.SSHAuthorizedIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.identityMap = identityMap
	m.authorizedIdentities = authorizedIdentities
	m.revokeStaleSessionsLocked()

	if m.server == nil {
		srv, err := m.buildServer()
		if err != nil {
			return err
		}
		m.server = srv
		m.listeners = make(map[string]net.Listener)
	}

	return m.syncListenersLocked()
}

// revokeStaleSessionsLocked cancels every live session whose peer/OS-user
// grant no longer exists under the identities recorded above.
func (m *Manager) revokeStaleSessionsLocked() {
	for id, sess := range m.sessions {
		osUsers, ok := m.authorizedOsUsersLocked(sess.remoteAddr)
		if ok && osUserAllowed(osUsers, sess.osUser) {
			continue
		}
		slog.Info("[sshserver] revoking session: grant no longer authorized",
			"peer", sess.remoteAddr.String(), "os_user", sess.osUser)
		sess.cancel()
		delete(m.sessions, id)
	}
}

func osUserAllowed(osUsers []string, requested string) bool {
	return slices.Contains(osUsers, "*") || slices.Contains(osUsers, requested)
}

// buildServer constructs the (unstarted) gliderssh.Server - the host key
// and handler wiring are one-time setup, done once per Manager lifetime and
// then reused across every listener syncListenersLocked binds or drops.
func (m *Manager) buildServer() (*gliderssh.Server, error) {
	signer, err := loadOrCreateHostKey()
	if err != nil {
		return nil, fmt.Errorf("sshserver: failed to prepare host key: %w", err)
	}

	return &gliderssh.Server{
		Handler:     m.handleSession,
		HostSigners: []gliderssh.Signer{signer},
		SubsystemHandlers: map[string]gliderssh.SubsystemHandler{
			"sftp": m.handleSFTP,
		},
		ConnCallback: func(_ gliderssh.Context, conn net.Conn) net.Conn {
			if _, ok := m.authorizedOsUsers(conn.RemoteAddr()); !ok {
				slog.Warn("[sshserver] rejected connection: peer has no Managed SSH grant on this host",
					"remote_addr", conn.RemoteAddr().String())
				return nil
			}
			return conn
		},
	}, nil
}

// syncListenersLocked reconciles m.listeners against the host's current
// WireGuard addresses.
func (m *Manager) syncListenersLocked() error {
	wanted := make(map[string]net.IP)
	for _, ip := range wireguardAddresses() {
		wanted[ip.String()] = ip
	}

	for key, ln := range m.listeners {
		if _, ok := wanted[key]; ok {
			continue
		}
		slog.Info("[sshserver] closing listener: address no longer assigned to this host", "addr", ln.Addr().String())
		_ = ln.Close()
		delete(m.listeners, key)
	}

	var firstErr error
	for key, ip := range wanted {
		if _, ok := m.listeners[key]; ok {
			continue
		}
		addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", DefaultPort))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			slog.Error("[sshserver] failed to listen on new address", "addr", addr, "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("sshserver: failed to listen on %s: %w", addr, err)
			}
			continue
		}
		m.listeners[key] = ln
		srv := m.server
		go func() {
			slog.Info("[sshserver] starting embedded SSH/SCP/SFTP server", "addr", ln.Addr().String())
			if err := srv.Serve(ln); err != nil && !errors.Is(err, gliderssh.ErrServerClosed) {
				slog.Error("[sshserver] server stopped", "addr", ln.Addr().String(), "error", err)
			}
		}()
	}

	if len(m.listeners) == 0 {
		return errors.New("sshserver: no WireGuard tunnel address available yet")
	}

	return firstErr
}

// wireguardAddresses returns the current set of WireGuard tunnel addresses
// across every network this host has joined - what the embedded SSH
// server binds to, instead of every interface on the box.
func wireguardAddresses() []net.IP {
	seen := make(map[string]struct{})
	var addrs []net.IP
	for _, node := range config.GetNodes() {
		for _, ip := range []net.IP{node.Address.IP, node.Address6.IP} {
			if ip == nil || ip.IsUnspecified() {
				continue
			}
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			addrs = append(addrs, ip)
		}
	}
	return addrs
}

// Stop shuts the SSH server down, if running, and resets the manager so a
// later Start begins fresh.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.server == nil {
		return nil
	}
	slog.Info("[sshserver] stopping embedded SSH server")
	err := m.server.Close()
	m.server = nil
	m.listeners = nil
	return err
}

// authorizedOsUsers returns the OS usernames a Managed SSH acl policy
// grants the peer at addr, and whether any grant exists at all.
func (m *Manager) authorizedOsUsers(addr net.Addr) ([]string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.authorizedOsUsersLocked(addr)
}

// authorizedOsUsersLocked is authorizedOsUsers without its own locking, for
// callers that already hold m.mu (Start, via revokeStaleSessionsLocked).
func (m *Manager) authorizedOsUsersLocked(addr net.Addr) ([]string, bool) {
	ip := hostIP(addr)
	if ip == nil {
		return nil, false
	}
	for cidr, identity := range m.authorizedIdentities {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return identity.OsUsers, true
		}
	}
	return nil, false
}

// trackSession registers a live session so a later grant change can revoke
// it (see revokeStaleSessionsLocked). untrackSession must be deferred by
// the caller to clean up on normal session end.
func (m *Manager) trackSession(id string, addr net.Addr, osUser string, cancel context.CancelFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions == nil {
		m.sessions = make(map[string]*liveSession)
	}
	m.sessions[id] = &liveSession{remoteAddr: addr, osUser: osUser, cancel: cancel}
}

func (m *Manager) untrackSession(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

// withTrackedSession registers s for the duration of fn so a grant change
// elsewhere can cancel the context fn is given, then runs fn.
func (m *Manager) withTrackedSession(s gliderssh.Session, fn func(ctx context.Context)) {
	id := s.Context().SessionID()
	ctx, cancel := context.WithCancel(s.Context())
	m.trackSession(id, s.RemoteAddr(), s.User(), cancel)
	defer m.untrackSession(id)
	fn(ctx)
}

// peerName returns the netmaker identity name for addr, if known, purely
// for logging/audit context - not part of the authorization decision.
func (m *Manager) peerName(addr net.Addr) string {
	ip := hostIP(addr)
	if ip == nil {
		return ""
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	for cidr, identity := range m.identityMap {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return identity.Name
		}
	}
	return ""
}

func hostIP(addr net.Addr) net.IP {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return net.ParseIP(host)
}

func (m *Manager) handleSession(s gliderssh.Session) {
	if !isGrantedOsUser(m, s) {
		return
	}
	m.withTrackedSession(s, func(ctx context.Context) {
		if ptyReq, winCh, isPty := s.Pty(); isPty {
			runShell(ctx, s, ptyReq, winCh)
			return
		}
		runExec(ctx, s)
	})
}

// isGrantedOsUser checks s.User() against the peer's grant and, if it
// isn't authorized, rejects the session and returns false.
func isGrantedOsUser(m *Manager, s gliderssh.Session) bool {
	osUsers, ok := m.authorizedOsUsers(s.RemoteAddr())
	if ok && osUserAllowed(osUsers, s.User()) {
		return true
	}
	slog.Warn("[sshserver] rejected session: os user not granted",
		"peer", m.peerName(s.RemoteAddr()), "requested_user", s.User())
	fmt.Fprintf(s, "ssh: %q is not an authorized login for this peer\n", s.User())
	_ = s.Exit(1)
	return false
}

func runShell(ctx context.Context, s gliderssh.Session, ptyReq gliderssh.Pty, winCh <-chan gliderssh.Window) {
	var cmd *exec.Cmd
	var err error
	if raw := s.RawCommand(); raw != "" {
		cmd, err = execCmd(s.User(), raw)
	} else {
		cmd, err = loginShellCmd(s.User())
	}
	if err != nil {
		fmt.Fprintln(s, err)
		_ = s.Exit(1)
		return
	}
	cmd.Env = append(os.Environ(), "TERM="+ptyReq.Term)

	f, err := pty.Start(cmd)
	if err != nil {
		fmt.Fprintln(s, "failed to start shell:", err)
		_ = s.Exit(1)
		return
	}
	defer f.Close()

	defer watchForRevoke(ctx, cmd)()

	go func() {
		for win := range winCh {
			_ = pty.Setsize(f, &pty.Winsize{Rows: uint16(win.Height), Cols: uint16(win.Width)})
		}
	}()
	go func() {
		_, _ = io.Copy(f, s)
	}()
	_, _ = io.Copy(s, f)
	_ = cmd.Wait()
}

// runExec handles non-interactive command execution.
func runExec(ctx context.Context, s gliderssh.Session) {
	if s.RawCommand() == "" {
		_ = s.Exit(1)
		return
	}
	cmd, err := execCmd(s.User(), s.RawCommand())
	if err != nil {
		fmt.Fprintln(s, err)
		_ = s.Exit(1)
		return
	}
	cmd.Env = os.Environ()
	cmd.Stdin = s
	cmd.Stdout = s
	cmd.Stderr = s.Stderr()

	if err := cmd.Start(); err != nil {
		fmt.Fprintln(s, "failed to start command:", err)
		_ = s.Exit(1)
		return
	}
	defer watchForRevoke(ctx, cmd)()

	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			_ = s.Exit(exitErr.ExitCode())
			return
		}
		_ = s.Exit(1)
		return
	}
	_ = s.Exit(0)
}

// watchForRevoke kills cmd's process if ctx is canceled before the process
// exits on its own.
func watchForRevoke(ctx context.Context, cmd *exec.Cmd) (stop func()) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		case <-done:
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

// handleSFTP serves the sftp subsystem.
func (m *Manager) handleSFTP(s gliderssh.Session) {
	if !isGrantedOsUser(m, s) {
		return
	}
	m.withTrackedSession(s, func(ctx context.Context) {
		if s.User() == "root" {
			srv, err := sftp.NewServer(s)
			if err != nil {
				return
			}
			defer srv.Close()
			_ = srv.Serve()
			return
		}

		sftpServerPath := findSftpServer()
		if sftpServerPath == "" {
			fmt.Fprintln(s.Stderr(), "sftp: no system sftp-server binary found to run as a non-root user")
			_ = s.Exit(1)
			return
		}
		cmd, err := execCmd(s.User(), sftpServerPath)
		if err != nil {
			fmt.Fprintln(s.Stderr(), err)
			_ = s.Exit(1)
			return
		}
		cmd.Stdin = s
		cmd.Stdout = s
		cmd.Stderr = s.Stderr()
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(s.Stderr(), "sftp: failed to start sftp-server:", err)
			_ = s.Exit(1)
			return
		}
		defer watchForRevoke(ctx, cmd)()
		_ = cmd.Wait()
	})
}

func loginShell() string {
	for _, name := range []string{"bash", "sh"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return "/bin/sh"
}

var (
	utilLinuxLoginOnce sync.Once
	utilLinuxLogin     bool
)

// isUtilLinuxLogin reports whether loginPath is util-linux's login, as
// opposed to shadow-utils' or busybox's. Only meaningful on Linux.
func isUtilLinuxLogin(loginPath string) bool {
	utilLinuxLoginOnce.Do(func() {
		if runtime.GOOS != "linux" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, loginPath, "--version").CombinedOutput()
		utilLinuxLogin = err == nil && strings.Contains(string(out), "util-linux")
	})
	return utilLinuxLogin
}

func loginShellCmd(osUser string) (*exec.Cmd, error) {
	if path, err := exec.LookPath("login"); err == nil {
		// -f: already authenticated (by the WireGuard/grant check), skip
		// login's own password prompt.
		args := []string{"-f", osUser}
		if !isUtilLinuxLogin(path) {
			return exec.Command(path, args...), nil
		}
		// util-linux login calls vhangup() on its terminal, which hangs it up
		// before the shell starts when it is the session leader, as it is
		// under pty.Start (Debian bug 1078023). setsid -c gives it a session
		// of its own that takes the pty as its controlling terminal; -w
		// waits so the exit status still propagates.
		if setsid, err := exec.LookPath("setsid"); err == nil {
			return exec.Command(setsid, append([]string{"-w", "-c", path}, args...)...), nil
		}
		// Without setsid that login would just hang up; use su instead.
	}
	if path, err := exec.LookPath("su"); err == nil {
		return exec.Command(path, "-", osUser), nil
	}
	if osUser == "root" {
		return rawRootShellCmd(), nil
	}
	return nil, fmt.Errorf("sshserver: neither login nor su is available to start a session as %q", osUser)
}

// execCmd returns the command to run a single command as osUser
// non-interactively - used for exec/legacy-scp and for the sftp-server
// helper. "login" is interactive-session oriented and doesn't portably
// support one-shot commands, so this always prefers su -c, which does.
func execCmd(osUser, command string) (*exec.Cmd, error) {
	if path, err := exec.LookPath("su"); err == nil {
		return exec.Command(path, "-", osUser, "-c", command), nil
	}
	if osUser == "root" {
		cmd := rawRootShellCmd()
		cmd.Args = append(cmd.Args, "-c", command)
		return cmd, nil
	}
	return nil, fmt.Errorf("sshserver: su is not available to run a command as %q", osUser)
}

// rawRootShellCmd is the last-resort fallback for root when neither login
// nor su is present.
func rawRootShellCmd() *exec.Cmd {
	cmd := exec.Command(loginShell())
	home := "/root"
	if u, err := user.Lookup("root"); err == nil && u.HomeDir != "" {
		home = u.HomeDir
	}
	cmd.Dir = home
	return cmd
}

// sftpServerPaths are the common install locations for OpenSSH's
// sftp-server helper binary across major distros.
var sftpServerPaths = []string{
	"/usr/lib/openssh/sftp-server",
	"/usr/libexec/openssh/sftp-server",
	"/usr/libexec/sftp-server",
	"/usr/lib/ssh/sftp-server",
	"/usr/lib/misc/sftp-server",
}

// findSftpServer returns the first sftp-server binary found on this host,
// or "" if none of the known locations exist.
func findSftpServer() string {
	for _, p := range sftpServerPaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// loadOrCreateHostKey persists an ed25519 SSH host key under netclient's
// config directory so repeated restarts don't churn clients' known_hosts
// with "remote host identification has changed" warnings.
func loadOrCreateHostKey() (gossh.Signer, error) {
	path := filepath.Join(config.GetNetclientPath(), hostKeyFile)
	if data, err := os.ReadFile(path); err == nil {
		if signer, err := gossh.ParsePrivateKey(data); err == nil {
			return signer, nil
		} else {
			slog.Warn("[sshserver] existing host key unreadable, regenerating", "error", err)
		}
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := gossh.MarshalPrivateKey(priv, "netclient sshserver host key")
	if err != nil {
		return nil, err
	}
	pemBytes := pemEncode(block)
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		slog.Warn("[sshserver] failed to persist host key, it will regenerate next start", "error", err)
	}

	return gossh.ParsePrivateKey(pemBytes)
}

func pemEncode(block *pem.Block) []byte {
	return pem.EncodeToMemory(block)
}
