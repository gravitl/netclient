package proxyegress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/exp/slog"
)

func reconcileForwarderLocked() {
	if len(domainToProxy) == 0 {
		stopForwarderLocked()
		return
	}
	if fwdLn != nil {
		// Already running; domain map updated under same lock — handlers read domainToProxy.
		return
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localForwardPort))
	if err != nil {
		slog.Error("egress proxy: local forwarder listen", "error", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	fwdLn = ln
	fwdCancel = cancel
	go serveForwarder(ctx, ln)
	slog.Info("egress proxy: local CONNECT forwarder listening", "addr", ln.Addr().String())
}

func stopForwarderLocked() {
	if fwdCancel != nil {
		fwdCancel()
		fwdCancel = nil
	}
	if fwdLn != nil {
		_ = fwdLn.Close()
		fwdLn = nil
	}
}

func serveForwarder(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				slog.Debug("egress proxy: forwarder accept ended", "error", err)
				return
			}
		}
		go handleForwardConn(conn)
	}
}

func handleForwardConn(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	hostPort := req.Host
	if hostPort == "" && req.URL != nil {
		hostPort = req.URL.Host
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		port = "443"
	}
	host = strings.ToLower(strings.TrimSpace(host))

	mu.RLock()
	proxyAddr := lookupProxyLocked(host)
	mu.RUnlock()
	if proxyAddr == "" {
		_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}

	upstream, err := net.DialTimeout("tcp", proxyAddr, 15*time.Second)
	if err != nil {
		slog.Warn("egress proxy: dial GW", "addr", proxyAddr, "error", err)
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()

	// Re-issue CONNECT to the gateway L7 server.
	connectReq := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)
	if _, err := io.WriteString(upstream, connectReq); err != nil {
		return
	}
	ubr := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(ubr, req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Fprintf(client, "HTTP/1.1 %d %s\r\n\r\n", resp.StatusCode, resp.Status)
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	clientReader := io.Reader(br)
	if br.Buffered() > 0 {
		clientReader = io.MultiReader(br, client)
	} else {
		clientReader = client
	}
	upReader := io.Reader(ubr)
	if ubr.Buffered() > 0 {
		upReader = io.MultiReader(ubr, upstream)
	} else {
		upReader = upstream
	}

	errc := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, clientReader)
		errc <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upReader)
		errc <- struct{}{}
	}()
	<-errc
}

func lookupProxyLocked(host string) string {
	if addr, ok := domainToProxy[host]; ok {
		return addr
	}
	// wildcard *.suffix
	for pat, addr := range domainToProxy {
		if strings.HasPrefix(pat, "*.") {
			suf := pat[1:] // .example.com
			if strings.HasSuffix(host, suf) && len(host) > len(suf) {
				return addr
			}
		}
	}
	return ""
}
