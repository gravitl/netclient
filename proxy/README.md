# WireGuard TCP Proxy

This package provides TCP proxy functionality with TLS support that can work with WireGuard interfaces. It allows you to proxy traffic from a local WireGuard interface to remote endpoints. **The primary use case is bypassing firewall restrictions where UDP (WireGuard's default protocol) is blocked by tunneling UDP traffic over TCP.**

## Features

- **TCP Proxy**: Forward TCP connections from local to remote endpoints
- **UDP-over-TCP Tunneling**: Tunnel UDP traffic over TCP to bypass firewall restrictions
- **TLS Support**: Optional TLS encryption for secure connections
- **Firewall Bypass**: Specialized mode for environments where UDP is blocked
- **WireGuard Integration**: Bind to WireGuard interface IP addresses
- **Graceful Shutdown**: Proper cleanup of connections and resources
- **Connection Monitoring**: Track active connections and proxy status

## Usage

### Command Line Interface

The proxy functionality is available as a subcommand of the netclient CLI:

```bash
# Basic TCP proxy
netclient proxy --port 8080 --remote example.com:80

# Firewall bypass mode (UDP-over-TCP)
netclient proxy --port 8080 --remote example.com:80 --firewall-bypass

# TLS-enabled firewall bypass
netclient proxy --port 8443 --remote example.com:443 --firewall-bypass --tls --cert cert.pem --key key.pem

# Bind to WireGuard interface IP
netclient proxy --port 8080 --remote example.com:80 --bind-wg

# With custom timeout and buffer size
netclient proxy --port 8080 --remote example.com:80 --timeout 60s --buffer-size 8192
```

### Programmatic Usage

```go
package main

import (
    "crypto/tls"
    "log"
    "time"
    
    "github.com/gravitl/netclient/proxy"
)

func main() {
    // Create proxy configuration
    config := &proxy.WireGuardProxyConfig{
        LocalPort:  8080,
        RemoteAddr: "example.com:80",
        UseTLS:     false,
        Timeout:    30 * time.Second,
        BindToWG:   true,
    }
    
    // Create and start proxy
    wgProxy := proxy.NewWireGuardProxy(config)
    if err := wgProxy.Start(); err != nil {
        log.Fatal("Failed to start proxy:", err)
    }
    
    // Proxy will run until stopped
    // You can call wgProxy.Stop() to shut it down
}
```

## Configuration Options

### WireGuardProxyConfig

- `LocalPort`: Port to listen on locally
- `RemoteAddr`: Remote endpoint address (host:port)
- `UseTLS`: Enable TLS encryption
- `TLSConfig`: TLS configuration (set automatically if UseTLS is true)
- `Timeout`: Connection timeout duration
- `BindToWG`: Bind to WireGuard interface IP instead of all interfaces

### TLS Configuration

For TLS-enabled proxies, you can create TLS configurations:

```go
// Server TLS config (for listening)
tlsConfig, err := proxy.CreateTLSConfig("cert.pem", "key.pem", false)

// Client TLS config (for connecting)
clientTLSConfig := proxy.CreateClientTLSConfig(true) // skipVerify = true
```

## Architecture

The proxy consists of two main components:

1. **Proxy**: Generic TCP proxy that handles connection forwarding
2. **WireGuardProxy**: WireGuard-specific wrapper that integrates with WireGuard interfaces

### Connection Flow

1. Client connects to local proxy port
2. Proxy establishes connection to remote endpoint
3. Bidirectional data transfer between client and remote
4. Connection cleanup on completion

### WireGuard Integration

When `BindToWG` is enabled, the proxy will:
1. Query the WireGuard interface for its IP addresses
2. Bind to the first available IPv4 address (fallback to IPv6)
3. Only accept connections on the WireGuard interface IP

## Security Considerations

- Use TLS for sensitive traffic
- Validate certificates when possible
- Consider firewall rules to restrict access
- Monitor connection logs for suspicious activity

## Examples

### Firewall Bypass (UDP-over-TCP)
```bash
# Bypass UDP firewall restrictions
netclient proxy --port 8080 --remote wireguard-server:51820 --firewall-bypass

# With TLS encryption
netclient proxy --port 8443 --remote wireguard-server:51820 --firewall-bypass --tls --cert cert.pem --key key.pem
```

### HTTP Proxy
```bash
# Proxy HTTP traffic through WireGuard
netclient proxy --port 8080 --remote web-server:80 --bind-wg
```

### HTTPS Proxy with TLS
```bash
# Proxy HTTPS with TLS termination
netclient proxy --port 8443 --remote web-server:443 --tls --cert cert.pem --key key.pem
```

### Database Proxy
```bash
# Proxy database connections
netclient proxy --port 5432 --remote db-server:5432 --bind-wg
```

## Firewall Bypass Use Case

The primary use case for this proxy is bypassing firewall restrictions where UDP traffic is blocked. Many corporate networks, public WiFi, and restrictive environments block UDP traffic, which prevents WireGuard from working normally.

### How it works:
1. **UDP-over-TCP Tunneling**: The proxy encapsulates UDP packets (WireGuard traffic) within TCP connections
2. **Firewall Bypass**: Since TCP is typically allowed, the tunneled traffic can pass through restrictive firewalls
3. **WireGuard Integration**: The proxy binds to the WireGuard interface and forwards traffic to remote WireGuard endpoints
4. **TLS Encryption**: Optional TLS encryption provides additional security for the tunneled traffic

### Typical Scenario:
```bash
# Client behind restrictive firewall
netclient proxy --port 8080 --remote wireguard-server:51820 --firewall-bypass --tls --cert cert.pem --key key.pem

# This allows WireGuard traffic to flow over TCP port 8080 with TLS encryption
# instead of being blocked by UDP restrictions
```

## Error Handling

The proxy handles various error conditions:
- Network timeouts
- TLS handshake failures
- WireGuard interface unavailability
- Invalid configurations
- Firewall connection failures

All errors are logged with appropriate context for debugging. 