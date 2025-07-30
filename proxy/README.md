# WireGuard TCP Proxy

This package provides TCP proxy functionality specifically designed for WireGuard firewall bypass scenarios. It allows you to tunnel WireGuard UDP traffic over TCP when UDP is blocked by firewalls. **The primary use case is bypassing firewall restrictions where UDP (WireGuard's default protocol) is blocked by tunneling UDP traffic over TCP.**

## Features

- **UDP-over-TCP Tunneling**: Tunnel WireGuard UDP traffic over TCP to bypass firewall restrictions
- **TLS Support**: Optional TLS encryption for secure connections
- **Firewall Bypass**: Specialized mode for environments where UDP is blocked
- **Failover Integration**: Coordinates with WireGuard's automatic failover system
- **WireGuard Integration**: Bind to WireGuard interface IP addresses
- **Graceful Shutdown**: Proper cleanup of connections and resources
- **Connection Monitoring**: Track active connections and proxy status

## Usage

### Command Line Interface

The proxy functionality is available as a subcommand of the netclient CLI:

```bash
# Firewall bypass mode (default - UDP-over-TCP)
netclient proxy --port 8080 --remote wireguard-server:51820

# TLS-enabled firewall bypass
netclient proxy --port 8443 --remote wireguard-server:51820 --tls --cert cert.pem --key key.pem

# Bind to WireGuard interface IP
netclient proxy --port 8080 --remote wireguard-server:51820 --bind-wg

# With custom timeout and buffer size
netclient proxy --port 8080 --remote wireguard-server:51820 --timeout 60s --buffer-size 8192
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
    // Create firewall bypass proxy configuration
    config := &proxy.WireGuardProxyConfig{
        LocalPort:  8080,
        RemoteAddr: "wireguard-server:51820",
        UseTLS:     false,
        Timeout:    60 * time.Second,
        BindToWG:   true,
        UDPOverTCP: true,  // Enable UDP-over-TCP tunneling
        BufferSize: 8192,  // Larger buffer for UDP packets
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

// Auto-generated TLS config
autoTLSConfig, err := proxy.CreateAutoTLSConfig("localhost")

// Client TLS config (for connecting)
clientTLSConfig := proxy.CreateClientTLSConfig(true) // skipVerify = true
```

### Automatic Certificate Management

The proxy supports automatic certificate generation and management:

```bash
# Use auto-generated certificates
netclient proxy --port 8443 --remote example.com:443 --tls --auto-cert

# Use custom certificates
netclient proxy --port 8443 --remote example.com:443 --tls --cert cert.pem --key key.pem
```

Auto-generated certificates are:
- Self-signed with 1-year validity
- Stored in temporary directory
- Automatically reused if already generated
- Include localhost and 127.0.0.1 in SAN

## Architecture

The proxy consists of two main components:

1. **Proxy**: TCP proxy optimized for UDP-over-TCP tunneling
2. **WireGuardProxy**: WireGuard-specific wrapper that integrates with WireGuard interfaces

The automatic failover system is handled separately by `functions/fail_over.go`.

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

### Automatic Failover Integration

WireGuard's automatic failover system works alongside the manual proxy:
1. **Automatic Failover**: WireGuard automatically switches to TCP relay when UDP fails (handled by `functions/fail_over.go`)
2. **Manual Firewall Bypass**: User can manually set up TCP proxy for WireGuard traffic when needed
3. **Coordinated Operation**: Both systems can work together for optimal connectivity

**Note**: The failover system is automatic and doesn't require manual intervention. The proxy provides manual control when needed.

## Security Considerations

- Use TLS for sensitive traffic
- Validate certificates when possible
- Consider firewall rules to restrict access
- Monitor connection logs for suspicious activity

## Examples

### Firewall Bypass (UDP-over-TCP)
```bash
# Bypass UDP firewall restrictions (default mode)
netclient proxy --port 8080 --remote wireguard-server:51820

# With TLS encryption
netclient proxy --port 8443 --remote wireguard-server:51820 --tls --cert cert.pem --key key.pem

# With custom settings
netclient proxy --port 8080 --remote wireguard-server:51820 --timeout 60s --buffer-size 8192
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