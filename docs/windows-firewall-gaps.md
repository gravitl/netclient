# Windows firewall gaps vs Linux

Windows implements the shared `firewallController` with **Hyper-V NetNat** (egress NAT) and **WFP** (ACLs). It is intentional and production-used for egress + peer/egress ACL enforcement, but it is **not feature-parity** with Linux iptables/nftables.

Primary code:

| Area | Path |
|------|------|
| Controller / NetNat / forwarding | `firewall/firewall_windows.go` |
| ACL install / bootstrap | `firewall/windows_acl.go` |
| ACL → WFP filter conversion | `firewall/windows_acl_convert.go` |
| WFP engine | `firewall/wfp/` |
| Linux reference | `firewall/iptables_linux.go`, `firewall/nftables_linux.go` |

---

## What works today

| Capability | Mechanism |
|------------|-----------|
| Egress SNAT (IPv4 mesh → LAN/WAN) | Hyper-V `New-NetNat` / NetNat |
| IP forwarding on mesh + LAN ifaces | `local.EnableForwardingOnInterfaces` |
| Host peer ACLs (inbound) | WFP ALE `AUTH_RECV_ACCEPT` |
| Egress ACLs (forwarded traffic) | WFP `IPFORWARD` |
| Default deny + allow-all toggle | `ChangeACLInTarget` / `ChangeACLFwdTarget` |
| Protocol match | TCP, UDP, ICMP, or any |
| Destination ports / ranges (host inbound only) | WFP local-port conditions |
| Src/dst IPv4 and IPv6 nets on ACL allows | `IPList`/`Dst` and `IP6List`/`Dst6` |
| Flush / cleanup | Close WFP session, remove Netmaker NetNats, disable forwarding |
| Legacy Defender rule cleanup | One-time PowerShell sweep on bootstrap |

ACL model: **unidirectional allow filters** on inbound vs forward layers, with a default block. Not Linux-style multi-chain jump tables or conntrack-mirrored bidirectional rules.

---

## Gaps and limitations

### Controllers / APIs that are stubs

| Method | Behavior | Impact |
|--------|----------|--------|
| `InsertIngressRoutingRules` | Always `nil` | Ingress gateway firewall rules are **not** applied on Windows |
| `AddDropRules` | Empty | No explicit DROP rule install path (default deny is WFP-only) |
| `DeleteRoutingRule` | Always `nil` | Fine-grained single-peer route rule delete is unused; callers should use `RemoveRoutingRules` / flush |
| `CreateChains` / `ForwardRule` | Bootstrap WFP only | No iptables/nft chain equivalent |

### ACL enforcement gaps

| Gap | Detail |
|-----|--------|
| **No destination ports on egress/forward ACLs** | WFP `IPFORWARD` has no L4 port fields. `aclToFilterSpecs` **drops** `AllowedPorts` for `LayerForwardACL`. Egress ACLs match **src/dst + protocol only**. |
| **Peer ACLs are host-inbound only** | `AddAclRules` / `UpsertAclRule` install on `LayerInboundACL` only. There is no separate host-outbound ALE layer for mesh-initiated traffic. |
| **No explicit deny ACL rules** | Policy is allow-list + default block. Per-rule DROP targets like Linux are not modeled as WFP deny filters for named ACLs. |
| **No source-port matching** | Only destination/local port is applied on inbound ALE. |
| **Iface bind race** | Init can run before the WireGuard adapter exists. Default deny is inactive until `RefreshACLInterface` / bootstrap rebinds the LUID. |

### NAT / egress gaps

| Gap | Detail |
|-----|--------|
| **Virtual NAT unsupported** | `shouldApplyVirtualNat` ranges log a warning and fall back to normal NetNat when `Nat=true`. No Linux VNAT prerouting/postrouting equivalent. |
| **IPv6 egress NAT unsupported** | Hyper-V NetNat accepts **IPv4** `InternalIPInterfaceAddressPrefix` only. IPv6 mesh prefixes skip NAT. |
| **One NetNat prefix system-wide** | Windows allows a single WinNAT internal prefix. Docker / WSL / Hyper-V NetNats can conflict; create fails with a clear error rather than sharing. |
| **One NetNat per egress ID** | First eligible IPv4 range wins (`natApplied`); additional ranges on the same egress do not get separate NATs. |
| **No per-range MASQUERADE iface selection** | Linux can SNAT out a resolved LAN/WAN iface; Windows SNATs via NetNat for traffic sourced from the mesh prefix leaving the host. |

### Platform / operational constraints

| Constraint | Detail |
|------------|--------|
| Requires Hyper-V / WinNAT capability | NetNat PowerShell APIs must work on the host |
| Dynamic WFP session | Filters disappear when the process exits (expected); `FlushAll` also closes the engine |
| Not Defender Firewall for ACLs | Current path is WFP; leftover `Netmaker-ACL` Defender rules are migration cleanup only |
| macOS | Desktop default-deny inbound via pf anchor (`firewall_darwin.go`); full ACL/egress/ingress not implemented |
| FreeBSD | Unimplemented stub (`firewall_freebsd.go` / `firewall_noop.go`) |

---

## Feature parity matrix (high level)

| Feature | Linux iptables/nft | Windows |
|---------|--------------------|---------|
| Peer host ACL (IP + proto + dst port) | Yes | Yes (inbound ALE) |
| Egress ACL (IP + proto + dst port) | Yes | Partial (IP + proto; **ports ignored**) |
| Ingress GW routing rules | Yes | **No** |
| Egress SNAT IPv4 | Yes | Yes (NetNat) |
| Egress SNAT IPv6 | Yes | **No** |
| Virtual NAT | Yes | **No** |
| Default ACL accept/drop targets | Yes | Yes |
| Named DROP ACL rules | Yes | **No** (default deny only) |
| Chain / jump model | Yes | N/A (WFP filters) |

---

## When extending Windows support

1. Prefer WFP for packet filters; keep NetNat for SNAT unless a different Windows NAT stack is chosen deliberately.
2. Do not assume IPFORWARD can grow port matching — use a different WFP layer (e.g. transport/ALE) if egress port policy becomes required.
3. Keep `aclToFilterSpecs` conservative: unparsable ports must be **skipped**, never coerced to “all ports”.
4. Document any new NetNat or WFP system-wide limit in this file.
