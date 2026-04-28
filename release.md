# Netclient v1.5.1 Release Notes 🚀

## 🚀 What’s New

### 🔁 Firewall Mark Support

Added support for configuring a **firewall mark** via the install command.

### 🔁 Traffic Logs (Beta)

Traffic Logs have now moved into **Beta**.

- Traffic Logs are now enriched with relevant **domain tagging**, making network activity easier to audit and investigate.

### 🔌 Default Netclient Port Update

The default Netclient port has been changed to **51821/udp** (previously **443/udp**).

---

## 🧰 Improvements & Fixes

### **Docker Netclient**
- Updated the Netclient Docker deployment to run in the **foreground**, moving away from daemon management inside the container.

### **Scalability Improvements**
- Improved peer synchronization by **caching peer information** and only refreshing when a peer update is triggered.

### **Windows**
- Netclient now uses the **provided interface name** on Windows.

### **DNS**
- Added a **Noop DNS Config Manager** fallback when DNS Manager initialization fails.
- Added **Windows Active Directory compatibility mode**.

### **Egress Routes**
- Netclient now automatically avoids adding **conflicting routes** with local interfaces.

### **Internet Gateways**
- Internet Gateways are now marked **unhealthy** when a node is disconnected or a peer is not found.

### **CLI Commands**
- Fixed missing `endpoint-ip6` flag name.
- Removed the **MTU flag** from CLI configuration (this can now be configured via the control plane).

---

## 🐞 Known Issues

- **IPv6-only machines**  
  Netclients cannot currently **auto-upgrade** on IPv6-only systems.

- **Multi-network join performance**  
  Multi-network netclient joins using an **enrollment key** still require optimization.

- **systemd-resolved DNS limitation**  
  On systems using **systemd-resolved in uplink mode**, only the **first 3 entries** in `resolv.conf` are honored; additional entries are ignored. This may cause DNS resolution issues. **Stub mode is recommended**.