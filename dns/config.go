package dns

const (
	DNS_MANAGER_STUB   = "stub"   // '/run/systemd/resolve/stub-resolv.conf'
	DNS_MANAGER_UPLINK = "uplink" // '/run/systemd/resolve/resolv.conf'
	DNS_MANAGER_FILE   = "file"   // other than above
)
