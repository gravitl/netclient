// Peer is a mirror of go type wg.PeerConfig
export interface PeerConfig {
  PublicKey?: number[];
  Endpoint: { IP: string; Port: number; Zone: string };
  Remove: boolean;
  UpdateOnly: boolean;
  PresharedKey?: number[];
  PersistentKeepaliveInterval: number;
  ReplaceAllowedIPs: boolean;
  AllowedIPs: { IP: string; Mask: string }[];
}
