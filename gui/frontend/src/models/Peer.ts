// Peer is a mirror of go type wg.PeerConfig
export interface Peer {
  PublicKey?: number[];
  Endpoint: { IP: string, Port: number, Zone: string, };
  Remove: boolean;
  UpdateOnly: boolean;
  PresharedKey?: number[];
  PersistentKeepaliveInterval: number;
  ReplaceAllowedIPs: boolean;
  AllowedIps: { IP: string, Mask: string, }[];
}
