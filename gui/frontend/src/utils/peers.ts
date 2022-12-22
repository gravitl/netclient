import { Peer } from "../models/Peer";

export function extractPeerPublicEndpoint(peer: Peer): string {
  return `${peer.Endpoint?.IP}:${peer?.Endpoint?.Port}`
}

export function extractPeerPrivateEndpoints(peer: Peer): string[] {
  return peer.AllowedIPs.map(endpoint => `${endpoint.IP}`)
}

export function byteArrayToString(byteArray: any): string {
  return btoa(String.fromCharCode(...new Uint8Array(byteArray)));
}
