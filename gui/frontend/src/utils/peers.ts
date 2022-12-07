import { Peer } from "../models/Peer";

export  function extractPeerEndpoint(peer: Peer): string {
  return `${peer.Endpoint?.IP}:${peer?.Endpoint?.Port}`
}

export function byteArrayToString(byteArray: any): string {
  return btoa(String.fromCharCode(...new Uint8Array(byteArray)));
}
