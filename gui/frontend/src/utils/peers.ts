import { Peer } from "../models/Peer";

export default function extractPeerEndpoint(peer: Peer): string {
  return `${peer.Endpoint?.IP}:${peer?.Endpoint?.Port}`
}
