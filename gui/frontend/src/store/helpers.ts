import { NetworksContextDispatcher, NetworksContextType } from "./NetworkContext";
import { GoGetKnownNetworks } from "../../wailsjs/go/main/App";

// Refresh and get all joined networks
export async function refreshNetworks(dispatch: NetworksContextDispatcher) {
  try {
    const networks = await GoGetKnownNetworks();
    dispatch({ action: "refresh-networks", data: networks });
  } catch (err) {
    return Promise.reject(err);
  }
}

// Check if the client is connected to the given network
export function isConnectedToNetwork(state: NetworksContextType, networkName: string): boolean {
  console.log(state);
  if (state.networks.find(nw => nw?.node?.network === networkName)?.node?.connected) return true
  return false
}
