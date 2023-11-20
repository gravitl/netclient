import {
  NetworksContextDispatcher,
  NetworksContextType,
} from "./NetworkContext";
import {
  GoConnectToNetwork,
  GoDisconnectFromNetwork,
  GoGetKnownNetworks,
  GoGetNetwork,
  GoLeaveNetwork,
} from "../../wailsjs/go/main/App";
import { main } from "../../wailsjs/go/models";

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
export function isConnectedToNetwork(
  state: NetworksContextType,
  networkName: string,
): boolean {
  console.log(state);
  if (
    state.networks.find((nw) => nw?.node?.network === networkName)?.node
      ?.connected
  )
    return true;
  return false;
}

// Get a known network
export async function getNetwork(
  state: NetworksContextType,
  networkName: string,
): Promise<main.Network> {
  const network = state.networks.find(
    (nw) => nw?.node?.network === networkName,
  );
  if (network) {
    return network;
  }
  try {
    const network = await GoGetNetwork(networkName);
    return network;
  } catch (err) {
    return Promise.reject(err);
  }
}

// Connect to/Disconnect from a known network and refresh networks
export async function updateConnectionStatusAndRefreshNetworks(
  dispatch: NetworksContextDispatcher,
  networkName: string,
  newStatus: boolean,
) {
  try {
    if (newStatus) {
      await GoConnectToNetwork(networkName);
    } else {
      await GoDisconnectFromNetwork(networkName);
    }
    const networks = await GoGetKnownNetworks();
    dispatch({ action: "refresh-networks", data: networks });
  } catch (err) {
    return Promise.reject(err);
  }
}

// Leave a known network and refresh networks
export async function leaveAndRefreshNetworks(
  dispatch: NetworksContextDispatcher,
  networkName: string,
) {
  try {
    await GoLeaveNetwork(networkName);
    const networks = await GoGetKnownNetworks();
    dispatch({ action: "refresh-networks", data: networks });
  } catch (err) {
    return Promise.reject(err);
  }
}
