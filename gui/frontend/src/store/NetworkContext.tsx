import { createContext, FC, ReactNode, useContext, useReducer } from "react";
import { main } from "../../wailsjs/go/models";

type NetworksContextAction = "refresh-networks" | "update-connection-status";

export interface NetworksContextType {
  networks: main.Network[];
}

export interface NetworksContextDispatcherProps {
  action: NetworksContextAction;
  data?: unknown;
}

export type NetworksContextDispatcher = (
  props: NetworksContextDispatcherProps,
) => void;

type NetworksContextProviderProps = { children: ReactNode };

type NetworksContextConsumerProps = { children: FC };

function networksContextReducer(
  state: NetworksContextType,
  dispatchProps: NetworksContextDispatcherProps,
): NetworksContextType {
  switch (dispatchProps.action) {
    case "refresh-networks":
      const networks = (dispatchProps.data as main.Network[]) ?? [];
      // sort by network name asc
      networks.sort((a, b) => a.node!.network.localeCompare(b.node!.network));
      return { networks };

    default:
      throw new Error("NetworksContextReducer: unkown action");
  }
}

const NetworksContext = createContext<
  | {
      networksState: NetworksContextType;
      networksDispatch: NetworksContextDispatcher;
    }
  | undefined
>(undefined);

NetworksContext.displayName = "NetworkContext";

const initialState: NetworksContextType = {
  networks: [],
};

function NetworksContextProvider({ children }: NetworksContextProviderProps) {
  const [networksState, networksDispatch] = useReducer(
    networksContextReducer,
    initialState,
  );

  return (
    <NetworksContext.Provider value={{ networksState, networksDispatch }}>
      {children}
    </NetworksContext.Provider>
  );
}

// function NetworksContextConsumer({ children, ...otherProps }: NetworksContextConsumerProps) {
//   return (
//     <NetworksContext.Consumer>
//       {(context) => {
//         if (context === undefined) {
//           throw new Error('NetworksContextConsumer must be used within a NetworksContextProvider')
//         }
//         return children(otherProps, context)
//       }}
//     </NetworksContext.Consumer>
//   )
// }

function useNetworksContext() {
  const context = useContext(NetworksContext);
  if (context === undefined) {
    throw new Error(
      "useNetworksContext must be used within a NetworksContextProvider",
    );
  }
  return context;
}

export {
  NetworksContextProvider,
  // NetworksContextConsumer,
  useNetworksContext,
};
