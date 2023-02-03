import { act, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe } from "vitest";

import Networks from "../../src/pages/Networks";
import {
  NetworksContextProvider,
  useNetworksContext,
} from "../../src/store/NetworkContext";
import { main } from "../../wailsjs/go/models";

const mockNetworks: Partial<main.Network>[] = [
  {
    node: {
      network: "mock-net",
      id: "0123",
      connected: true,
      server: "mock-server",
      peers: [
        {
          PublicKey: [56, 65, 75, 77],
          Endpoint: { IP: "51.0.0.1", Port: 38378, Zone: "" },
          AllowedIPs: [{ IP: "10.0.0.51", Mask: "w+" }],
        },
      ],
    } as any,
    server: {
      name: "mock-server",
    } as any,
  },
];

describe("NetworksPage", () => {
  beforeEach(() => {
    (window as any)["go"] = {};
    (window as any)["go"]["gui"] = {};
    (window as any)["go"]["gui"]["App"] = {};
    (window as any)["go"]["gui"]["App"]["GoGetKnownNetworks"] = () => [];

    act(() => {
      render(
        <NetworksContextProvider>
          <MemoryRouter>
            <Networks />
          </MemoryRouter>
        </NetworksContextProvider>
      );
    });

    // screen.debug();
  });

  it("renders title", () => {
    act(() => {
      expect(screen.getAllByText("Networks").length).toBeGreaterThan(0);
    });
  });

  it("provides a search bar to search for a network", () => {
    act(async () => {
      await waitFor(() =>
        expect(screen.getByTestId("networks-search-inp")).toBeInTheDocument()
      );
    });
  });

  it("provides a button to add new network", () => {
    act(async () => {
      await waitFor(() =>
        expect(screen.getByTestId("add-network-btn")).toBeInTheDocument()
      );
    });
  });
});
