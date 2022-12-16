import { act, cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe } from "vitest";
import NetworkTable from "../../src/components/NetworkTable";
import { main } from "../../wailsjs/go/models";

const mockNetworks: Partial<main.Network>[] = [
  {
    node: {
      network: "mock-net-1",
      connected: true,
    } as any,
  },
  {
    node: {
      network: "mock-net-2",
      connected: false,
    } as any,
  },
];

function mockOnNetworkStatusChange(networkName: string, newStatus: boolean) {}

describe("NetworksTable", () => {
  beforeEach(() => {
    (window as any)["go"] = {};
    (window as any)["go"]["gui"] = {};
    (window as any)["go"]["gui"]["App"] = {};

    act(() => {
      render(
        <MemoryRouter>
          <NetworkTable
            networks={[]}
            onNetworkStatusChange={mockOnNetworkStatusChange}
          />
        </MemoryRouter>
      );
    });
  });

  it("renders no networks when there is none", async () => {
    const networksEls = screen.queryAllByTestId("network-row");
    expect(networksEls.length).toEqual(0);

    expect(screen.getByText("No networks found")).toBeInTheDocument();
  });

  it("renders networks correctly", async () => {
    cleanup();
    act(() => {
      render(
        <MemoryRouter>
          <NetworkTable
            networks={mockNetworks as any}
            onNetworkStatusChange={mockOnNetworkStatusChange}
          />
        </MemoryRouter>
      );
    });

    const networksEls = screen.queryAllByTestId("network-row");
    expect(networksEls.length).toEqual(mockNetworks.length);

    mockNetworks.forEach((nw) => {
      expect(screen.getByText(nw.node?.network!)).toBeInTheDocument();
    });

    const statusToggles = screen.queryAllByTestId("status-toggle");
    expect(statusToggles.length).toEqual(mockNetworks.length);
  });
});
