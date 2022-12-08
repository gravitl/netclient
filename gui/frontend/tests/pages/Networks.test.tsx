import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe } from "vitest";

import Networks from "../../src/pages/Networks";
import { NetworksContextProvider } from "../../src/store/NetworkContext";

describe("NetworksPage", () => {
  it("renders title", () => {
    (window as any)["go"] = {};
    (window as any)["go"]["main"] = {};
    (window as any)["go"]["main"]["App"] = {};
    (window as any)["go"]["main"]["App"]["GoGetKnownNetworks"] = () => [];

    render(
      <NetworksContextProvider>
        <MemoryRouter>
          <Networks />
        </MemoryRouter>
      </NetworksContextProvider>
    );

    screen.debug();

    expect(screen.getAllByText("Networks").length).toBeGreaterThan(0);
  });
});
