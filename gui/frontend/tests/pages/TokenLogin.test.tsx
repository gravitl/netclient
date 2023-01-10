import { act, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe } from "vitest";
import TokenLogin from "../../src/pages/TokenLogin";
import {
  NetworksContextProvider,
} from "../../src/store/NetworkContext";


describe("TokenLoginPage", () => {
  beforeEach(() => {
    (window as any)["go"] = {};
    (window as any)["go"]["gui"] = {};
    (window as any)["go"]["gui"]["App"] = {};
    (window as any)["go"]["gui"]["App"]["GoJoinNetworkByToken"] = (token: string) => {};
    (window as any)["go"]["gui"]["App"]["GoParseAccessToken"] = (token: string) => {};
    (window as any)["go"]["gui"]["App"]["GoOpenDialogue"] = (arg1: any, arg2: any, arg3: any) => {};

    act(() => {
      render(
        <NetworksContextProvider>
          <MemoryRouter>
            <TokenLogin />
          </MemoryRouter>
        </NetworksContextProvider>
      );
    });

    // screen.debug();
  });

  it("renders title", () => {
    act(() => {
      expect(screen.getAllByText("Connect with Token").length).toBeGreaterThan(0);
    });
  });

  it("provides provides an input to enter token", () => {
    act(() => {
      expect(screen.getByTestId("token-inp")).toBeInTheDocument()
    });
  });

  it("validates token", () => {
    act(() => {
      fireEvent.click(screen.getByTestId("connect-btn"))
    });
    expect(screen.getByText('Token cannot be empty')).toBeInTheDocument()

    act(() => {
      fireEvent.change(screen.getByTestId("token-inp"), { target: { value: 'random-token' } })
      fireEvent.click(screen.getByTestId("connect-btn"))
    });
    expect(screen.queryByText('Token cannot be empty')).toBeNull()
  });

});
