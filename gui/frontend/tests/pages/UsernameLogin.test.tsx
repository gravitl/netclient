import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe } from "vitest";
import TokenLogin from "../../src/pages/TokenLogin";
import UsernameLogin from "../../src/pages/UsernameLogin";
import { NetworksContextProvider } from "../../src/store/NetworkContext";

describe("UsernameLoginPage", () => {
  beforeEach(() => {
    (window as any)["go"] = {};
    (window as any)["go"]["gui"] = {};
    (window as any)["go"]["gui"]["App"] = {};
    (window as any)["go"]["gui"]["App"]["GoJoinNetworkByBasicAuth"] = (
      arg1: string,
      arg2: string,
      arg3: string,
      arg4: string
    ) => {};
    (window as any)["go"]["gui"]["App"]["GoJoinNetworkBySso"] = (
      arg1: string,
      arg2: string
    ) => {};
    (window as any)["go"]["gui"]["App"]["GoGetRecentServerNames"] = () => [
      "mock-server-1",
      "mock-server-2",
    ];
    (window as any)["go"]["gui"]["App"]["GoOpenDialogue"] = (
      arg1: any,
      arg2: any,
      arg3: any
    ) => {};

    act(() => {
      render(
        <NetworksContextProvider>
          <MemoryRouter>
            <UsernameLogin />
          </MemoryRouter>
        </NetworksContextProvider>
      );
    });

    // screen.debug();
  });

  it("renders title", () => {
    act(() => {
      expect(
        screen.getAllByText("Connect with Username/Password").length
      ).toBeGreaterThan(0);
    });
  });

  it("provides provides inputs to enter credentials", () => {
    act(() => {
      expect(screen.getByTestId("server-inp")).toBeInTheDocument();
      expect(screen.getByTestId("network-inp")).toBeInTheDocument();
      expect(screen.getByTestId("username-inp")).toBeInTheDocument();
      expect(screen.getByTestId("password-inp")).toBeInTheDocument();
    });
  });

  it("validates inputs", () => {
    act(() => {
      fireEvent.click(screen.getByTestId("sso-login-btn"));
    });
    expect(screen.getByText("Server name cannot be empty")).toBeInTheDocument();

    act(() => {
      fireEvent.change(screen.getByTestId("server-inp"), {
        target: { value: "random-data" },
      });
      fireEvent.click(screen.getByTestId("login-btn"));
    });
    expect(
      screen.getByText("Network name cannot be empty")
    ).toBeInTheDocument();

    act(() => {
      fireEvent.change(screen.getByTestId("network-inp"), {
        target: { value: "random-data" },
      });
      fireEvent.click(screen.getByTestId("login-btn"));
    });
    expect(screen.getByText("Username cannot be empty")).toBeInTheDocument();

    act(() => {
      fireEvent.change(screen.getByTestId("username-inp"), {
        target: { value: "random-data" },
      });
      fireEvent.click(screen.getByTestId("login-btn"));
    });
    expect(screen.getByText("Password cannot be empty")).toBeInTheDocument();

    act(() => {
      fireEvent.change(screen.getByTestId("password-inp"), {
        target: { value: "random-data" },
      });
      fireEvent.click(screen.getByTestId("login-btn"));
    });
    expect(screen.queryByText("Server name cannot be empty")).toBeNull();
    expect(screen.queryByText("Network name cannot be empty")).toBeNull();
    expect(screen.queryByText("Username cannot be empty")).toBeNull();
    expect(screen.queryByText("Password cannot be empty")).toBeNull();
  });
});
