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

  it("provides provides inputs to enter custom endpoint and port", () => {
    act(() => {
      expect(screen.getByTestId("custom-endpoint-inp")).toBeInTheDocument()
      expect(screen.getByTestId("custom-port-inp")).toBeInTheDocument()
    });
  });

  // it("validates inputs", () => {
  //   act(() => {
  //     fireEvent.click(screen.getByTestId("sso-login-btn"));
  //   });
  //   expect(screen.getByText("Server name cannot be empty")).toBeInTheDocument();

  //   act(() => {
  //     fireEvent.change(screen.getByTestId("server-inp"), {
  //       target: { value: "random-data" },
  //     });
  //     fireEvent.click(screen.getByTestId("login-btn"));
  //   });
  //   expect(
  //     screen.getByText("Network name cannot be empty")
  //   ).toBeInTheDocument();

  //   act(() => {
  //     fireEvent.change(screen.getByTestId("network-inp"), {
  //       target: { value: "random-data" },
  //     });
  //     fireEvent.click(screen.getByTestId("login-btn"));
  //   });
  //   expect(screen.getByText("Username cannot be empty")).toBeInTheDocument();

  //   act(() => {
  //     fireEvent.change(screen.getByTestId("username-inp"), {
  //       target: { value: "random-data" },
  //     });
  //     fireEvent.click(screen.getByTestId("login-btn"));
  //   });
  //   expect(screen.getByText("Password cannot be empty")).toBeInTheDocument();

  //   act(() => {
  //     fireEvent.change(screen.getByTestId("password-inp"), {
  //       target: { value: "random-data" },
  //     });
  //     fireEvent.click(screen.getByTestId("login-btn"));
  //   });
  //   expect(screen.queryByText("Server name cannot be empty")).toBeNull();
  //   expect(screen.queryByText("Network name cannot be empty")).toBeNull();
  //   expect(screen.queryByText("Username cannot be empty")).toBeNull();
  //   expect(screen.queryByText("Password cannot be empty")).toBeNull();
  // });
});
