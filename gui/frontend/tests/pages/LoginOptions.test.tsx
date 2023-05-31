import { act, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe } from "vitest";
import LoginOption from "../../src/pages/LoginOption";
import {
  NetworksContextProvider,
} from "../../src/store/NetworkContext";


describe("LoginOptionsPage", () => {
  beforeEach(() => {
    act(() => {
      render(
        <NetworksContextProvider>
          <MemoryRouter>
            <LoginOption />
          </MemoryRouter>
        </NetworksContextProvider>
      );
    });

    // screen.debug();
  });

  it("renders title", () => {
    act(() => {
      expect(screen.getAllByText("How would you like to connect?").length).toBeGreaterThan(0);
    });
  });

  it("provides login/join options", () => {
    act(() => {
      expect(screen.getByTestId("login-by-token-btn")).toBeInTheDocument()
      expect(screen.getByTestId("login-by-token-btn")).toHaveTextContent('By Enrollment Key')

      expect(screen.getByTestId("login-by-cred-btn")).toBeInTheDocument()
      expect(screen.getByTestId("login-by-cred-btn")).toHaveTextContent('Username/Password/SSO')
    });
  });

});
