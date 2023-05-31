import { act, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe } from "vitest";
import TokenLogin from "../../src/pages/TokenLogin";
import {
  NetworksContextProvider,
} from "../../src/store/NetworkContext";


describe("TokenLoginPage", () => {
  beforeEach(() => {
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

  // it("provides provides radio options to choose token type", () => {
  //   act(() => {
  //     expect(screen.getByText("Token type")).toBeInTheDocument()
  //   });
  // });
  
  it("provides provides an input to enter enrollment key", () => {
    act(() => {
      expect(screen.getByTestId("enrollment-key-inp")).toBeInTheDocument()
    });
  });

  it("validates key", () => {
    act(() => {
      fireEvent.click(screen.getByTestId("connect-btn"))
    });
    expect(screen.getByText('Enrollment key cannot be empty')).toBeInTheDocument()

    act(() => {
      fireEvent.change(screen.getByTestId("enrollment-key-inp"), { target: { value: 'random-token' } })
      fireEvent.click(screen.getByTestId("connect-btn"))
    });
    expect(screen.queryByText('Enrollment key cannot be empty')).toBeNull()
  });

});
