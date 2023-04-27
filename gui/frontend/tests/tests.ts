import { expect, afterEach } from "vitest";
import { cleanup } from "@testing-library/react";
import matchers from "@testing-library/jest-dom/matchers";

// extends Vitest's expect method with methods from react-testing-library
expect.extend(matchers);


export const MOCK_CHOICE = "mock-choice";

export function setupMocks() {
  (window as any)["go"] = {};
  (window as any)["go"]["main"] = {};
  (window as any)["go"]["main"]["App"] = {};
  (window as any)["go"]["main"]["App"]["GoGetKnownNetworks"] = () => [];
  (window as any)["go"]["main"]["App"]["GoOpenDialogue"] = (
    arg1: any,
    arg2: any,
    arg3: any
  ) => {
    return new Promise((resolve, reject) => {
      resolve(MOCK_CHOICE);
    });
  };
  (window as any)["go"]["main"]["App"]["GoWriteToClipboard"] = (text: string) =>
    Promise.resolve(text);
  (window as any)["go"]["main"]["App"]["GoGetRecentServerNames"] = () =>
    Promise.resolve([]);
}

beforeAll(() => {
  setupMocks();
});

// runs a cleanup after each test case (e.g. clearing jsdom)
afterEach(() => {
  cleanup();
});
