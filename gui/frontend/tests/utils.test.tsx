import { act, screen, waitFor } from "@testing-library/react";
import { describe } from "vitest";
import { Peer } from "../src/models/Peer";
import { AppRoutes } from "../src/routes";
import { writeTextToClipboard } from "../src/utils/browser";
import { getUserConfirmation, notifyUser } from "../src/utils/messaging";
import { getNetworkDetailsPageUrl } from "../src/utils/networks";
import { extractPeerPrivateEndpoints, extractPeerPublicEndpoint } from "../src/utils/peers";
import { main } from "../wailsjs/go/models";

function setupMocks() {
  (window as any)["go"] = {};
  (window as any)["go"]["gui"] = {};
  (window as any)["go"]["gui"]["App"] = {};
  (window as any)["go"]["gui"]["App"]["GoGetKnownNetworks"] = () => [];
  (window as any)["go"]["gui"]["App"]["GoOpenDialogue"] = (
    arg1: any,
    arg2: any,
    arg3: any
  ) => {
    return new Promise((resolve, reject) => {
      resolve(MOCK_CHOICE);
    });
  };
  (window as any)["go"]["gui"]["App"]["GoWriteToClipboard"] = (text: string) =>
    Promise.resolve(text);
}

const MOCK_CHOICE = "mock-choice";
describe("networks utility functions", () => {
  beforeEach(() => {
    setupMocks();
  });

  it("provides a function to form network details page URL from network id", () => {
    const mockNetworkId = "mock-net";

    const networkDetailsUrl = getNetworkDetailsPageUrl(mockNetworkId);

    expect(networkDetailsUrl).toEqual(
      AppRoutes.NETWORK_DETAILS_ROUTE.split(":")?.[0] + `${mockNetworkId}`
    );
  });
});

describe("messaging utility functions", () => {
  beforeEach(() => {
    setupMocks();
  });

  it("provides a function to notify users", async () => {
    expect(await getUserConfirmation("test message", "test title")).toEqual(
      false
    );
  });

  it("provides a function to get user's confirmations", async () => {
    expect(await notifyUser("test message")).toEqual(MOCK_CHOICE);
  });
});

describe("browser utility functions", () => {
  beforeEach(() => {
    setupMocks();
  });

  it("provides a function to write text to clipboard", async () => {
    const mockText = "test message";

    expect(await writeTextToClipboard(mockText)).toEqual(mockText);
  });
});

describe("peers utility functions", () => {
  beforeEach(() => {
    setupMocks();
  });

  it("provides a function to get peer public endpoint", () => {
    const mockPeer: Peer = {
      PublicKey: [56, 65, 75, 77],
      Endpoint: { IP: "51.0.0.1", Port: 38378, Zone: "" },
      AllowedIPs: [{ IP: "10.0.0.51", Mask: "w+" }],
      Remove: false,
      UpdateOnly: false,
      PersistentKeepaliveInterval: 0,
      ReplaceAllowedIPs: false
    };

    const expected = `${mockPeer.Endpoint.IP}:${mockPeer.Endpoint.Port}`

    expect(extractPeerPublicEndpoint(mockPeer)).toEqual(expected);
    expect(extractPeerPrivateEndpoints(mockPeer)).toEqual(["10.0.0.51"]);
  });
});
