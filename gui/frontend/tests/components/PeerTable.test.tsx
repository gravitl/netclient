import { act, render, screen } from "@testing-library/react";
import { beforeEach, describe } from "vitest";
import PeersTable from "../../src/components/PeersTable";
import { PeerConfig } from "../../src/models/Peer";

import {
  byteArrayToString,
  extractPeerPrivateEndpoints,
  extractPeerPublicEndpoint,
} from "../../src/utils/peers";

const mockPeers: PeerConfig[] = [
  {
    AllowedIPs: [{ IP: "10.0.0.124", Mask: "//w+" }],
    Endpoint: {
      IP: "51.0.0.0",
      Port: 51280,
      Zone: "",
    },
    PublicKey: [32, 34, 34, 54, 57],
    Remove: false,
    UpdateOnly: false,
    PresharedKey: [43, 46, 65, 57, 44],
    PersistentKeepaliveInterval: 1500,
    ReplaceAllowedIPs: false,
  },
  {
    AllowedIPs: [{ IP: "10.0.0.125", Mask: "//w+" }],
    Endpoint: {
      IP: "52.0.0.24",
      Port: 51281,
      Zone: "",
    },
    PublicKey: [32, 34, 34, 54, 54],
    Remove: false,
    UpdateOnly: false,
    PresharedKey: [43, 46, 65, 57, 43],
    PersistentKeepaliveInterval: 1500,
    ReplaceAllowedIPs: false,
  },
];

describe("PeersTable", () => {
  beforeEach(() => {
    (window as any)["go"] = {};
    (window as any)["go"]["gui"] = {};
    (window as any)["go"]["gui"]["App"] = {};

    act(() => {
      render(<PeersTable peers={mockPeers} />);
    });

    // screen.debug();
  });

  it("renders peer details correctly", async () => {
    const peersEls = await screen.findAllByTestId("peer-row");
    const mockPublicEndpoints = mockPeers.flatMap((p) =>
      extractPeerPublicEndpoint(p)
    );
    const mockPrivateEndpoints = mockPeers.flatMap((p) =>
      extractPeerPrivateEndpoints(p)
    );
    const mockPublicKeys: string[] = mockPeers.map((p) =>
      byteArrayToString(p.PublicKey)
    );

    // peers should be listed
    expect(peersEls.length).toBeGreaterThan(0);

    // public endpoints should show
    const publicEndpointsEls = await screen.findAllByTestId("public-endpoint");
    publicEndpointsEls.forEach((el) => {
      expect(mockPublicEndpoints).toContain(el.textContent);
    });

    // private endpoints should show
    const privateEndpointsEls = await screen.findAllByTestId(
      "private-endpoint"
    );
    privateEndpointsEls.forEach((el) => {
      expect(mockPrivateEndpoints).toContain(el.textContent);
    });

    // public keys should show
    const publicKeysEls = await screen.findAllByTestId("public-key");
    publicKeysEls.forEach((el) => {
      expect(mockPublicKeys).toContain(el.textContent);
    });
  });
});
