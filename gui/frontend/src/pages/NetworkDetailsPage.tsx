import { Grid, Switch, Typography } from "@mui/material";
import LoadingButton from "@mui/lab/LoadingButton";
import { useCallback, useEffect, useState } from "react";
import LoopIcon from "@mui/icons-material/Loop";
import PeersTable from "../components/PeersTable";
import { useNavigate, useParams } from "react-router-dom";
import { AppRoutes } from "../routes";
import { main } from "../../wailsjs/go/models";
import { useNetworksContext } from "../store/NetworkContext";
import {
  getNetwork,
  leaveAndRefreshNetworks,
  refreshNetworks,
  updateConnectionStatusAndRefreshNetworks,
} from "../store/helpers";
import { getUserConfirmation, notifyUser } from "../utils/messaging";
import { PeerConfig } from "../models/Peer";
import { GoGetNodePeers } from "../../wailsjs/go/main/App";

export default function NetworkDetailsPage() {
  const [networkDetails, setNetworkDetails] = useState<main.Network | null>(
    null,
  );
  const [isLoadingDetails, setIsLoadingDetails] = useState(true);
  const [isLoadingPeers, setIsLoadingPeers] = useState(true);
  const [isLeavingNetwork, setIsLeavingNetwork] = useState(false);
  const [networkPeers, setNetworkPeers] = useState<PeerConfig[]>([]);
  const navigate = useNavigate();
  const { networksState, networksDispatch } = useNetworksContext();
  const { networkName } = useParams();

  const loadPeers = useCallback(
    async (shouldNotifyOnError = false) => {
      if (!networkDetails?.node) return;
      try {
        const peers = (await GoGetNodePeers(networkDetails.node)) ?? [];
        peers.sort((a, b) => a.Endpoint.IP.localeCompare(b.Endpoint.IP));
        setNetworkPeers(() => peers);
      } catch (err) {
        console.error(err);
        if (shouldNotifyOnError) {
          await notifyUser(("Failed to load peers\n" + err) as string);
        }
      } finally {
        setIsLoadingPeers(() => false);
      }
    },
    [networkDetails, setNetworkPeers],
  );

  const loadNetworkDetails = useCallback(async () => {
    try {
      if (!networkName) {
        throw new Error("No network name");
      }
      const network = await getNetwork(networksState, networkName);
      setNetworkDetails(network);
      await loadPeers(true);
    } catch (err) {
      await notifyUser(("Failed to load network\n" + err) as string);
      console.error(err);
    } finally {
      setIsLoadingDetails(() => false);
    }
  }, [setIsLoadingDetails, setNetworkDetails, networksState]);

  const onConnectionStatusChange = useCallback(
    async (newStatus: boolean) => {
      try {
        if (!networkName) {
          throw new Error("No network name");
        }
        if (
          newStatus === false &&
          !(await getUserConfirmation(
            `Are you sure you want to disconnect from network: ${networkName}`,
            "Disconnect from network?",
          ))
        ) {
          return;
        }
        await updateConnectionStatusAndRefreshNetworks(
          networksDispatch,
          networkName,
          newStatus,
        );
      } catch (err) {
        await notifyUser(("Failed to update network status\n" + err) as string);
        console.error(err);
      }
    },
    [setNetworkDetails, networkDetails, networkName, networksDispatch],
  );

  const onLeaveNetwork = useCallback(async () => {
    try {
      if (!networkName) {
        throw new Error("No network name");
      }
      setIsLeavingNetwork(true);
      if (
        !(await getUserConfirmation(
          `Are you sure you want to leave network: ${networkName}`,
          "Leave network?",
        ))
      ) {
        return;
      }
      await leaveAndRefreshNetworks(networksDispatch, networkName);
      navigate(AppRoutes.NETWORKS_ROUTE, { replace: true });
    } catch (err) {
      await notifyUser(("Failed to leave network\n" + err) as string);
      console.error(err);
    } finally {
      setIsLeavingNetwork(false);
    }
  }, [navigate, networksDispatch, setIsLeavingNetwork, networkName]);

  useEffect(() => {
    loadNetworkDetails();
    const id = setInterval(async () => {
      try {
        if (!networkName) {
          throw new Error("No network name");
        }
        await refreshNetworks(networksDispatch);
        const network = await getNetwork(networksState, networkName);
        setNetworkDetails(network);
        await loadPeers(false);
      } catch (err) {
        console.error(err);
      }
    }, 5000);
    return () => clearInterval(id);
  }, [
    loadNetworkDetails,
    networkName,
    networksState,
    networksDispatch,
    loadPeers,
    setNetworkDetails,
  ]);

  return (
    <Grid
      container
      direction="column"
      alignItems="center"
      className="page"
      rowSpacing={2}
    >
      <Grid item xs={12}>
        <h1 className="page-title">Network Details</h1>
      </Grid>

      <Grid
        container
        item
        xs={12}
        justifyContent="center"
        style={{ minHeight: "5rem" }}
      >
        {isLoadingDetails ? (
          <div style={{ textAlign: "center" }}>
            <LoopIcon fontSize="large" className="spinning" />
          </div>
        ) : (
          <Grid container item style={{ width: "90vw" }}>
            <Grid container item xs={12}>
              <Grid item xs={3}>
                <Typography variant="overline">Network name</Typography>
                <Typography variant="h4">
                  {networkDetails?.node?.network}
                </Typography>
              </Grid>

              <Grid item xs={3}>
                <Typography variant="overline">
                  Connected/Disconnected
                </Typography>
                <br />
                <Switch
                  checked={networkDetails?.node?.connected}
                  onChange={() =>
                    onConnectionStatusChange(!networkDetails?.node?.connected)
                  }
                  data-testid="connect-btn"
                />
              </Grid>

              <Grid item xs={6} textAlign="right">
                <LoadingButton
                  loading={isLeavingNetwork}
                  variant="outlined"
                  color="error"
                  onClick={onLeaveNetwork}
                  data-testid="leave-btn"
                >
                  Leave Network
                </LoadingButton>
              </Grid>
            </Grid>

            <Grid
              item
              xs={12}
              style={{ marginTop: "2rem", maxHeight: "60vh", overflow: "auto" }}
            >
              {isLoadingPeers ? (
                <div style={{ textAlign: "center", height: "5rem" }}>
                  <LoopIcon fontSize="large" className="spinning" />
                </div>
              ) : (
                <PeersTable peers={networkPeers} />
              )}
            </Grid>
          </Grid>
        )}
      </Grid>
    </Grid>
  );
}
