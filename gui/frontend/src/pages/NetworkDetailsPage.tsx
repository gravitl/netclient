import { Grid, Switch, Typography } from "@mui/material";
import LoadingButton from '@mui/lab/LoadingButton';
import { useCallback, useEffect, useState } from "react";
import LoopIcon from "@mui/icons-material/Loop";
import PeersTable from "../components/PeersTable";
import { useNavigate, useParams } from "react-router-dom";
import { AppRoutes } from "../routes";
import { main } from "../../wailsjs/go/models";
import { useNetworksContext } from "../store/NetworkContext";
import { getNetwork, leaveAndRefreshNetworks, updateConnectionStatusAndRefreshNetworks } from "../store/helpers";

export default function NetworkDetailsPage() {
  const [networkDetails, setNetworkDetails] = useState<main.Network | null>(
    null
  );
  const [isLoadingDetails, setIsLoadingDetails] = useState(true);
  const [isLeavingNetwork, setIsLeavingNetwork] = useState(false);
  const navigate = useNavigate();
  const { networksState, networksDispatch } = useNetworksContext();
  const { networkName } = useParams();

  const loadNetworkDetails = useCallback(async () => {
    try {
      setIsLoadingDetails(() => true);
      if (!networkName) {
        throw new Error("No network name")
      }
      const network = await getNetwork(networksState, networkName)
      setNetworkDetails(network);
    } catch (err) {
      // TODO: notify
      console.error(err)
    } finally {
      setIsLoadingDetails(() => false);
    }
  }, [setIsLoadingDetails, setNetworkDetails, networksState]);

  const onConnectionStatusChange = useCallback(async (newStatus: boolean) => {
    try {
      if (!networkName) {
        throw new Error("No network name")
      }
      await updateConnectionStatusAndRefreshNetworks(networksDispatch, networkName, newStatus)
    } catch (err) {
      // TODO: notify
      console.error(err);
    }
  }, [setNetworkDetails, networkDetails, networkName, networksDispatch]);

  const onLeaveNetwork = useCallback(async () => {
    try {
      if (!networkName) {
        throw new Error("No network name")
      }
      setIsLeavingNetwork(true)
      await leaveAndRefreshNetworks(networksDispatch, networkName)
      navigate(AppRoutes.NETWORKS_ROUTE, { replace: true });
    } catch (err) {
      // TODO: notify
      console.error(err)
    } finally {
      setIsLeavingNetwork(false)
    }
  }, [navigate, networksDispatch, setIsLeavingNetwork, networkName]);

  useEffect(() => {
    loadNetworkDetails();
  }, [loadNetworkDetails]);

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
            <Grid item xs={3}>
              <div>
                <Typography variant="overline">Network name</Typography>
                <Typography variant="h4">{networkDetails?.node?.network}</Typography>
              </div>

              <div style={{ marginTop: "4rem" }}>
                <Typography variant="overline">
                  Connected/Disconnected
                </Typography>
                <br />
                <Switch
                  checked={networkDetails?.node?.connected}
                  onChange={() => onConnectionStatusChange(!networkDetails?.node?.connected)}
                />
              </div>

              <div style={{ marginTop: "4rem" }}>
                <LoadingButton loading={isLeavingNetwork} variant="contained" onClick={onLeaveNetwork}>
                  Leave Network
                </LoadingButton>
              </div>
            </Grid>
            <Grid item xs={9} style={{ maxHeight: "70vh", overflow: "auto" }}>
              <PeersTable peers={networkDetails?.node?.peers ?? []} />
            </Grid>
          </Grid>
        )}
      </Grid>
    </Grid>
  );
}
