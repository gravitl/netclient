import Grid from "@mui/material/Grid";
import { Button } from "@mui/material";
import LoopIcon from "@mui/icons-material/Loop";
import { useCallback, useEffect, useState } from "react";
import NetworkTable from "../components/NetworkTable";
import { Link } from "react-router-dom";
import { AppRoutes } from "../routes";
import { useNetworksContext } from "../store/NetworkContext";
import { refreshNetworks } from "../store/helpers";
import { main } from "../../wailsjs/go/models";

function Networks() {
  const [isLoadingNetworks, setIsLoadingNetworks] = useState<boolean>(true);
  const [networks, setNetworks] = useState<main.Network[]>([]);
  const { networksState, networksDispatch } = useNetworksContext();

  const loadNetworks = useCallback(() => {
    setIsLoadingNetworks(true);
    try {
      refreshNetworks(networksDispatch);
    } catch (err) {
      // TODO: notifications
      console.log(err);
    } finally {
      setIsLoadingNetworks(false);
    }

    return () => {
      setIsLoadingNetworks(false);
    };
  }, [setIsLoadingNetworks]);

  const changeNetworkStatus = useCallback(
    (networkName: string, newStatus: boolean) => {
      // get network
      const network = networks.find((nw) => (nw?.node?.network ?? '') === networkName);
      if (!network) return;
      // check and change status
      if (network?.node?.connected === newStatus) return;
      // make API call
      if (network.node) {
        network.node.connected = newStatus;
      }
      setNetworks([...networks]);
    },
    [networks, setNetworks]
  );

  // on init
  useEffect(() => {
    loadNetworks();
  }, [loadNetworks]);

  return (
    <Grid
      container
      direction="column"
      alignItems="center"
      className="page"
      rowSpacing={2}
    >
      <Grid item xs={12}>
        <h1 className="page-title">Networks</h1>
      </Grid>

      <Grid
        item
        xs={12}
        justifyContent="center"
        style={{ minHeight: "5rem", maxHeight: "65vh", overflow: "auto" }}
      >
        {isLoadingNetworks ? (
          <div style={{ textAlign: "center" }}>
            <LoopIcon fontSize="large" className="spinning" />
          </div>
        ) : (
          <NetworkTable
            networks={networksState.networks}
            onNetworkStatusChange={changeNetworkStatus}
            emptyMsg="No recent network"
          />
        )}
      </Grid>

      <Grid container item xs={12} justifyContent="center">
        <Grid item>
          <Button
            variant="contained"
            component={Link}
            to={AppRoutes.LOGIN_OPTIONS_ROUTE}
          >
            Add New
          </Button>
        </Grid>
      </Grid>
    </Grid>
  );
}

export default Networks;
