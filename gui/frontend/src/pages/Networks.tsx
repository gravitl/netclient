import Grid from "@mui/material/Grid";
import { Button } from "@mui/material";
import LoopIcon from "@mui/icons-material/Loop";
import { useCallback, useEffect, useState } from "react";
import NetworkTable from "../components/NetworkTable";
import { Link } from "react-router-dom";
import { AppRoutes } from "../routes";
import { useNetworksContext } from "../store/NetworkContext";
import { refreshNetworks, updateConnectionStatusAndRefreshNetworks } from "../store/helpers";
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
    async (networkName: string, newStatus: boolean) => {
      try {
        if (!networkName) {
          throw new Error("No network name")
        }
        await updateConnectionStatusAndRefreshNetworks(networksDispatch, networkName, newStatus)
      } catch (err) {
        // TODO: notify
        console.error(err);
      }
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
            emptyMsg="No joined network"
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
