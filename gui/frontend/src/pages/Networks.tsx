import Grid from "@mui/material/Grid";
import { Button, TextField } from "@mui/material";
import LoopIcon from "@mui/icons-material/Loop";
import { useCallback, useEffect, useMemo, useState } from "react";
import NetworkTable from "../components/NetworkTable";
import { Link } from "react-router-dom";
import { AppRoutes } from "../routes";
import { useNetworksContext } from "../store/NetworkContext";
import { refreshNetworks, updateConnectionStatusAndRefreshNetworks } from "../store/helpers";
import { main } from "../../wailsjs/go/models";

function Networks() {
  const [isLoadingNetworks, setIsLoadingNetworks] = useState<boolean>(true);
  const [networks, setNetworks] = useState<main.Network[]>([]);
  const [networksSearch, setNetworksSearch] = useState<string>('');
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

  const filteredNetworks = useMemo(() => {
    return networksState.networks.filter(nw => nw.node?.network.toLocaleLowerCase().includes(networksSearch.toLocaleLowerCase()))
  }, [networksSearch, networksState])

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
        container
        item
        xs={12}
        direction="column"
        alignItems="center"
        style={{ minHeight: "5rem", maxHeight: "65vh", overflow: "auto" }}
      >
        {isLoadingNetworks ? (
          <div style={{ textAlign: "center" }}>
            <LoopIcon fontSize="large" className="spinning" />
          </div>
        ) : (
          <>
            <Grid item xs={12}>
              <TextField
                style={{ width: "40vw" }}
                placeholder="Search for networks by name"
                value={networksSearch}
                onChange={(e) => setNetworksSearch(e.target.value)}
              />
            </Grid>

            <Grid item xs={12} marginTop="2rem">
              <NetworkTable
                networks={filteredNetworks}
                onNetworkStatusChange={changeNetworkStatus}
              />
            </Grid>
          </>
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
