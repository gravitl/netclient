import Grid from "@mui/material/Grid";
import { Button, TextField } from "@mui/material";
import LoopIcon from "@mui/icons-material/Loop";
import { useCallback, useEffect, useMemo, useState } from "react";
import NetworkTable from "../components/NetworkTable";
import { Link } from "react-router-dom";
import { AppRoutes } from "../routes";
import { useNetworksContext } from "../store/NetworkContext";
import {
  refreshNetworks,
  updateConnectionStatusAndRefreshNetworks,
} from "../store/helpers";
import { main } from "../../wailsjs/go/models";
import { getUserConfirmation, notifyUser } from "../utils/messaging";

function Networks() {
  const [isLoadingNetworks, setIsLoadingNetworks] = useState<boolean>(true);
  const [networks, setNetworks] = useState<main.Network[]>([]);
  const [networksSearch, setNetworksSearch] = useState<string>("");
  const { networksState, networksDispatch } = useNetworksContext();

  const loadNetworks = useCallback(async () => {
    setIsLoadingNetworks(true);
    try {
      await refreshNetworks(networksDispatch);
    } catch (err) {
      await notifyUser(("Failed to load networks\n" + err) as string);
      console.log(err);
    } finally {
      setIsLoadingNetworks(false);
    }

    return () => {
      setIsLoadingNetworks(false);
    };
  }, [setIsLoadingNetworks]);

  const filteredNetworks = useMemo(() => {
    return networksState.networks.filter(
      (nw) =>
        nw.node?.network
          .toLocaleLowerCase()
          .includes(networksSearch.toLocaleLowerCase()),
    );
  }, [networksSearch, networksState]);

  const changeNetworkStatus = useCallback(
    async (networkName: string, newStatus: boolean) => {
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
    [networks, setNetworks],
  );

  // on init
  useEffect(() => {
    loadNetworks();
    const id = setInterval(() => refreshNetworks(networksDispatch), 5000);
    return () => clearInterval(id);
  }, [loadNetworks, networksDispatch]);

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
              {/* search network */}
              <TextField
                style={{ width: "40vw" }}
                placeholder="Search for networks by name"
                value={networksSearch}
                onChange={(e) => setNetworksSearch(e.target.value)}
                size="small"
                data-testid="networks-search-inp"
              />

              {/* add network button */}
              <Button
                variant="contained"
                component={Link}
                size="medium"
                style={{ marginLeft: "2rem" }}
                to={AppRoutes.LOGIN_OPTIONS_ROUTE}
                data-testid="add-network-btn"
              >
                Add New
              </Button>
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
    </Grid>
  );
}

export default Networks;
