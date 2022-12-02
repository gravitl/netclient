import { Button, Grid, Switch, Typography } from "@mui/material";
import { useCallback, useEffect, useState } from "react";
import LoopIcon from "@mui/icons-material/Loop";
import PeersTable from "../components/PeersTable";
import { useNavigate } from "react-router-dom";
import { AppRoutes } from "../routes";

const mockNetworkDetails = {
  name: "Test net",
  isConnected: true,
  peers: [
    { name: "Peer 1", addr: "10.0.1.125" },
    { name: "Peer 2", addr: "10.0.1.12" },
    { name: "Peer 3", addr: "10.0.1.15" },
    { name: "Peer 4", addr: "10.0.1.25" },
    { name: "Peer 5", addr: "10.0.1.1" },
    { name: "Peer 6", addr: "10.0.1.122" },
    { name: "Peer 7", addr: "10.0.1.123" },
    { name: "Peer 8", addr: "10.0.1.124" },
    { name: "Peer 9", addr: "10.0.1.115" },
    { name: "Peer 10", addr: "10.0.10.125" },
    { name: "Peer 11", addr: "10.0.10.125" },
    { name: "Peer 12", addr: "10.0.10.125" },
    { name: "Peer 13", addr: "10.0.10.125" },
    { name: "Peer 14", addr: "10.0.10.125" },
    { name: "Peer 15", addr: "10.0.10.125" },
    { name: "Peer 16", addr: "10.0.10.125" },
    { name: "Peer 17", addr: "10.0.10.125" },
    { name: "Peer 18", addr: "10.0.10.125" },
    { name: "Peer 19", addr: "10.0.10.125" },
    { name: "Peer 20", addr: "10.0.10.125" },
    { name: "Peer 21", addr: "10.0.10.125" },
    { name: "Peer 22", addr: "10.0.10.125" },
    { name: "Peer 23", addr: "10.0.10.125" },
    { name: "Peer 24", addr: "10.0.10.125" },
    { name: "Peer 25", addr: "10.0.10.125" },
    { name: "Peer 26", addr: "10.0.10.125" },
    { name: "Peer 27", addr: "10.0.10.125" },
    { name: "Peer 28", addr: "10.0.10.125" },
    { name: "Peer 29", addr: "10.0.10.125" },
    { name: "Peer 30", addr: "10.0.10.125" },
    { name: "Peer 31", addr: "10.0.10.125" },
    { name: "Peer 32", addr: "10.0.10.125" },
    { name: "Peer 33", addr: "10.0.10.125" },
    { name: "Peer 34", addr: "10.0.10.125" },
    { name: "Peer 35", addr: "10.0.10.125" },
    { name: "Peer 36", addr: "10.0.10.125" },
  ],
};

export default function NetworkDetailsPage() {
  const [networkDetails, setNetworkDetils] = useState<any>(null);
  const [isLoadingDetails, setIsLoadingDetails] = useState(true);
  const navigate = useNavigate();

  const loadNetworkDetails = useCallback(() => {
    // TODO: get details from context
    return setTimeout(() => {
      setIsLoadingDetails(() => true);
      setNetworkDetils(mockNetworkDetails);
      setIsLoadingDetails(() => false);
    }, 2000);
  }, [setIsLoadingDetails, setNetworkDetils]);

  const onConnectionStatusChange = useCallback(() => {
    // TODO: implementation
    setNetworkDetils({
      ...networkDetails,
      isConnected: !networkDetails.isConnected,
    });
  }, [setNetworkDetils, networkDetails]);

  const onLeaveNetwork = useCallback(() => {
    // TODO: implement
    navigate(AppRoutes.NETWORKS_ROUTE, { replace: true })
  }, [navigate])

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
                <Typography variant="h4">{networkDetails?.name}</Typography>
              </div>

              <div style={{ marginTop: "4rem" }}>
                <Typography variant="overline">
                  Connected/Disconnected
                </Typography>
                <br />
                <Switch
                  checked={networkDetails?.isConnected}
                  onChange={onConnectionStatusChange}
                />
              </div>

              <div style={{ marginTop: "4rem" }}>
                <Button
                  variant="contained"
                  onClick={onLeaveNetwork}
                >
                  Leave Network
                </Button>
              </div>
            </Grid>
            <Grid item xs={9} style={{ maxHeight: "70vh", overflow: "auto" }}>
              <PeersTable peers={networkDetails?.peers} />
            </Grid>
          </Grid>
        )}
      </Grid>
    </Grid>
  );
}
