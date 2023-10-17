import {
  TableContainer,
  Paper,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
  Button,
  Switch,
  Grid,
} from "@mui/material";
import { useCallback } from "react";
import { Link } from "react-router-dom";
import { main } from "../../wailsjs/go/models";
import { getNetworkDetailsPageUrl } from "../utils/networks";

interface NetworkTableProps {
  networks: main.Network[];
  onNetworkStatusChange: (networkName: string, newStatus: boolean) => void;
  emptyMsg?: string;
}

export default function NetworkTable(props: NetworkTableProps) {
  const getNetworkLink = useCallback((network: main.Network) => {
    return getNetworkDetailsPageUrl(network?.node?.network ?? "");
  }, []);

  return (
    <>
      {props?.networks?.length > 0 ? (
        <TableContainer component={Paper} style={{ width: "80vw" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Network</TableCell>
                <TableCell align="right">Connect/Disconnect</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {props.networks.map((nw, i) => (
                <TableRow
                  key={(nw?.node?.network ?? "") + i}
                  data-testid="network-row"
                >
                  <TableCell data-testid="network-name">
                    <Button
                      variant="text"
                      title="View details"
                      component={Link}
                      to={getNetworkLink(nw)}
                    >
                      {nw?.node?.network ?? "n/a"}
                    </Button>
                  </TableCell>
                  <TableCell align="right">
                    <Switch
                      data-testid="status-toggle"
                      checked={nw?.node?.connected ?? false}
                      onChange={() =>
                        props.onNetworkStatusChange(
                          nw?.node?.network ?? "",
                          !nw?.node?.connected,
                        )
                      }
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ) : (
        <Grid container>
          <Grid item xs={12} style={{ textAlign: "center" }}>
            <h4>{props.emptyMsg ? props.emptyMsg : "No networks found"}</h4>
          </Grid>
        </Grid>
      )}
    </>
  );
}
