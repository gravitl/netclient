import {
  TableContainer,
  Paper,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
  Grid,
  TableFooter,
  TablePagination,
  IconButton,
} from "@mui/material";
import TablePaginationActions from "@mui/material/TablePagination/TablePaginationActions";
import React, { useCallback } from "react";
import { Peer } from "../models/Peer";
import {
  extractPeerPublicEndpoint,
  byteArrayToString,
  extractPeerPrivateEndpoints,
} from "../utils/peers";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import { writeTextToClipboard } from "../utils/browser";
import { notifyUser } from "../utils/messaging";

interface PeersTableProps {
  peers: Peer[];
  emptyMsg?: string;
}

const rowsPerPageOptions = [10, 25, 50, 100, 256, { label: "All", value: -1 }];

export default function PeersTable(props: PeersTableProps) {
  const [page, setPage] = React.useState(0);
  const [rowsPerPage, setRowsPerPage] = React.useState(10);

  const handleChangePage = (
    event: React.MouseEvent<HTMLButtonElement> | null,
    newPage: number
  ) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (
    event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const onCopyClicked = useCallback(async (text: string) => {
    try {
      writeTextToClipboard(text);
    } catch (err) {
      await notifyUser("Failed to copy\n" + err);
    }
  }, []);

  return (
    <>
      {props.peers?.length > 0 ? (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Peer endpoint (public)</TableCell>
                <TableCell>Peer endpoint (private)</TableCell>
                <TableCell>Public key</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {(rowsPerPage > 0
                ? props.peers?.slice(
                    page * rowsPerPage,
                    page * rowsPerPage + rowsPerPage
                  )
                : props.peers
              ).map((p, i) => (
                <TableRow key={`${p.PublicKey}-${i}`} data-testid="peer-row">
                  <TableCell data-testid="public-endpoint">
                    {
                      <span
                        onClick={() =>
                          onCopyClicked(extractPeerPublicEndpoint(p))
                        }
                        title="Copy"
                        style={{ cursor: "pointer" }}
                      >
                        {extractPeerPublicEndpoint(p)}
                      </span>
                    }
                  </TableCell>
                  <TableCell data-testid="private-endpoint">
                    {extractPeerPrivateEndpoints(p).map(
                      (endpoint, i, endpoints) => (
                        <>
                          <span key={endpoint + i}>
                            {endpoint}
                            <IconButton
                              size="small"
                              onClick={() => onCopyClicked(endpoint)}
                              title="Copy"
                            >
                              <ContentCopyIcon
                                style={{ width: "0.9rem", height: "0.9rem" }}
                              />
                            </IconButton>
                          </span>
                          {i !== endpoints.length - 1 ? ", " : ""}
                        </>
                      )
                    )}
                  </TableCell>
                  <TableCell data-testid="public-key">
                    <span
                      onClick={() => onCopyClicked(byteArrayToString(p.PublicKey))}
                      title="Copy"
                      style={{ cursor: "pointer" }}
                    >
                      {byteArrayToString(p.PublicKey)}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
            <TableFooter>
              <TableRow>
                <TablePagination
                  rowsPerPageOptions={rowsPerPageOptions}
                  colSpan={3}
                  count={props.peers.length}
                  rowsPerPage={rowsPerPage}
                  page={page}
                  SelectProps={{
                    inputProps: {
                      "aria-label": "rows per page",
                    },
                    native: true,
                  }}
                  onPageChange={handleChangePage}
                  onRowsPerPageChange={handleChangeRowsPerPage}
                  ActionsComponent={TablePaginationActions}
                />
              </TableRow>
            </TableFooter>
          </Table>
        </TableContainer>
      ) : (
        <Grid container>
          <Grid item xs={12} style={{ textAlign: "center" }}>
            <h4>{props.emptyMsg ? props.emptyMsg : "No peers"}</h4>
          </Grid>
        </Grid>
      )}
    </>
  );
}
