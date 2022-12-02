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
} from "@mui/material";
import TablePaginationActions from "@mui/material/TablePagination/TablePaginationActions";
import React from "react";
import { Peer } from "../models/Peer";
import extractPeerEndpoint from "../utils/peers";

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

  return (
    <>
      {props.peers?.length > 0 ? (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Peer endpoint</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {(rowsPerPage > 0
                ? props.peers?.slice(
                    page * rowsPerPage,
                    page * rowsPerPage + rowsPerPage
                  )
                : props.peers
              ).map((p) => (
                <TableRow key={`${p.PublicKey}${p.Endpoint}`}>
                  <TableCell>{extractPeerEndpoint(p)}</TableCell>
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
