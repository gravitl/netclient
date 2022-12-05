import Grid from "@mui/material/Grid";
import {
  Autocomplete,
  Button,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import { useCallback, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AppRoutes } from "../routes";

const mockRecentServers = [
  "Office-server",
  "server-1",
  "krypto-punk-server",
  "do-not-connect-server",
  "gothic-server",
];

export default function UsernameLogin() {
  const [serverName, setServerName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  const getRecentServers = useCallback(() => mockRecentServers, []);
  const onSsoLoginClick = useCallback(() => {}, []);
  const onLoginClick = useCallback(() => {
    // TODO: implement
    navigate(AppRoutes.NETWORKS_ROUTE)
  }, [navigate]);

  return (
    <Grid
      container
      direction="column"
      alignItems="center"
      className="page"
      rowSpacing={2}
      style={{ textAlign: "center" }}
    >
      <Grid item xs={12}>
        <h1 className="page-title">Connect with Username/Password</h1>
      </Grid>

      <Grid container item xs={12} justifyContent="center">
        <Autocomplete
          freeSolo
          options={getRecentServers()}
          value={serverName}
          onChange={(e, selectedName) => setServerName(selectedName!)}
          renderInput={(params) => (
            <TextField
              {...params}
              value={serverName}
              onChange={(e) => setServerName(e.target.value)}
              label="Server name"
              placeholder="Enter server name"
              aria-label="server name"
            />
          )}
          style={{ width: "40vw" }}
        />
      </Grid>

      <Grid item xs={12}>
        <TextField
          label="Username"
          placeholder="Enter username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={{ width: "40vw" }}
        />
      </Grid>

      <Grid item xs={12}>
        <TextField
          type="password"
          label="Password"
          placeholder="Enter password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{ width: "40vw" }}
        />
      </Grid>

      <Grid item xs={12}>
        <Typography variant="caption">
          *Details can be acquired from Netmaker server
        </Typography>
      </Grid>

      <Grid item xs={12}>
        <Button variant="contained" onClick={onLoginClick}>
          Login
        </Button>
      </Grid>
      <Grid item xs={12}>
        <Button size="small" variant="outlined" onClick={onSsoLoginClick}>
          <AdminPanelSettingsIcon /> SSO Login
        </Button>
      </Grid>
    </Grid>
  );
}
