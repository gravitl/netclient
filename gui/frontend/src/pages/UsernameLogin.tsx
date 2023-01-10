import Grid from "@mui/material/Grid";
import { Autocomplete, TextField, Typography } from "@mui/material";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { LoadingButton } from "@mui/lab";
import { getNetworkDetailsPageUrl } from "../utils/networks";
import {
  NetworksContextDispatcherProps,
  useNetworksContext,
} from "../store/NetworkContext";
import {
  GoGetRecentServerNames,
  GoJoinNetworkByBasicAuth,
  GoJoinNetworkBySso,
} from "../../wailsjs/go/main/App";
import { notifyUser } from "../utils/messaging";

export default function UsernameLogin() {
  const [recentServerNames, setRecentServerNames] = useState<string[]>([]);
  const [serverName, setServerName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [networkName, setNetworkName] = useState("");
  const [isConnecting, setIsConnecting] = useState(false);
  const [isServerNameFormValid, setIsServerNameFormValid] = useState(true);
  const [isUsernameFormValid, setIsUsernameFormValid] = useState(true);
  const [isNetworkNameFormValid, setIsNetworkNameFormValid] = useState(true);
  const [isPasswordFormValid, setIsPasswordFormValid] = useState(true);
  const navigate = useNavigate();
  const { networksState, networksDispatch } = useNetworksContext();

  const loadRecentServers = useCallback(async () => {
    let serverNames = await GoGetRecentServerNames();
    serverNames = serverNames.map(name => name = `api.${name}`)
    setRecentServerNames(serverNames);
  }, [setRecentServerNames]);

  const checkIsFormValid = useCallback(
    (type: "basic-auth" | "sso") => {
      setIsServerNameFormValid(true);
      setIsNetworkNameFormValid(true);
      setIsUsernameFormValid(true);
      setIsPasswordFormValid(true);

      if (serverName.length < 1) {
        setIsServerNameFormValid(false);
        return false;
      }
      if (networkName.length < 1) {
        setIsNetworkNameFormValid(false);
        return false;
      }
      if (type === "basic-auth" && username.length < 1) {
        setIsUsernameFormValid(false);
        return false;
      }
      if (type === "basic-auth" && password.length < 1) {
        setIsPasswordFormValid(false);
        return false;
      }

      return true;
    },
    [
      setIsServerNameFormValid,
      setIsUsernameFormValid,
      setIsNetworkNameFormValid,
      setIsPasswordFormValid,
      serverName,
      username,
      networkName,
      password,
    ]
  );

  const onSsoLoginClick = useCallback(async () => {
    if (!checkIsFormValid("sso")) return;

    setIsConnecting(true);
    try {
      await GoJoinNetworkBySso(serverName, networkName);

      const data: NetworksContextDispatcherProps = {
        action: "refresh-networks",
      };
      networksDispatch(data);

      navigate(getNetworkDetailsPageUrl(networkName));
    } catch (err) {
      await notifyUser("Failed to login to network\n" + err as string);
      console.error(err);
    } finally {
      setIsConnecting(false);
    }
  }, [
    navigate,
    setIsConnecting,
    networksDispatch,
    checkIsFormValid,
    serverName,
    networkName,
  ]);

  const onLoginClick = useCallback(async () => {
    if (!checkIsFormValid("basic-auth")) return;

    setIsConnecting(true);
    try {
      await GoJoinNetworkByBasicAuth(serverName, username, networkName, password);

      const data: NetworksContextDispatcherProps = {
        action: "refresh-networks",
      };
      networksDispatch(data);

      // redirect
      navigate(getNetworkDetailsPageUrl(networkName));
    } catch (err) {
      await notifyUser("Failed to login to network\n" + err as string);
      console.error(err);
    } finally {
      setIsConnecting(false);
    }
  }, [
    navigate,
    setIsConnecting,
    checkIsFormValid,
    networksDispatch,
    serverName,
    username,
    networkName,
    password,
  ]);

  // on created
  useEffect(() => {
    loadRecentServers();
  }, [loadRecentServers]);

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
          options={recentServerNames}
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
              error={!isServerNameFormValid}
              helperText={
                isServerNameFormValid ? "" : "Server name cannot be empty"
              }
              inputProps={{ 'data-testid': 'server-inp' }}
            />
          )}
          style={{ width: "40vw" }}
        />
      </Grid>

      <Grid item xs={12}>
        <TextField
          label="Network"
          placeholder="Enter network"
          value={networkName}
          onChange={(e) => setNetworkName(e.target.value)}
          style={{ width: "40vw" }}
          error={!isNetworkNameFormValid}
          helperText={
            isNetworkNameFormValid ? "" : "Network name cannot be empty"
          }
          inputProps={{ 'data-testid': 'network-inp' }}
        />
      </Grid>

      <Grid item xs={12}>
        <TextField
          label="Username"
          placeholder="Enter username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={{ width: "40vw" }}
          error={!isUsernameFormValid}
          helperText={isUsernameFormValid ? "" : "Username cannot be empty"}
          inputProps={{ 'data-testid': 'username-inp' }}
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
          error={!isPasswordFormValid}
          helperText={isPasswordFormValid ? "" : "Password cannot be empty"}
          inputProps={{ 'data-testid': 'password-inp' }}
        />
      </Grid>

      <Grid item xs={12}>
        <Typography variant="caption">
          *Details can be acquired from Netmaker server
        </Typography>
      </Grid>

      <Grid item xs={12}>
        <LoadingButton
          loading={isConnecting}
          variant="contained"
          onClick={onLoginClick}
          data-testid="login-btn"
        >
          Login
        </LoadingButton>
      </Grid>
      <Grid item xs={12}>
        <LoadingButton
          loading={isConnecting}
          size="small"
          variant="outlined"
          onClick={onSsoLoginClick}
          data-testid="sso-login-btn"
        >
          <AdminPanelSettingsIcon /> SSO Login
        </LoadingButton>
      </Grid>
    </Grid>
  );
}
