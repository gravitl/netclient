import Grid from "@mui/material/Grid";
import { TextField, Typography } from "@mui/material";
import { useCallback, useState } from "react";
import { useNavigate } from "react-router-dom";
import { GoJoinNetworkByToken, GoParseAccessToken } from "../../wailsjs/go/main/App";
import { NetworksContextDispatcherProps, useNetworksContext } from "../store/NetworkContext";
import { getNetworkDetailsPageUrl } from "../utils/networks";
import { LoadingButton } from "@mui/lab";
import { notifyUser } from "../utils/messaging";

function TokenLogin() {
  const [isFormValid, setIsFormValid] = useState(true);
  const [token, setToken] = useState("");
  const [isConnecting, setIsConnecting] = useState(false);
  const navigate = useNavigate();
  const { networksDispatch } = useNetworksContext();

  const checkIsFormValid = useCallback(() => {
    // reset
    setIsFormValid(true)

    // perform validation
    if (token.length < 1) {
      setIsFormValid(false)
      return false
    }

    return true
  }, [setIsFormValid, token])

  const onConnectClick = useCallback(async () => {
    // validate
    if (!checkIsFormValid()) return

    try {
      setIsConnecting(true)
      await GoJoinNetworkByToken(token)

      // store n/w details in ctx
      const data: NetworksContextDispatcherProps = {
        action: 'refresh-networks',
      }
      networksDispatch(data)

      const { network: networkName } = await GoParseAccessToken(token)
      navigate(getNetworkDetailsPageUrl(networkName));
    } catch (err) {
      await notifyUser("Failed to connect to network\n" + err as string);
      console.error(err);
    } finally {
      setIsConnecting(false)
    }
  }, [navigate, checkIsFormValid, setIsConnecting, networksDispatch]);

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
        <h1 className="page-title">Connect with Token</h1>
      </Grid>

      <Grid item xs={12} style={{ marginTop: "6rem" }}>
        <TextField
          label="Token"
          placeholder="Enter network token"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          error={!isFormValid}
          helperText={isFormValid ? "" : "Token cannot be empty"}
          inputProps={{ 'data-testid': 'token-inp' }}
        />
        <br />
        <Typography variant="caption">
          *Token can be acquired from Netmaker server
        </Typography>
      </Grid>

      <Grid item xs={12}>
        <LoadingButton
          loading={isConnecting}
          variant="contained"
          onClick={onConnectClick}
          data-testid="connect-btn"
        >
          Connect
        </LoadingButton>
      </Grid>
    </Grid>
  );
}

export default TokenLogin;
