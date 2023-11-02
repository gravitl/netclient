import Grid from "@mui/material/Grid";
import {
  FormControl,
  FormControlLabel,
  FormLabel,
  Radio,
  RadioGroup,
  TextField,
  Typography,
} from "@mui/material";
import { useCallback, useState } from "react";
import { useNavigate } from "react-router-dom";
import { GoRegisterWithEnrollmentKey } from "../../wailsjs/go/main/App";
import {
  NetworksContextDispatcherProps,
  useNetworksContext,
} from "../store/NetworkContext";
import { getNetworkDetailsPageUrl } from "../utils/networks";
import { LoadingButton } from "@mui/lab";
import { notifyUser } from "../utils/messaging";
import { AppRoutes } from "../routes";

function TokenLogin() {
  const [isFormValid, setIsFormValid] = useState(true);
  const [token, setToken] = useState("");
  const [enrollmentKey, setEnrollmentKey] = useState("");
  const [isConnecting, setIsConnecting] = useState(false);
  const [type, setType] = useState<"access-key" | "enrollment-key">(
    "enrollment-key",
  );
  const navigate = useNavigate();
  const { networksDispatch } = useNetworksContext();

  const checkIsFormValid = useCallback(() => {
    // reset
    setIsFormValid(true);

    // perform validation
    if (
      (type === "access-key" && token.length < 1) ||
      (type === "enrollment-key" && enrollmentKey.length < 1)
    ) {
      setIsFormValid(false);
      return false;
    }

    return true;
  }, [setIsFormValid, token, type, enrollmentKey]);

  const onConnectClick = useCallback(async () => {
    // validate
    if (!checkIsFormValid()) return;

    try {
      setIsConnecting(true);

      switch (type) {
        case "enrollment-key":
          await GoRegisterWithEnrollmentKey(enrollmentKey);
          // wait a while for the server to register host to network. makes the UX better
          await new Promise((resolve) => setTimeout(resolve, 3000));
          break;
      }

      // store n/w details in ctx
      const data: NetworksContextDispatcherProps = {
        action: "refresh-networks",
      };
      networksDispatch(data);

      // const { network: networkName } = await GoParseAccessToken(token)
      // navigate(getNetworkDetailsPageUrl(networkName));
      navigate(AppRoutes.NETWORKS_ROUTE);
    } catch (err) {
      await notifyUser(("Failed to connect to network\n" + err) as string);
      console.error(err);
    } finally {
      setIsConnecting(false);
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

      {/* <Grid item xs={12}>
        <FormControl>
          <FormLabel>Token type</FormLabel>
          <RadioGroup
            onChange={(ev, type) => setType(type as any)}
            defaultValue="access-key"
          >
            <FormControlLabel
              label="Access Key"
              value="access-key"
              control={<Radio />}
            />
            <FormControlLabel
              value="enrollment-key"
              control={<Radio />}
              label="Enrollment Key"
            />
          </RadioGroup>
        </FormControl>
      </Grid> */}

      {type === "access-key" && (
        <Grid item xs={12}>
          <TextField
            key="token-inp"
            label="Token"
            placeholder="Enter network token"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            error={!isFormValid}
            helperText={isFormValid ? "" : "Token cannot be empty"}
            inputProps={{ "data-testid": "token-inp" }}
          />
          <br />
          <Typography variant="caption">
            *Token can be acquired from Netmaker server
          </Typography>
        </Grid>
      )}
      {type === "enrollment-key" && (
        <Grid item xs={12}>
          <TextField
            key="enrollment-key-inp"
            label="Enrollment Key"
            placeholder="Enter enrollment key"
            value={enrollmentKey}
            onChange={(e) => setEnrollmentKey(e.target.value)}
            error={!isFormValid}
            helperText={isFormValid ? "" : "Enrollment key cannot be empty"}
            inputProps={{ "data-testid": "enrollment-key-inp" }}
          />
          <br />
          <Typography variant="caption">
            *Enrollment key can be acquired from Netmaker server
          </Typography>
        </Grid>
      )}

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
