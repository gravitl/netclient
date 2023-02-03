import { useCallback, useEffect, useState } from "react";
import {
  Button,
  FormControlLabel,
  Grid,
  Switch,
  TextField,
} from "@mui/material";
import LoopIcon from "@mui/icons-material/Loop";
import { notifyUser } from "../utils/messaging";
import { config } from "../../wailsjs/go/models";
import { LoadingButton } from "@mui/lab";
import { GoGetNetclientConfig } from "../../wailsjs/go/main/App";

export default function SettingsPage() {
  const [isLoadingDetails, setIsLoadingDetails] = useState(true);
  const [isEditing, setIsEditing] = useState(false);
  const [isSavingSettings, setIsSavingSettings] = useState(false);
  const [ncSettings, setNcSettings] = useState<Omit<
    config.NcConfig,
    "convertValues"
  > | null>(null);
  const [ncSettingsFormData, setNcSettingsFormData] = useState<Omit<
    config.NcConfig,
    "convertValues"
  > | null>(null);

  const loadSettings = useCallback(async () => {
    try {
      setIsLoadingDetails(true);
      const config = await GoGetNetclientConfig();
      setNcSettings(config);
    } catch (err) {
      await notifyUser(("Failed to load settings\n" + err) as string);
      console.error(err);
    } finally {
      setIsLoadingDetails(false);
    }
  }, [setNcSettings]);

  const saveSettings = useCallback(async () => {}, []);

  const onEditSettings = useCallback(() => {
    // make a deep copy of current settings
    setNcSettingsFormData(JSON.parse(JSON.stringify(ncSettings)));
    setIsEditing(true);
  }, [setIsEditing]);

  const onCancelEdit = useCallback(() => {
    setIsEditing(false);
  }, [setIsEditing]);

  const onSaveSettings = useCallback(async () => {
    try {
      // validate
      // make call to save settings
      setIsSavingSettings(true);
      await saveSettings();
      // update ncSettings with ncSettingsFormData
      // switch back to view mode
      setIsEditing(false);
    } catch (err) {
      await notifyUser(("Failed to save settings\n" + err) as string);
      console.error(err);
    } finally {
      setIsSavingSettings(false);
    }
  }, [saveSettings, setIsEditing]);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  return (
    <Grid
      container
      direction="column"
      alignItems="center"
      className="page"
      rowSpacing={2}
    >
      <Grid item xs={12}>
        <h1 className="page-title" style={{ marginBottom: "0px" }}>
          Netclient Settings
        </h1>
        <h4 className="page-title" style={{ marginTop: "0px" }}>
          Host ID: {ncSettings?.id}
        </h4>
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
          <Grid
            container
            item
            style={{
              width: "90vw",
              height: "70vh",
              overflow: "auto",
              paddingTop: "1rem",
              paddingLeft: "0.5rem",
            }}
            rowGap={2}
          >
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="name"
                label="Name"
                required
                value={isEditing ? ncSettingsFormData?.name : ncSettings?.name}
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    name: ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="version"
                label="Version"
                value={
                  isEditing ? ncSettingsFormData?.version : ncSettings?.version
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    version: ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="mtu"
                label="MTU"
                value={isEditing ? ncSettingsFormData?.mtu : ncSettings?.mtu}
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    mtu: +ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="os"
                label="OS"
                value={isEditing ? ncSettingsFormData?.os : ncSettings?.os}
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    os: ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="hostpass"
                label="Host Password"
                value={
                  isEditing
                    ? ncSettingsFormData?.hostpass
                    : ncSettings?.hostpass
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    hostpass: ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="interface"
                label="Interface"
                value={
                  isEditing
                    ? ncSettingsFormData?.interface
                    : ncSettings?.interface
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    interface: ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="firewallinuse"
                label="Firewall"
                value={
                  isEditing
                    ? ncSettingsFormData?.firewallinuse
                    : ncSettings?.firewallinuse
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    firewallinuse: ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="public_listen_port"
                label="Public Listen Port"
                type="number"
                value={
                  isEditing
                    ? ncSettingsFormData?.public_listen_port
                    : ncSettings?.public_listen_port
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    public_listen_port: +ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="proxy_listen_port"
                label="Proxy listen Port"
                value={
                  isEditing
                    ? ncSettingsFormData?.proxy_listen_port
                    : ncSettings?.proxy_listen_port
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    proxy_listen_port: +ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="publickey"
                label="Public Key"
                value={
                  isEditing
                    ? ncSettingsFormData?.publickey
                    : ncSettings?.publickey
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    // publickey: ev.target.value, // how to convert
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="trafickeypublic"
                label="Public Traffic Key"
                value={
                  isEditing
                    ? ncSettingsFormData?.traffickeypublic
                    : ncSettings?.traffickeypublic
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    // traffickeypublic: ev.target.value, // how to convert
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="internetgateway"
                label="Internet Gateway"
                value={
                  isEditing
                    ? ncSettingsFormData?.internetgateway
                    : `${String(ncSettings?.internetgateway.IP)}:${String(
                        ncSettings?.internetgateway.Port
                      )}` // how to get
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    internetgateway: ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="endpointip"
                label="Endpoint IP"
                value={
                  isEditing
                    ? ncSettingsFormData?.endpointip
                    : ncSettings?.endpointip
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    endpointip: ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="macaddress"
                label="MAC Address"
                value={
                  isEditing
                    ? ncSettingsFormData?.macaddressstr
                    : `${String(ncSettings?.macaddressstr)}`
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    macaddress: ev.target.value,
                  })
                }
              />
            </Grid>

            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="verbosity"
                label="Verbosity"
                type="number"
                value={
                  isEditing
                    ? ncSettingsFormData?.verbosity
                    : ncSettings?.verbosity
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    verbosity: +ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="mtu"
                label="MTU"
                type="number"
                value={isEditing ? ncSettingsFormData?.mtu : ncSettings?.mtu}
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    mtu: +ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="endpointip"
                label="Endpoint IP"
                type="number"
                value={
                  isEditing
                    ? ncSettingsFormData?.endpointip
                    : ncSettings?.endpointip
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    endpointip: ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="listenport"
                label="Listen Port"
                type="number"
                value={
                  isEditing
                    ? ncSettingsFormData?.listenport
                    : ncSettings?.listenport
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    listenport: +ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <TextField
                disabled={!isEditing}
                name="proxy_listen_port"
                label="Proxy Listen Port"
                type="number"
                value={
                  isEditing
                    ? ncSettingsFormData?.proxy_listen_port
                    : ncSettings?.proxy_listen_port
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    proxy_listen_port: +ev.target.value,
                  })
                }
              />
            </Grid>

            <Grid item xs={12}></Grid>

            <Grid item xs={3}>
              <TextField
                disabled={!isEditing}
                name="defautlinterface"
                label="Default Interface"
                value={
                  isEditing
                    ? ncSettingsFormData?.defautlinterface
                    : ncSettings?.defautlinterface
                }
                onChange={(ev) =>
                  setNcSettingsFormData({
                    ...ncSettingsFormData!,
                    defautlinterface: ev.target.value,
                  })
                }
              />
            </Grid>
            <Grid item xs={8} md={9}>
              Interfaces:{" "}
              {ncSettings?.interfaces
                .map((iface) => `${String(iface.address.IP)}`)
                .join(", ")}
            </Grid>

            <Grid item xs={12}></Grid>

            <Grid item xs={4} md={3}>
              <FormControlLabel
                disabled={!isEditing}
                label="Relay"
                control={
                  <Switch
                    checked={
                      isEditing
                        ? ncSettingsFormData?.isrelay
                        : ncSettings?.isrelay
                    }
                    onChange={(ev) =>
                      setNcSettingsFormData({
                        ...ncSettingsFormData!,
                        isrelay: ev.target.checked,
                      })
                    }
                  />
                }
              />
            </Grid>
            <Grid item xs={8} md={9}>
              Relaying (hosts):{" "}
              {ncSettings?.relay_hosts.map((hostId) => hostId).join(", ")}
            </Grid>

            <Grid item xs={12}></Grid>

            <Grid item xs={4} md={3}>
              <FormControlLabel
                disabled={!isEditing}
                label="Default Host"
                control={
                  <Switch
                    checked={
                      isEditing
                        ? ncSettingsFormData?.isdefault
                        : ncSettings?.isdefault
                    }
                    onChange={(ev) =>
                      setNcSettingsFormData({
                        ...ncSettingsFormData!,
                        isdefault: ev.target.checked,
                      })
                    }
                  />
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <FormControlLabel
                disabled={!isEditing}
                label="Proxy Enabled"
                control={
                  <Switch
                    checked={
                      isEditing
                        ? ncSettingsFormData?.proxy_enabled
                        : ncSettings?.proxy_enabled
                    }
                    onChange={(ev) =>
                      setNcSettingsFormData({
                        ...ncSettingsFormData!,
                        proxy_enabled: ev.target.checked,
                      })
                    }
                  />
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <FormControlLabel
                disabled={!isEditing}
                label="Static Endpoint IP"
                control={
                  <Switch
                    checked={
                      isEditing
                        ? ncSettingsFormData?.isstatic
                        : ncSettings?.isstatic
                    }
                    onChange={(ev) =>
                      setNcSettingsFormData({
                        ...ncSettingsFormData!,
                        isstatic: ev.target.checked,
                      })
                    }
                  />
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <FormControlLabel
                disabled={!isEditing}
                label="IP Forwarding"
                control={
                  <Switch
                    checked={
                      isEditing
                        ? ncSettingsFormData?.ipforwarding
                        : ncSettings?.ipforwarding
                    }
                    onChange={(ev) =>
                      setNcSettingsFormData({
                        ...ncSettingsFormData!,
                        ipforwarding: ev.target.checked,
                      })
                    }
                  />
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <FormControlLabel
                disabled={!isEditing}
                label="Daemon installed"
                control={
                  <Switch
                    checked={
                      isEditing
                        ? ncSettingsFormData?.daemoninstalled
                        : ncSettings?.daemoninstalled
                    }
                    onChange={(ev) =>
                      setNcSettingsFormData({
                        ...ncSettingsFormData!,
                        daemoninstalled: ev.target.checked,
                      })
                    }
                  />
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <FormControlLabel
                disabled={!isEditing}
                label="Debug"
                control={
                  <Switch
                    checked={
                      isEditing ? ncSettingsFormData?.debug : ncSettings?.debug
                    }
                    onChange={(ev) =>
                      setNcSettingsFormData({
                        ...ncSettingsFormData!,
                        debug: ev.target.checked,
                      })
                    }
                  />
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <FormControlLabel
                disabled={!isEditing}
                label="Relayed"
                control={
                  <Switch
                    checked={
                      isEditing
                        ? ncSettingsFormData?.isrelayed
                        : ncSettings?.isrelayed
                    }
                    onChange={(ev) =>
                      setNcSettingsFormData({
                        ...ncSettingsFormData!,
                        isrelayed: ev.target.checked,
                      })
                    }
                  />
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <FormControlLabel
                disabled={!isEditing}
                label="Is Docker host"
                control={
                  <Switch
                    checked={
                      isEditing
                        ? ncSettingsFormData?.isdocker
                        : ncSettings?.isdocker
                    }
                    onChange={(ev) =>
                      setNcSettingsFormData({
                        ...ncSettingsFormData!,
                        isdocker: ev.target.checked,
                      })
                    }
                  />
                }
              />
            </Grid>
            <Grid item xs={4} md={3}>
              <FormControlLabel
                disabled={!isEditing}
                label="Is Kubernetes Host"
                control={
                  <Switch
                    checked={
                      isEditing ? ncSettingsFormData?.isk8s : ncSettings?.isk8s
                    }
                    onChange={(ev) =>
                      setNcSettingsFormData({
                        ...ncSettingsFormData!,
                        isk8s: ev.target.checked,
                      })
                    }
                  />
                }
              />
            </Grid>

            {isEditing && (
              <Grid item xs={12} textAlign="right">
                <Button variant="outlined" onClick={onCancelEdit}>
                  Cancel
                </Button>
                <LoadingButton
                  variant="contained"
                  loading={isSavingSettings}
                  onClick={() => onSaveSettings()}
                >
                  Save
                </LoadingButton>
              </Grid>
            )}
          </Grid>
        )}
      </Grid>
    </Grid>
  );
}
