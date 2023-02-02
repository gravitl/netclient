import { useCallback, useEffect, useState } from "react";
import { FormControlLabel, Grid, Switch, TextField } from "@mui/material";
import LoopIcon from "@mui/icons-material/Loop";
import { notifyUser } from "../utils/messaging";
import { config } from "../../wailsjs/go/models";

export default function SettingsPage() {
  const [isLoadingDetails, setIsLoadingDetails] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [ncSettings, setNcSettings] = useState<Omit<
    config.Config,
    "convertValues"
  > | null>(null);
  const [ncSettingsFormData, setNcSettingsFormData] = useState<Omit<
    config.Config,
    "convertValues"
  > | null>(null);

  const loadSettings = useCallback(() => {}, []);

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
      await saveSettings();
      // update ncSettings with ncSettingsFormData
      // switch back to view mode
      setIsEditing(false);
    } catch (err) {
      await notifyUser(("Failed to save settings\n" + err) as string);
      console.error(err);
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
        <h1 className="page-title">Netclient Settings</h1>
        <h4 className="page-title">Host ID: {ncSettings?.id}</h4>
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
          <Grid container item style={{ width: "90vw" }} rowGap={2}>
            <Grid item xs={3}>
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
            <Grid item xs={3}>
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
            <Grid item xs={3}>
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
            <Grid item xs={3}>
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
            <Grid item xs={3}>
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
            <Grid item xs={3}>
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
            <Grid item xs={3}>
              <TextField
                disabled={!isEditing}
                name="defautlinterface"
                label="Default Interface"
                type="number"
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

            <Grid item xs={12}></Grid>

            <Grid item xs={3}>
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
            <Grid item xs={3}>
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
            <Grid item xs={3}>
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
          </Grid>
        )}
      </Grid>
    </Grid>
  );
}
