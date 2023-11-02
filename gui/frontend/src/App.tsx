import React, { useCallback, useEffect, useState } from "react";
import { routes } from "./routes";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import "./App.css";
import { Grid, ThemeProvider } from "@mui/material";
import AppHeader from "./components/AppHeader";
import appTheme from "./theme";
import AppEventListener from "./components/AppEventListener";
import { NetworksContextProvider } from "./store/NetworkContext";
import { GoGetStatus } from "../wailsjs/go/main/App";
import { notifyUser } from "./utils/messaging";
import LoopIcon from "@mui/icons-material/Loop";
import { LogFatal } from "../wailsjs/runtime/runtime";

export default function App() {
  const [isDaemonReachable, setIsDaemonReachable] = useState<boolean>(false);

  const checkDaemonConnectivity = useCallback(async () => {
    try {
      await GoGetStatus();
      setIsDaemonReachable(true);
    } catch (err) {
      console.error(err);
      setIsDaemonReachable(false);
      await notifyUser(
        "Cannot connect to daemon. Ensure that the netclient daemon is running then retry."
      );
      await LogFatal(
        "Cannot connect to daemon. Ensure that the netclient daemon is running then retry."
      );
    }
  }, []);

  useEffect(() => {
    checkDaemonConnectivity();
  }, [checkDaemonConnectivity]);

  return (
    <div id="app">
      <React.StrictMode>
        <ThemeProvider theme={appTheme}>
          <MemoryRouter>
            {/* app layout */}
            <Grid container>
              <Grid item xs={12}>
                <AppHeader />
              </Grid>

              <Grid item xs={12}>
                <NetworksContextProvider>
                  {isDaemonReachable ? (
                    <Routes>
                      {routes.map((route) => (
                        <Route
                          path={route.path}
                          element={route.element}
                          key={route.path}
                        />
                      ))}
                    </Routes>
                  ) : (
                    <div style={{ textAlign: "center" }}>
                      <LoopIcon fontSize="large" className="spinning" />
                    </div>
                  )}
                </NetworksContextProvider>
              </Grid>
            </Grid>

            {/* renderless component to handle events */}
            <AppEventListener />
          </MemoryRouter>
        </ThemeProvider>
      </React.StrictMode>
    </div>
  );
}
