import React, { useState } from "react";
import { routes } from "./routes";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import "./App.css";
import { Grid, ThemeProvider } from "@mui/material";
import AppHeader from "./components/AppHeader";
import appTheme from "./theme";
import AppEventListener from "./components/AppEventListener";
import { NetworksContextProvider } from "./store/NetworkContext";

export default function App() {
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
                  <Routes>
                    {routes.map((route) => (
                      <Route
                        path={route.path}
                        element={route.element}
                        key={route.path}
                      />
                    ))}
                  </Routes>
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
