import Home from "./pages/Home";
import LoginOption from "./pages/LoginOption";
import TokenLogin from "./pages/TokenLogin";
import UsernameLogin from "./pages/UsernameLogin";
import Networks from "./pages/Networks";
import NetworkDetailsPage from "./pages/NetworkDetailsPage";
import LogsPage from "./pages/Logs";
import SettingsPage from "./pages/SettingsPage";

export class AppRoutes {
  static HOME_ROUTE = "/";
  static LOGIN_OPTIONS_ROUTE = "/login-options";
  static TOKEN_LOGIN_ROUTE = "/login-token";
  static USERNAME_LOGIN_ROUTE = "/login-username";
  static NETWORKS_ROUTE = "/networks";
  static NETWORK_DETAILS_ROUTE = "/networks/:networkName";
  static LOGS_ROUTE = "/logs";
  static SETTINGS_ROUTE = "/settings";
}

export const routes = [
  { path: AppRoutes.HOME_ROUTE, element: <Networks /> },
  { path: AppRoutes.LOGIN_OPTIONS_ROUTE, element: <LoginOption /> },
  { path: AppRoutes.TOKEN_LOGIN_ROUTE, element: <TokenLogin /> },
  { path: AppRoutes.USERNAME_LOGIN_ROUTE, element: <UsernameLogin /> },
  { path: AppRoutes.NETWORKS_ROUTE, element: <Networks /> },
  { path: AppRoutes.NETWORK_DETAILS_ROUTE, element: <NetworkDetailsPage /> },
  { path: AppRoutes.LOGS_ROUTE, element: <LogsPage /> },
  { path: AppRoutes.SETTINGS_ROUTE, element: <SettingsPage /> },

  // fallback route
  { path: "*", element: <Networks /> },
];
