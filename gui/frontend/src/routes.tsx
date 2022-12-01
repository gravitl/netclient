import Home from "./pages/Home";
import LoginOption from "./pages/LoginOption";
import TokenLogin from "./pages/TokenLogin";
import UsernameLogin from "./pages/UsernameLogin";
import Networks from "./pages/Networks";
import NetworkDetailsPage from "./pages/NetworkDetailsPage";
import LogsPage from "./pages/Logs";

export class AppRoutes {
  static HOME_ROUTE = '/'
  static LOGIN_OPTIONS_ROUTE = '/login-options'
  static TOKEN_LOGIN_ROUTE = '/login-token'
  static USERNAME_LOGIN_ROUTE = '/login-username'
  static NETWORKS_ROUTE = '/networks'
  static NETWORK_DETAILS_ROUTE = '/networks/:networkId'
  static LOGS_ROUTE = '/logs'
}

export const routes = [
  { path: AppRoutes.HOME_ROUTE, element: <Networks />, },
  { path: AppRoutes.LOGIN_OPTIONS_ROUTE, element: <LoginOption />, },
  { path: AppRoutes.TOKEN_LOGIN_ROUTE, element: <TokenLogin />, },
  { path: AppRoutes.USERNAME_LOGIN_ROUTE, element: <UsernameLogin />, },
  { path: AppRoutes.NETWORKS_ROUTE, element: <Networks />, },
  { path: AppRoutes.NETWORK_DETAILS_ROUTE, element: <NetworkDetailsPage />, },
  { path: AppRoutes.LOGS_ROUTE, element: <LogsPage />, },
  
  // fallback route
  { path: '*', element: <Networks />, },
]
