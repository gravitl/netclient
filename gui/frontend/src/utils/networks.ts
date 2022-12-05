import { AppRoutes } from "../routes";

export function getNetworkDetailsPageUrl(id: string) {
  return AppRoutes.NETWORK_DETAILS_ROUTE.split(":")?.[0] + `${id}`;
}
