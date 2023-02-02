import { useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom"
import { AppEvents } from "../constants";
import { AppRoutes } from "../routes";

const wailsRuntime = (window as any).runtime

export default function AppEventListener() {
  const navigate = useNavigate();

  // define event handlers
  
  const openNetworksPage = useCallback(() => {
    navigate(AppRoutes.NETWORKS_ROUTE)
  }, [navigate])

  const openServerLogsPage = useCallback(() => {
    navigate(AppRoutes.LOGS_ROUTE)
  }, [navigate])

  const openSettingsPage = useCallback(() => {
    navigate(AppRoutes.SETTINGS_ROUTE)
  }, [navigate])

  // register event handlers
  useEffect(() => {
    wailsRuntime?.EventsOn(AppEvents.EV_OPEN_NETWORKS_PAGE, openNetworksPage)
    wailsRuntime?.EventsOn(AppEvents.EV_OPEN_LOGS_PAGE, openServerLogsPage)
    wailsRuntime?.EventsOn(AppEvents.EV_OPEN_SETTINGS_PAGE, openSettingsPage)
    
    // cleanup
    return () => {
      wailsRuntime?.EventsOff(AppEvents.EV_OPEN_NETWORKS_PAGE)
      wailsRuntime?.EventsOff(AppEvents.EV_OPEN_LOGS_PAGE)
      wailsRuntime?.EventsOff(AppEvents.EV_OPEN_SETTINGS_PAGE)
    }
  })

  // renderless
  return (<></>)
}
