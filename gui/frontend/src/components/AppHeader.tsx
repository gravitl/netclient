import { Button, Grid, Typography } from "@mui/material";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { AppRoutes } from "../routes";
import AppLogo from "./AppLogo";

export default function AppHeader() {
  const navigate = useNavigate();
  const location = useLocation();

  return (
    <Grid container>
      <Grid container item xs={12}>
        <Button
          variant="text"
          title="Back"
          onClick={() => navigate(AppRoutes.NETWORKS_ROUTE, { replace: true })}
          // disable if on first page
          disabled={location.key === "default"}
        >
          <Typography variant="h3">&lt;</Typography>
        </Button>
        <Link to={AppRoutes.HOME_ROUTE} title="Home">
          <AppLogo />
        </Link>
      </Grid>
    </Grid>
  );
}
