import Grid from "@mui/material/Grid";
import { Button } from "@mui/material";
import { Link } from "react-router-dom";
import { AppRoutes } from "../routes";

function LoginOption() {
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
        <h1 className="page-title">How would you like to connect?</h1>
      </Grid>

      <Grid item xs={12} style={{ marginTop: "6rem" }}>
        <Button
          variant="contained"
          component={Link}
          to={AppRoutes.TOKEN_LOGIN_ROUTE}
          data-testid="login-by-token-btn"
        >
          By Token
        </Button>
      </Grid>

      <Grid item xs={12}>
        <Button
          variant="contained"
          component={Link}
          to={AppRoutes.USERNAME_LOGIN_ROUTE}
          data-testid="login-by-cred-btn"
        >
          Username/Password/SSO
        </Button>
      </Grid>
    </Grid>
  );
}

export default LoginOption;
