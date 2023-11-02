import Card from "@mui/material/Card";
import CardContent from "@mui/material/CardContent";
import Button from "@mui/material/Button";
import Typography from "@mui/material/Typography";
import { Link } from "react-router-dom";
import { AppRoutes } from "../../routes";

export default function NetworkCard() {
  return (
    <Button
      color={"inherit"}
      fullWidth
      style={{ textTransform: "none" }}
      component={Link}
      to={AppRoutes.NETWORKS_ROUTE}
    >
      <Card sx={{ minWidth: 275 }} variant="elevation">
        <CardContent>
          <Typography variant="h3" gutterBottom>
            Networks
          </Typography>
          <Typography variant="h6" component="div" color="text.secondary">
            View Network Details
          </Typography>
        </CardContent>
      </Card>
    </Button>
  );
}
