import { createTheme, PaletteMode } from "@mui/material";
import { teal } from "@mui/material/colors";

const DEFAULT_APP_THEME: PaletteMode = "dark";

const appTheme = createTheme({
  palette: {
    mode: DEFAULT_APP_THEME,
    primary: teal,
  },
});

export default appTheme;
