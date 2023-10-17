import Grid from "@mui/material/Grid";

function Home() {
  const test = () => {
    console.log("test");
  };

  return (
    <Grid
      container
      spacing={2}
      direction="column"
      alignItems="center"
      maxWidth="100vw"
    >
      <Grid item>
        <h1 className="App-title">Where would you like to go next?</h1>
      </Grid>
      <Grid item>
        <button className="App-button" onClick={test}>
          Networks
        </button>
      </Grid>
      <Grid item>
        <button className="App-button" onClick={test}>
          Logs
        </button>
      </Grid>

      <Grid>
        <Grid item>
          <button className="App-button" onClick={test}>
            Uninstall
          </button>
        </Grid>
      </Grid>
    </Grid>
  );
}

export default Home;
