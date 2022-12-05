import { Checkbox, FormControlLabel, Grid, Typography } from "@mui/material";
import LoopIcon from "@mui/icons-material/Loop";
import { useCallback, useEffect, useState } from "react";

export default function LogsPage() {
  const [isLoadingLogs, setIsLoadingLogs] = useState(true);
  const [logs, setLogs] = useState<string[]>([]);
  const [shouldAutoScroll, setShouldAutoScroll] = useState(true);

  const pollLogs = useCallback(() => {
    // TODO: implement
    return setInterval(() => {
      setIsLoadingLogs(() => false);

      setLogs((logs) => [...logs, "2022-11-23 21:09: dummy logs..."]);
      if (shouldAutoScroll) {
        const logsArea = document.getElementById("logs-area");
        logsArea?.scrollTo({ top: logsArea.scrollHeight, behavior: "auto" });
      }
    }, 2000);
  }, [setIsLoadingLogs, setLogs, shouldAutoScroll]);

  useEffect(() => {
    const counterNo = pollLogs();

    return () => {
      clearInterval(counterNo);
    };
  }, [pollLogs]);

  return (
    <Grid
      container
      direction="column"
      alignItems="center"
      className="page"
      rowSpacing={2}
    >
      <Grid item xs={12}>
        <h1 className="page-title">Server Logs</h1>
      </Grid>

      <div style={{ textAlign: "right", width: "90vw" }}>
        <FormControlLabel
          label="Auto-scrolling"
          control={
            <Checkbox
              defaultChecked
              value={shouldAutoScroll}
              onSelect={() => {
                setShouldAutoScroll(!shouldAutoScroll);
              }}
            />
          }
        />
      </div>
      <Grid
        item
        xs={12}
        justifyContent="center"
        id="logs-area"
        style={{
          minHeight: "5rem",
          maxHeight: "70vh",
          width: "90vw",
          overflow: "auto",
        }}
      >
        {isLoadingLogs ? (
          <div style={{ textAlign: "center" }}>
            <LoopIcon fontSize="large" className="spinning" />
          </div>
        ) : (
          <div>
            {logs.map((log) => (
              <Typography key={new Date().getTime()}>{log}</Typography>
            ))}
          </div>
        )}
      </Grid>
    </Grid>
  );
}
