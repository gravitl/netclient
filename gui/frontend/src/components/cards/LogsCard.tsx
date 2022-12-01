import * as React from 'react';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';

export default function LogsCard() {
  return (
    <Button color={'inherit'} fullWidth style={{ textTransform: 'none' }}>
      <Card sx={{ minWidth: 275 }} variant="elevation">
        <CardContent>
          <Typography variant="h3" gutterBottom>
            Logs
          </Typography>
          <Typography variant="h6" component="div" color="text.secondary">
            View Network Logs
          </Typography>
        </CardContent>
      </Card>
    </Button>
  );
}
