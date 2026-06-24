import React, { PropsWithChildren } from 'react';
import type { Theme } from '../../../../../../components/Theme';
import makeStyles from '@mui/styles/makeStyles';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/Grid2';
import { Typography } from '@mui/material';

const useStyles = makeStyles<Theme>((theme) => ({
  innerTitle: {
    paddingLeft: theme.spacing(2),
    paddingTop: theme.spacing(1),
    textTransform: 'uppercase',
    fontSize: 12,
    fontWeight: 500,
    color: theme.palette.text?.secondary,
  },
  summaryContent: {
    height: '100%',
    overflow: 'hidden',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
  },
  children: {
    flex: 1,
    display: 'flex',
    overflowY: 'auto',
  },
}));

interface SummaryCardProps {
  title: string;
  size: number;
  height?: number;
  padding?: number;
}

const SummaryCard = ({ title, size, height = 160, padding = 16, children }: PropsWithChildren<SummaryCardProps>) => {
  const classes = useStyles();
  return (
    <Grid size={size}>
      {height > 100 ? <Typography variant="h4">{title}</Typography> : null}
      <Card
        style={{ height: height, display: 'flex', flexDirection: 'column' }}
        variant="outlined"
      >
        {height <= 100 ? <div className={classes.innerTitle}>{title}</div> : null}
        <CardContent className={classes.summaryContent} sx={{ padding: `${padding}px !important` }}>
          <div className={classes.children}>
            {children}
          </div>
        </CardContent>
      </Card>
    </Grid>
  );
};
export default SummaryCard;
