import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import LinearProgress from '@mui/material/LinearProgress';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import TaskStatus from '../../../../components/TaskStatus';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  paper: {
    margin: '10px 0 20px 0',
    padding: '10px',
    borderRadius: 4,
    position: 'relative',
  },
  number: {
    fontWeight: 600,
    fontSize: 18,
  },
  progress: {
    borderRadius: 4,
    height: 10,
  },
}));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const WorkDetail = ({ work }: { work: any }) => {
  const { t_i18n, nsdt } = useFormatter();
  const classes = useStyles();

  return <Paper key={work.id} classes={{ root: classes.paper }} variant="outlined">
    <Grid container={true} spacing={3}>
      <Grid item xs={6}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Work start time')}
        </Typography>
        {nsdt(work.received_time)}
      </Grid>
      <Grid item xs={6}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Work end time')}
        </Typography>
        {work.completed_time ? nsdt(work.completed_time) : '-'}
      </Grid>
      <Grid item xs={6}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Operations completed')}
        </Typography>
        <span className={classes.number}>
          {work.status === 'wait'
            ? '-'
            : work.tracking?.import_processed_number ?? '-'}
        </span>
      </Grid>
      <Grid item xs={6}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Total number of operations')}
        </Typography>
        <span className={classes.number}>
          {work.tracking?.import_expected_number ?? '-'}
        </span>
      </Grid>
      <Grid item xs={6}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Progress')}
        </Typography>
        <LinearProgress
          classes={{ root: classes.progress }}
          variant="determinate"
          value={
              work.tracking && !!work.tracking.import_expected_number && !!work.tracking.import_processed_number
                ? Math.round((work.tracking.import_processed_number / work.tracking.import_expected_number) * 100)
                : 0}
        />
      </Grid>
      <Grid item xs={6}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Status')}
        </Typography>
        <TaskStatus status={work.status} label={t_i18n(work.status)} />
      </Grid>
    </Grid>
  </Paper>;
};

export default WorkDetail;
