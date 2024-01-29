import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, createRefetchContainer, RelayRefetchProp } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import LinearProgress from '@mui/material/LinearProgress';
import Paper from '@mui/material/Paper';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import { interval } from 'rxjs';
import { Delete } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { ConnectorWorks_data$data } from '@components/data/connectors/__generated__/ConnectorWorks_data.graphql';
import TaskStatus from '../../../../components/TaskStatus';
import { useFormatter } from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import Transition from '../../../../components/Transition';

const interval$ = interval(FIVE_SECONDS);

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
    position: 'relative',
  },
  number: {
    fontWeight: 600,
    fontSize: 18,
  },
  progress: {
    borderRadius: 5,
    height: 10,
  },
}));

export const connectorWorksWorkDeletionMutation = graphql`
  mutation ConnectorWorksWorkDeletionMutation($id: ID!) {
    workEdit(id: $id) {
      delete
    }
  }
`;

type WorkMessages = NonNullable<NonNullable<NonNullable<ConnectorWorks_data$data['works']>['edges']>[0]>['node']['errors'];

interface Options {
  count: number,
  filters: {
    mode: string,
    filters: [
      {
        key: string
        values: string[]
        operator: string
        mode: string
      },
    ],
    filterGroups: [],
  },
}

interface ConnectorWorksComponentProps {
  data: ConnectorWorks_data$data
  options: Options[]
  relay: RelayRefetchProp
}

const ConnectorWorksComponent: FunctionComponent<ConnectorWorksComponentProps> = ({ data, options, relay }) => {
  const works = data.works?.edges ?? [];
  const { t_i18n, nsdt } = useFormatter();
  const classes = useStyles();
  const [displayErrors, setDisplayErrors] = useState<boolean>(false);
  const [errors, setErrors] = useState<WorkMessages>([]);

  const handleOpenErrors = (errorsList: WorkMessages) => {
    if (!errorsList) return;
    setDisplayErrors(true);
    setErrors(errorsList);
  };

  const handleCloseErrors = () => {
    setDisplayErrors(false);
    setErrors([]);
  };

  // eslint-disable-next-line class-methods-use-this
  const handleDeleteWork = (workId: string) => {
    commitMutation({
      mutation: connectorWorksWorkDeletionMutation,
      variables: {
        id: workId,
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: () => {
        MESSAGING$.notifySuccess('The work has been deleted');
      },
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch(options);
    });
    return () => subscription.unsubscribe();
  }, []);

  return (
    <div>
      {works.length === 0 && (
        <Paper
          classes={{ root: classes.paper }}
          variant="outlined"
          style={{ marginBottom: 20 }}
        >
          <div
            style={{
              display: 'table',
              height: '100%',
              width: '100%',
            }}
          >
            <span
              style={{
                display: 'table-cell',
                verticalAlign: 'middle',
                textAlign: 'center',
              }}
            >
              {t_i18n('No work')}
            </span>
          </div>
        </Paper>
      )}
      {works.map((workEdge) => {
        const work = workEdge?.node;
        if (!work) return null;
        const { tracking } = work;
        return (
          <Paper
            key={work.id}
            classes={{ root: classes.paper }}
            variant="outlined"
            style={{ marginBottom: 20 }}
          >
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={5}>
                <Grid container={true} spacing={1}>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Name')}
                    </Typography>
                    <Typography>
                      {work.name}
                    </Typography>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Status')}
                    </Typography>
                    <TaskStatus status={work.status} label={t_i18n(work.status)} />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t_i18n('Work start time')}
                    </Typography>
                    {nsdt(work.received_time)}
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t_i18n('Work end time')}
                    </Typography>
                    {work.completed_time ? nsdt(work.completed_time) : '-'}
                  </Grid>
                </Grid>
              </Grid>
              <Grid item={true} xs={5}>
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Operations completed')}
                    </Typography>
                    <span className={classes.number}>
                      {work.status === 'wait'
                        ? '-'
                        : tracking?.import_processed_number ?? '-'}
                    </span>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Total number of operations')}
                    </Typography>
                    <span className={classes.number}>
                      {work.status === 'wait'
                        ? '-'
                        : tracking?.import_expected_number ?? '-'}
                    </span>
                  </Grid>
                  <Grid item={true} xs={12}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Progress')}
                    </Typography>
                    <LinearProgress
                      classes={{ root: classes.progress }}
                      variant="determinate"
                      value={
                        // eslint-disable-next-line no-nested-ternary
                        tracking && !!tracking.import_expected_number && !!tracking.import_processed_number
                          ? Math.round((tracking.import_processed_number / tracking.import_expected_number) * 100)
                          : 0
                      }
                    />
                  </Grid>
                </Grid>
              </Grid>
              <Button
                style={{ position: 'absolute', right: 10, top: 10 }}
                variant="contained"
                color="secondary"
                onClick={() => handleOpenErrors(work.errors ?? [])}
                size="small"
              >
                {work.errors?.length} {t_i18n('errors')}
              </Button>
              <Button
                variant="outlined"
                style={{ position: 'absolute', right: 10, bottom: 10 }}
                onClick={() => handleDeleteWork(work.id)}
                size="small"
              >
                <Delete fontSize="small" />
                &nbsp;&nbsp;{t_i18n('Delete')}
              </Button>
            </Grid>
          </Paper>
        );
      })}
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayErrors}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseErrors}
        fullScreen={true}
      >
        <DialogContent>
          <DialogContentText>
            <TableContainer component={Paper}>
              <Table aria-label="simple table">
                <TableHead>
                  <TableRow>
                    <TableCell>{t_i18n('Timestamp')}</TableCell>
                    <TableCell>{t_i18n('Message')}</TableCell>
                    <TableCell>{t_i18n('Source')}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {errors?.map((error) => error && (
                    <TableRow key={error.timestamp}>
                      <TableCell>{nsdt(error.timestamp)}</TableCell>
                      <TableCell>{error.message}</TableCell>
                      <TableCell>{error.source}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseErrors} color="primary">
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export const connectorWorksQuery = graphql`
  query ConnectorWorksQuery(
    $count: Int
    $orderBy: WorksOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ConnectorWorks_data
      @arguments(
        count: $count
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

const ConnectorWorks = createRefetchContainer(
  ConnectorWorksComponent,
  {
    data: graphql`
      fragment ConnectorWorks_data on Query
      @argumentDefinitions(
        count: { type: "Int" }
        orderBy: { type: "WorksOrdering", defaultValue: timestamp }
        orderMode: { type: "OrderingMode", defaultValue: desc }
        filters: { type: "FilterGroup" }
      ) {
        works(
          first: $count
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) {
          edges {
            node {
              id
              name
              user {
                name
              }
              timestamp
              status
              event_source_id
              received_time
              processed_time
              completed_time
              tracking {
                import_expected_number
                import_processed_number
              }
              messages {
                timestamp
                message
                sequence
                source
              }
              errors {
                timestamp
                message
                sequence
                source
              }
            }
          }
        }
      }
    `,
  },
  connectorWorksQuery,
);

export default ConnectorWorks;
