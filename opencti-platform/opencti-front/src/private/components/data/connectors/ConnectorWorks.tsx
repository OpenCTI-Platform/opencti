import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, createRefetchContainer, RelayRefetchProp } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import LinearProgress from '@mui/material/LinearProgress';
import Paper from '@mui/material/Paper';
import Button from '@mui/material/Button';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Tooltip from '@mui/material/Tooltip';
import { interval } from 'rxjs';
import { Delete } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@components/common/drawer/Drawer';
import Alert from '@mui/material/Alert';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import parseWorkErrors, { ParsedWorkMessage } from '@components/data/connectors/parseWorkErrors';
import { ConnectorWorksQuery$variables } from './__generated__/ConnectorWorksQuery.graphql';
import { ConnectorWorks_data$data } from './__generated__/ConnectorWorks_data.graphql';
import TaskStatus from '../../../../components/TaskStatus';
import { useFormatter } from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { MESSAGING$ } from '../../../../relay/environment';
import { MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import ConnectorWorksErrorLine from './ConnectorWorksErrorLine';

const interval$ = interval(FIVE_SECONDS);

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  paper: {
    margin: '10px 0 20px 0',
    padding: '15px',
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
  bottomTypo: {
    marginTop: 20,
  },
  errorButton: {
    position: 'absolute',
    right: 10,
    top: 10,
  },
  deleteButton: {
    position: 'absolute',
    right: 10,
    bottom: 10,
  },
}));

export const connectorWorksWorkDeletionMutation = graphql`
  mutation ConnectorWorksWorkDeletionMutation($id: ID!) {
    workEdit(id: $id) {
      delete
    }
  }
`;

export type WorkMessages = NonNullable<NonNullable<NonNullable<ConnectorWorks_data$data['works']>['edges']>[0]>['node']['errors'];

interface ConnectorWorksComponentProps {
  data: ConnectorWorks_data$data
  options: ConnectorWorksQuery$variables[]
  relay: RelayRefetchProp
  inProgress?: boolean
}

const ConnectorWorksComponent: FunctionComponent<ConnectorWorksComponentProps> = ({
  data,
  options,
  relay,
  inProgress,
}) => {
  const works = data.works?.edges ?? [];
  const { t_i18n, nsdt } = useFormatter();
  const classes = useStyles();
  const [commit] = useApiMutation(connectorWorksWorkDeletionMutation);
  const [openDrawerErrors, setOpenDrawerErrors] = useState<boolean>(false);
  const [errors, setErrors] = useState<ParsedWorkMessage[]>([]);
  const [criticals, setCriticals] = useState<ParsedWorkMessage[]>([]);
  const [warnings, setWarnings] = useState<ParsedWorkMessage[]>([]);
  const [tabValue, setTabValue] = useState<string>('Critical');

  const handleOpenDrawerErrors = async (errorsList: WorkMessages) => {
    setOpenDrawerErrors(true);
    const parsedList = await parseWorkErrors(errorsList);
    setErrors(parsedList);
    const criticalErrors = parsedList.filter((error) => error.level === 'Critical');
    setCriticals(criticalErrors);
    const warningErrors = parsedList.filter((error) => error.level === 'Warning');
    setWarnings(warningErrors);
  };

  const handleCloseDrawerErrors = () => {
    setOpenDrawerErrors(false);
    setErrors([]);
  };

  const handleDeleteWork = (workId: string) => {
    commit({
      variables: {
        id: workId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The work has been deleted');
      },
    });
  };

  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch(options);
    });
    return () => subscription.unsubscribe();
  }, []);

  return (
    <>
      <Typography variant="h4" gutterBottom={true}>
        {inProgress ? t_i18n('In progress works') : t_i18n('Completed works')}{` (${works.length})`}
      </Typography>
      <div>
        {works.length === 0 && (
        <Paper
          classes={{ root: classes.paper }}
          variant="outlined"
        >
          <Typography align='center'>
            {t_i18n('No work')}
          </Typography>
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
            >
              <Grid container={true} spacing={3}>
                <Grid item xs={7}>
                  <Grid container={true} spacing={1}>
                    <Grid item xs={8}>
                      <Typography variant="h3" gutterBottom={true}>
                        {t_i18n('Name')}
                      </Typography>
                      <Tooltip title={work.name}>
                        <Typography sx={{ overflowX: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'noWrap' }}>
                          {work.name}
                        </Typography>
                      </Tooltip>
                    </Grid>
                    <Grid item xs={4}>
                      <Typography variant="h3" gutterBottom={true}>
                        {t_i18n('Status')}
                      </Typography>
                      <TaskStatus status={work.status} label={t_i18n(work.status)} />
                    </Grid>
                    <Grid item xs={8}>
                      <Typography
                        variant="h3"
                        gutterBottom={true}
                        classes={{ root: classes.bottomTypo }}
                      >
                        {t_i18n('Work start time')}
                      </Typography>
                      {nsdt(work.received_time)}
                    </Grid>
                    <Grid item xs={4}>
                      <Typography
                        variant="h3"
                        gutterBottom={true}
                        classes={{ root: classes.bottomTypo }}
                      >
                        {t_i18n('Work end time')}
                      </Typography>
                      {work.completed_time ? nsdt(work.completed_time) : '-'}
                    </Grid>
                  </Grid>
                </Grid>
                <Grid item xs={4}>
                  <Grid container={true} spacing={3}>
                    <Grid item xs={6}>
                      <Typography variant="h3" gutterBottom={true}>
                        {t_i18n('Operations completed')}
                      </Typography>
                      <span className={classes.number}>
                        {work.status === 'wait'
                          ? '-'
                          : tracking?.import_processed_number ?? '-'}
                      </span>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="h3" gutterBottom={true}>
                        {t_i18n('Total number of operations')}
                      </Typography>
                      <span className={classes.number}>
                        {tracking?.import_expected_number ?? '-'}
                      </span>
                    </Grid>
                    <Grid item xs={11}>
                      <Typography variant="h3" gutterBottom={true}>
                        {t_i18n('Progress')}
                      </Typography>
                      <LinearProgress
                        classes={{ root: classes.progress }}
                        variant="determinate"
                        value={
                        tracking && !!tracking.import_expected_number && !!tracking.import_processed_number
                          ? Math.round((tracking.import_processed_number / tracking.import_expected_number) * 100)
                          : 0
                      }
                      />
                    </Grid>
                  </Grid>
                </Grid>
                <Button
                  classes={{ root: classes.errorButton }}
                  variant="outlined"
                  color={(work.errors ?? []).length === 0 ? 'success' : 'warning'}
                  onClick={() => handleOpenDrawerErrors(work.errors ?? [])}
                  size="small"
                >
                  {work.errors?.length} {t_i18n('errors')}
                </Button>
                <Security needs={[MODULES_MODMANAGE]}>
                  <Button
                    variant="outlined"
                    classes={{ root: classes.deleteButton }}
                    onClick={() => handleDeleteWork(work.id)}
                    size="small"
                    startIcon={<Delete/>}
                  >
                    {t_i18n('Delete')}
                  </Button>
                </Security>
              </Grid>
            </Paper>
          );
        })}
        <Drawer
          title={t_i18n('Errors')}
          open={openDrawerErrors}
          onClose={handleCloseDrawerErrors}
        >
          <>
            <Alert severity="info">{t_i18n('This page lists only the first 100 errors returned by the connector')}</Alert>
            <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)}>
              <Tab label={`${t_i18n('Critical')} (${criticals.length})`} value="Critical" />
              <Tab label={`${t_i18n('Warning')} (${warnings.length})`} value="Warning" />
              <Tab label={`${t_i18n('All')} (${errors.length})`} value="All" />
            </Tabs>
            <TableContainer component={Paper}>
              <Table aria-label="errors table">
                <TableHead>
                  <TableRow>
                    <TableCell>{t_i18n('Timestamp')}</TableCell>
                    <TableCell>{t_i18n('Code')}</TableCell>
                    <TableCell>{t_i18n('Message')}</TableCell>
                    <TableCell>{t_i18n('Source')}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {tabValue === 'Critical' && criticals.map((error, i) => (
                    <ConnectorWorksErrorLine key={error.rawError?.timestamp ?? i} error={error} />
                  ))}
                  {tabValue === 'Warning' && warnings.map((error, i) => (
                    <ConnectorWorksErrorLine key={error.rawError?.timestamp ?? i} error={error} />
                  ))}
                  {tabValue === 'All' && errors.map((error, i) => (
                    <ConnectorWorksErrorLine key={error.rawError?.timestamp ?? i} error={error} />
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </>
        </Drawer>
      </div>
    </>
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
