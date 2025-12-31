import React, { FunctionComponent, useState } from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import LinearProgress from '@mui/material/LinearProgress';
import Button from '@common/button/Button';
import { Delete } from 'mdi-material-ui';
import Paper from '@mui/material/Paper';
import Alert from '@mui/material/Alert';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import TableContainer from '@mui/material/TableContainer';
import Table from '@mui/material/Table';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TableCell from '@mui/material/TableCell';
import TableBody from '@mui/material/TableBody';
import ConnectorWorksErrorLine from '@components/data/connectors/ConnectorWorksErrorLine';
import Drawer from '@components/common/drawer/Drawer';
import { ConnectorWorks_data$data, State } from '@components/data/connectors/__generated__/ConnectorWorks_data.graphql';
import parseWorkErrors, { ParsedWorkMessage } from '@components/data/connectors/parseWorkErrors';
import { connectorWorksWorkDeletionMutation } from '@components/data/connectors/ConnectorWorks';
import { MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import TaskStatus from '../../../../components/TaskStatus';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';

type WorkMessages = NonNullable<NonNullable<NonNullable<ConnectorWorks_data$data['works']>['edges']>[0]>['node']['errors'];
interface ConnectorWorkLineProps {
  workId: string;
  workName: string | null | undefined;
  workStatus: State;
  workReceivedTime: string;
  workEndTime: string;
  workExpectedNumber: number | null | undefined;
  workProcessedNumber: number | null | undefined;
  workErrors: WorkMessages | null | undefined;
  readOnly?: boolean | undefined;
}
const ConnectorWorkLine: FunctionComponent<
  ConnectorWorkLineProps
> = ({ workId, workName, workStatus, workReceivedTime, workEndTime, workExpectedNumber, workProcessedNumber, workErrors, readOnly }) => {
  const { t_i18n, nsdt } = useFormatter();

  const [commit] = useApiMutation(connectorWorksWorkDeletionMutation);
  const [openDrawerErrors, setOpenDrawerErrors] = useState<boolean>(false);
  const [errors, setErrors] = useState<ParsedWorkMessage[]>([]);
  const [criticals, setCriticals] = useState<ParsedWorkMessage[]>([]);
  const [warnings, setWarnings] = useState<ParsedWorkMessage[]>([]);
  const [tabValue, setTabValue] = useState<string>('Critical');

  const handleCloseDrawerErrors = () => {
    setOpenDrawerErrors(false);
    setErrors([]);
  };

  const handleDeleteWork = () => {
    commit({
      variables: {
        id: workId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The work has been deleted');
      },
    });
  };

  const handleOpenDrawerErrors = async (errorsList: WorkMessages) => {
    setOpenDrawerErrors(true);
    const parsedList = await parseWorkErrors(errorsList);
    setErrors(parsedList);
    const criticalErrors = parsedList.filter((error) => error.level === 'Critical');
    setCriticals(criticalErrors);
    const warningErrors = parsedList.filter((error) => error.level === 'Warning');
    setWarnings(warningErrors);
  };

  return (
    <>
      <Grid container={true} spacing={3}>
        <Grid item xs={7}>
          <Grid container={true} spacing={1}>
            <Grid item xs={8}>
              <Typography variant="h3" gutterBottom={true}>
                {t_i18n('Name')}
              </Typography>
              <Tooltip title={workName}>
                <Typography sx={{ overflowX: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'noWrap' }}>
                  {workName}
                </Typography>
              </Tooltip>
            </Grid>
            <Grid item xs={4}>
              <Typography variant="h3" gutterBottom={true}>
                {t_i18n('Status')}
              </Typography>
              <TaskStatus status={workStatus} label={t_i18n(workStatus)} />
            </Grid>
            <Grid item xs={8}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t_i18n('Work start time')}
              </Typography>
              {nsdt(workReceivedTime)}
            </Grid>
            <Grid item xs={4}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t_i18n('Work end time')}
              </Typography>
              {workEndTime ? nsdt(workEndTime) : '-'}
            </Grid>
          </Grid>
        </Grid>
        <Grid item xs={4}>
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t_i18n('Operations completed')}
              </Typography>
              <span style={{ fontWeight: 600, fontSize: 18 }}>
                {workStatus === 'wait'
                  ? '-'
                  : workProcessedNumber ?? '-'}
              </span>
            </Grid>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t_i18n('Total number of operations')}
              </Typography>
              <span style={{ fontWeight: 600, fontSize: 18 }}>
                {workExpectedNumber ?? '-'}
              </span>
            </Grid>
            <Grid item xs={11}>
              <Typography variant="h3" gutterBottom={true}>
                {t_i18n('Progress')}
              </Typography>
              <LinearProgress
                style={{ borderRadius: 4, height: 10 }}
                variant="determinate"
                value={
                  !!workExpectedNumber && !!workProcessedNumber
                    ? Math.round((workProcessedNumber / workExpectedNumber) * 100)
                    : 0
                }
              />
            </Grid>
          </Grid>
        </Grid>
        <Button
          style={{ position: 'absolute', right: 10, top: 10 }}
          variant="secondary"
          color={(workErrors ?? []).length === 0 ? 'success' : 'warning'}
          onClick={() => handleOpenDrawerErrors(workErrors ?? [])}
          size="small"
        >
          {workErrors?.length} {t_i18n('errors')}
        </Button>
        {!readOnly && (
          <Security needs={[MODULES_MODMANAGE]}>
            <Button
              variant="secondary"
              style={{ position: 'absolute', right: 10, bottom: 10 }}
              onClick={() => handleDeleteWork()}
              size="small"
              startIcon={<Delete />}
            >
              {t_i18n('Delete')}
            </Button>
          </Security>
        )}
      </Grid>
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
    </>
  );
};

export default ConnectorWorkLine;
