/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { FunctionComponent, useEffect } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import Button from '@common/button/Button';
import { ClearOutlined, FolderOutlined, PauseOutlined, PlayArrowOutlined, StorageOutlined, SyncDisabledOutlined, SyncOutlined } from '@mui/icons-material';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { fileIndexingConfigurationFieldPatch, fileIndexingResetMutation } from '@components/settings/file_indexing/FileIndexing';
import { FileIndexingMonitoringQuery } from '@components/settings/file_indexing/__generated__/FileIndexingMonitoringQuery.graphql';
import { interval } from 'rxjs';
import LinearProgress, { linearProgressClasses } from '@mui/material/LinearProgress';
import { FileIndexingConfigurationAndMonitoringQuery$data } from '@components/settings/file_indexing/__generated__/FileIndexingConfigurationAndMonitoringQuery.graphql';
import { styled } from '@mui/material/styles';
import FileIndexingConfiguration from '@components/settings/file_indexing/FileIndexingConfiguration';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import { FileIndexingConfigurationQuery$data } from '@components/settings/file_indexing/__generated__/FileIndexingConfigurationQuery.graphql';
import DangerZoneBlock from '@components/common/danger_zone/DangerZoneBlock';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { handleError, MESSAGING$ } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { TEN_SECONDS } from '../../../../utils/Time';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import ItemBoolean from '../../../../components/ItemBoolean';

const interval$ = interval(TEN_SECONDS);

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
  header: {
    textTransform: 'uppercase',
  },
  mimeTypeCount: {
    color: theme.palette.primary.main,
  },
}));

const fileIndexingMonitoringQuery = graphql`
  query FileIndexingMonitoringQuery {
    indexedFilesMetrics {
      globalCount
      globalSize
    }
  }
`;

interface FileIndexingMonitoringComponentProps {
  queryRef: PreloadedQuery<FileIndexingMonitoringQuery>;
  refetch: () => void;
  managerConfigurationId: string | undefined;
  filesMetrics: FileIndexingConfigurationAndMonitoringQuery$data['filesMetrics'];
  managerConfiguration: FileIndexingConfigurationQuery$data['managerConfigurationByManagerId'];
  isStarted: boolean;
  totalFiles: number;
  lastIndexationDate: Date;
}

const BorderLinearProgress = styled(LinearProgress)(({ theme }) => ({
  height: 8,
  borderRadius: 4,
  flex: 1,
  margin: `0 ${theme.spacing(2)}`,
  [`& .${linearProgressClasses.bar}`]: {
    borderRadius: 4,
    backgroundColor: theme.palette.primary.main,
  },
}));

const FileIndexingMonitoringComponent: FunctionComponent<FileIndexingMonitoringComponentProps> = ({
  managerConfigurationId,
  isStarted,
  totalFiles,
  lastIndexationDate,
  filesMetrics,
  managerConfiguration,
  queryRef,
  refetch,
}) => {
  const theme = useTheme<Theme>();
  const { n, t_i18n, fldt, b } = useFormatter();
  const classes = useStyles();
  const { indexedFilesMetrics } = usePreloadedQuery<FileIndexingMonitoringQuery>(
    fileIndexingMonitoringQuery,
    queryRef,
  );
  const indexedFiles = indexedFilesMetrics?.globalCount ?? 0;
  const volumeIndexed = indexedFilesMetrics?.globalSize ?? 0;
  const dataToIndex = filesMetrics?.globalSize ?? 0;
  const metricsByMimeType = filesMetrics?.metricsByMimeType ?? [];
  const [commitManagerRunning] = useApiMutation(
    fileIndexingConfigurationFieldPatch,
  );
  const updateManagerRunning = (running: boolean) => {
    commitManagerRunning({
      variables: {
        id: managerConfigurationId,
        input: { key: 'manager_running', value: running },
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(
          `File indexing successfully ${running ? 'started' : 'paused'}`,
        );
      },
      onError: (error) => {
        handleError(error);
      },
    });
  };
  const [commitManagerReset] = useApiMutation(fileIndexingResetMutation);
  const resetManager = () => {
    commitManagerReset({
      variables: {},
      onCompleted: () => {
        MESSAGING$.notifySuccess('File indexing successfully reset');
        refetch();
      },
      onError: (error) => {
        handleError(error);
      },
    });
  };
  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      refetch();
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);
  const handleStart = () => {
    updateManagerRunning(true);
  };
  const handlePause = () => {
    updateManagerRunning(false);
  };
  const handleReset = () => {
    handlePause();
    resetManager();
  };
  return (
    <Grid container={true} spacing={3}>
      <Grid item xs={6}>
        <Typography variant="h4">{t_i18n('Status')}</Typography>
        <Paper
          variant="outlined"
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: theme.spacing(2),
            height: 'fit-content',
          }}
          className="paper-for-grid"
        >
          <ItemBoolean
            label={isStarted ? t_i18n('Running') : t_i18n('Stopped')}
            status={isStarted}
          />
          <BorderLinearProgress
            value={
              indexedFiles > 0
                ? Math.round((indexedFiles / totalFiles) * 100)
                : 0
            }
            variant="determinate"
          />
          {isStarted ? (
            <SyncOutlined color="primary" sx={{ fontSize: 40 }} />
          ) : (
            <SyncDisabledOutlined color="primary" sx={{ fontSize: 40 }} />
          )}
        </Paper>
      </Grid>
      <Grid item xs={3}>
        <Typography variant="h4">{t_i18n('Indexed files')}</Typography>
        <Paper
          variant="outlined"
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: theme.spacing(2),
          }}
          className="paper-for-grid"
        >
          <Typography variant="h2" style={{ margin: 0 }}>
            {indexedFiles} / {totalFiles}
          </Typography>
          <FolderOutlined color="primary" sx={{ fontSize: 40 }} />
        </Paper>
      </Grid>
      <Grid item xs={3}>
        <Typography variant="h4">{t_i18n('Volume indexed')}</Typography>
        <Paper
          variant="outlined"
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: theme.spacing(2),
          }}
          className="paper-for-grid"
        >
          <Typography variant="h2" style={{ margin: 0 }}>
            {indexedFiles ? n(volumeIndexed) : 0}
          </Typography>
          <StorageOutlined color="primary" sx={{ fontSize: 40 }} />
        </Paper>
      </Grid>
      <Grid item xs={4}>
        <DangerZoneBlock
          type="file_indexing"
          title={t_i18n('Control')}
          component={({ disabled, style }) => (
            <Paper classes={{ root: classes.paper }} className="paper-for-grid" variant="outlined" style={style}>
              <Grid container={true} spacing={3}>
                <Grid item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Engine')}
                  </Typography>
                  {isStarted ? (
                    <Button
                      startIcon={<PauseOutlined />}
                      aria-label="Pause"
                      onClick={handlePause}
                      color="warning"
                      disabled={disabled}
                    >
                      {t_i18n('Pause')}
                    </Button>
                  ) : (
                    <Button
                      startIcon={<PlayArrowOutlined />}
                      aria-label="Start"
                      onClick={handleStart}
                      color="success"
                      disabled={disabled}
                    >
                      {t_i18n('Start')}
                    </Button>
                  )}
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Indexing')}
                  </Typography>
                  <Button
                    startIcon={<ClearOutlined />}
                    aria-label="Reset"
                    onClick={handleReset}
                    color="error"
                    disabled={disabled || indexedFiles === 0}
                  >
                    {t_i18n('Reset')}
                  </Button>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Indexing manager start')}
                  </Typography>
                  {fldt(managerConfiguration?.last_run_start_date)}
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Last indexation')}
                  </Typography>
                  {fldt(lastIndexationDate)}
                </Grid>
              </Grid>
            </Paper>
          )}
        />
      </Grid>
      <Grid item xs={4}>
        <Typography variant="h4" gutterBottom={true}>
          {t_i18n('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} className="paper-for-grid" variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t_i18n('Total files in S3')}
              </Typography>
              <span style={{ fontWeight: 600, fontSize: 20 }}>
                {n(totalFiles)}
              </span>
            </Grid>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t_i18n('Files volumes in S3')}
              </Typography>
              <span style={{ fontWeight: 600, fontSize: 20 }}>
                {b(dataToIndex)}
              </span>
            </Grid>
            <Grid item xs={12}>
              <Typography variant="h3" gutterBottom={true}>
                {t_i18n('S3 volume by file type')}
              </Typography>
              <List>
                <ListItem
                  divider={true}
                  dense={true}
                  style={{ height: 32, padding: 0 }}
                >
                  <ListItemText
                    primary={t_i18n('Type')}
                    className={classes.header}
                    style={{ width: '30%' }}
                  />
                  <ListItemText
                    primary={t_i18n('Files count')}
                    className={classes.header}
                    style={{ width: '30%' }}
                  />
                  <ListItemText
                    primary={t_i18n('Files size')}
                    className={classes.header}
                    style={{ width: '30%' }}
                  />
                </ListItem>
                {metricsByMimeType.map((metrics) => (
                  <ListItem
                    key={metrics.mimeType}
                    divider={true}
                    dense={true}
                    style={{ height: 32, padding: 0 }}
                  >
                    <ListItemText
                      primary={t_i18n(metrics.mimeType)}
                      className={classes.mimeType}
                      style={{ width: '30%' }}
                    />
                    <ListItemText
                      primary={`${metrics.count}`}
                      className={classes.mimeTypeCount}
                      style={{ width: '30%' }}
                    />
                    <ListItemText
                      primary={`${b(metrics.size)}`}
                      className={classes.mimeTypeCount}
                      style={{ width: '30%' }}
                    />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>
      </Grid>
      <Grid item xs={4}>
        <FileIndexingConfiguration
          managerConfiguration={managerConfiguration}
        />
      </Grid>
    </Grid>
  );
};

interface FileIndexingMonitoringProps {
  filesMetrics: FileIndexingConfigurationAndMonitoringQuery$data['filesMetrics'];
  managerConfiguration: FileIndexingConfigurationQuery$data['managerConfigurationByManagerId'];
  managerConfigurationId: string | undefined;
  isStarted: boolean;
  totalFiles: number;
  lastIndexationDate: Date;
}

const FileIndexingMonitoring: FunctionComponent<FileIndexingMonitoringProps> = ({
  managerConfigurationId,
  isStarted,
  totalFiles,
  lastIndexationDate,
  filesMetrics,
  managerConfiguration,
}) => {
  const [queryRef, loadQuery] = useQueryLoader<FileIndexingMonitoringQuery>(
    fileIndexingMonitoringQuery,
  );
  useEffect(() => {
    loadQuery({}, { fetchPolicy: 'store-and-network' });
  }, []);

  const refetch = React.useCallback(() => {
    loadQuery({}, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);

  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <FileIndexingMonitoringComponent
            queryRef={queryRef}
            refetch={refetch}
            managerConfigurationId={managerConfigurationId}
            isStarted={isStarted}
            totalFiles={totalFiles}
            lastIndexationDate={lastIndexationDate}
            filesMetrics={filesMetrics}
            managerConfiguration={managerConfiguration}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default FileIndexingMonitoring;
