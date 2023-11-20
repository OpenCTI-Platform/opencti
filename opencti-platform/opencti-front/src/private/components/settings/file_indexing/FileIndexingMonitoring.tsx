/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
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
import Button from '@mui/material/Button';
import { ClearOutlined, PauseOutlined, PlayArrowOutlined } from '@mui/icons-material';
import { graphql, PreloadedQuery, useMutation, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { fileIndexingConfigurationFieldPatch, fileIndexingResetMutation } from '@components/settings/file_indexing/FileIndexing';
import {
  FileIndexingMonitoringQuery,
} from '@components/settings/file_indexing/__generated__/FileIndexingMonitoringQuery.graphql';
import { interval } from 'rxjs';
import LinearProgress from '@mui/material/LinearProgress';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { handleError, MESSAGING$ } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { TEN_SECONDS } from '../../../../utils/Time';

const interval$ = interval(TEN_SECONDS);

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 20,
    borderRadius: 6,
  },
  resetButton: {
    marginTop: theme.spacing(2),
  },
  count: {
    fontSize: 30,
    color: theme.palette.primary.main,
    textAlign: 'center',
  },
  countText: {
    textAlign: 'center',
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
    fontWeight: 500,
    color: theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
  },
  countContainer: {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    alignItems: 'center',
    justifyContent: 'center',
  },
  progress: {
    borderRadius: 5,
    height: 10,
    width: '100%',
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
  isStarted: boolean;
  totalFiles: number;
}

const FileIndexingMonitoringComponent: FunctionComponent<FileIndexingMonitoringComponentProps> = ({
  managerConfigurationId,
  isStarted,
  totalFiles,
  queryRef,
  refetch,
}) => {
  const { n, t } = useFormatter();
  const classes = useStyles();

  const { indexedFilesMetrics } = usePreloadedQuery<FileIndexingMonitoringQuery>(fileIndexingMonitoringQuery, queryRef);
  const indexedFiles = indexedFilesMetrics?.globalCount ?? 0;
  const volumeIndexed = indexedFilesMetrics?.globalSize ?? 0;

  const [commitManagerRunning] = useMutation(fileIndexingConfigurationFieldPatch);
  const updateManagerRunning = (running: boolean) => {
    commitManagerRunning({
      variables: {
        id: managerConfigurationId,
        input: { key: 'manager_running', value: running },
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(`File indexing successfully ${running ? 'started' : 'paused'}`);
      },
      onError: (error) => {
        handleError(error);
      },
    });
  };

  const [commitManagerReset] = useMutation(fileIndexingResetMutation);
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
    <div>
      <Typography variant="h4" gutterBottom={true}>
        {t('Indexing information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={4}>
            {isStarted ? (
              <Button
                startIcon={<PauseOutlined />}
                aria-label="Pause"
                onClick={handlePause}
                size="large"
                color="warning"
                variant="contained"
              >
                {t('Pause')}
              </Button>
            ) : (
              <Button
                startIcon={<PlayArrowOutlined />}
                aria-label="Start"
                onClick={handleStart}
                size="large"
                color="success"
                variant="contained"
              >
                {t('Start')}
              </Button>
            )}
            { indexedFiles > 0 && (
              <Button
                startIcon={<ClearOutlined />}
                aria-label="Reset"
                onClick={handleReset}
                size="large"
                color="error"
                variant="contained"
                classes={{ root: classes.resetButton }}
              >
                {t('Reset')}
              </Button>
            )}
          </Grid>
          <Grid item={true} xs={4}>
            <div className={classes.countContainer}>
              <div className={classes.count}>
                {indexedFiles} / {totalFiles}
              </div>
              <div className={classes.countText}>
                {t('Files indexed')}
              </div>
            </div>
          </Grid>
          <Grid item={true} xs={4}>
            <div className={classes.countContainer}>
              <div className={classes.count}>
                {indexedFiles ? n(volumeIndexed) : 0}
              </div>
              <div className={classes.countText}>
                {t('Volume indexed')}
              </div>
            </div>
          </Grid>
        </Grid>
        { isStarted && (
          <div style={{ paddingTop: 30 }}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Progress')}
            </Typography>
            <LinearProgress
              classes={{ root: classes.progress }}
              variant="determinate"
              value={
                // eslint-disable-next-line no-nested-ternary
                indexedFiles
                  ? indexedFiles === 0
                    ? 0
                    : Math.round(
                      (indexedFiles
                        / totalFiles)
                        * 100,
                    )
                  : 0
              }
            />
          </div>
        )}
      </Paper>
    </div>
  );
};

interface FileIndexingMonitoringProps {
  managerConfigurationId: string | undefined;
  isStarted: boolean;
  totalFiles: number;
}

const FileIndexingMonitoring: FunctionComponent<FileIndexingMonitoringProps> = ({ managerConfigurationId, isStarted, totalFiles }) => {
  const [queryRef, loadQuery] = useQueryLoader<FileIndexingMonitoringQuery>(fileIndexingMonitoringQuery);
  useEffect(() => {
    loadQuery({}, { fetchPolicy: 'store-and-network' });
  }, []);

  const refetch = React.useCallback(() => {
    loadQuery({}, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);

  return (
    <>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <FileIndexingMonitoringComponent
            queryRef={queryRef}
            refetch={refetch}
            managerConfigurationId={managerConfigurationId}
            isStarted={isStarted}
            totalFiles={totalFiles}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.container} />
      )}
    </>
  );
};

export default FileIndexingMonitoring;
