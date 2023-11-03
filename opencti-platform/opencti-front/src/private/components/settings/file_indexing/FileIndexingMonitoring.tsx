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
import { PauseOutlined, PlayArrowOutlined } from '@mui/icons-material';
import { graphql, PreloadedQuery, useMutation, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { fileIndexingConfigurationFieldPatch } from '@components/settings/file_indexing/FileIndexing';
import {
  FileIndexingMonitoringQuery,
} from '@components/settings/file_indexing/__generated__/FileIndexingMonitoringQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { handleError } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 20,
    borderRadius: 6,
  },
  button: {
    marginLeft: theme.spacing(2),
    marginTop: theme.spacing(2),
  },
  count: {
    marginTop: 10,
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
  queryRef: PreloadedQuery<FileIndexingMonitoringQuery>
  managerConfigurationId: string | undefined
  isStarted: boolean
  totalFiles: number | undefined
}

const FileIndexingMonitoringComponent: FunctionComponent<FileIndexingMonitoringComponentProps> = ({
  managerConfigurationId,
  isStarted,
  totalFiles,
  queryRef,
}) => {
  const { n, t } = useFormatter();
  const classes = useStyles();

  const { indexedFilesMetrics } = usePreloadedQuery<FileIndexingMonitoringQuery>(fileIndexingMonitoringQuery, queryRef);
  const indexedFiles = indexedFilesMetrics?.globalCount;
  const volumeIndexed = indexedFilesMetrics?.globalSize;

  const [commit] = useMutation(fileIndexingConfigurationFieldPatch);
  const updateManagerRunning = (running: boolean) => {
    commit({
      variables: {
        id: managerConfigurationId,
        input: { key: 'manager_running', value: running },
      },
      onCompleted: (data) => {
        console.log('data', data);
      },
      onError: (error) => {
        handleError(error);
      },
    });
  };

  const handleStart = () => {
    updateManagerRunning(true);
  };
  const handlePause = () => {
    updateManagerRunning(false);
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
                  classes={{ root: classes.button }}
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
                  classes={{ root: classes.button }}
                >
                  {t('Start')}
                </Button>
              )}
                </Grid>
                <Grid item={true} xs={4}>
                  <div className={classes.count}>
                      {indexedFiles} / {totalFiles}
                  </div>
                  <div className={classes.countText}>
                      {t('Files indexed')}
                  </div>
                </Grid>
                <Grid item={true} xs={4}>
                  <div className={classes.count}>
                      {n(volumeIndexed)}
                  </div>
                  <div className={classes.countText}>
                      {t('Volume indexed')}
                  </div>
                </Grid>
            </Grid>
        </Paper>
    </div>
  );
};

interface FileIndexingMonitoringProps {
  managerConfigurationId: string | undefined
  isStarted: boolean
  totalFiles: number | undefined
}

const FileIndexingMonitoring: FunctionComponent<FileIndexingMonitoringProps> = ({ managerConfigurationId, isStarted, totalFiles }) => {
  const [queryRef, loadQuery] = useQueryLoader<FileIndexingMonitoringQuery>(fileIndexingMonitoringQuery);
  useEffect(() => {
    loadQuery({}, { fetchPolicy: 'store-and-network' });
  }, []);
  return (
      <>
        {queryRef ? (
            <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
              <FileIndexingMonitoringComponent
                  queryRef={queryRef}
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
