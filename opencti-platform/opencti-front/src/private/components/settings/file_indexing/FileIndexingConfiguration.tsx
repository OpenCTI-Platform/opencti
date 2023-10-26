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

import React, { FunctionComponent } from 'react';
import EnterpriseEdition from '@components/common/EnterpriseEdition';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import { PauseOutlined, PlayArrowOutlined } from '@mui/icons-material';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';
import { FILE_INDEX_MANAGER } from '../../../../utils/platformModulesHelper';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 20,
    borderRadius: 6,
  },
  gridContainer: {
    marginBottom: 20,
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
  button: {
    marginLeft: theme.spacing(2),
    marginTop: theme.spacing(2),
  },
}));

const FileIndexingConfiguration: FunctionComponent = () => {
  const { n, t, b } = useFormatter();
  const classes = useStyles();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { platformModuleHelpers } = useAuth();
  const isModuleWarning = platformModuleHelpers.isModuleWarning(FILE_INDEX_MANAGER);
  const isStarted = false; // TODO get from config

  const totalFiles = 333; // TODO queries
  const dataToIndex = 140000000; // TODO managing different units of size  14000 => 14 GO  14 => 14 MO
  const indexedFiles = 2;
  const volumeIndexed = 1;

  const handleStart = () => {};
  const handlePause = () => {};

  return (
    <div>
      {!isEnterpriseEdition && (
        <EnterpriseEdition />
      )}
      <Grid container={true} spacing={3} classes={{ container: classes.gridContainer }}>
        <Grid item={true} xs={12}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Requirements')}
          </Typography>
          <Paper classes={{ root: classes.paper }} variant="outlined">
            <Alert
                classes={{ root: classes.alert, message: classes.message }}
                severity={isModuleWarning ? 'warning' : 'info'}
                variant="outlined"
                style={{ position: 'relative' }}
            >
              {t('File indexing needs one of these requirements: ')}
              <ul>
                <li>Elasticsearch &gt;= 8.4</li>
                <li>Elasticsearch &lt; 8.4 with ingest-attachment plugin</li>
                <li>OpenSearch with ingest-attachment plugin</li>
              </ul>
            </Alert>
          </Paper>
        </Grid>
      </Grid>
        {isEnterpriseEdition && !isModuleWarning && (
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6} style={{ marginTop: 30 }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Configuration and impact')}
              </Typography>
              <Paper classes={{ root: classes.paper }} variant="outlined">
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={6}>
                    <div className={classes.count}>
                      {n(totalFiles)}
                    </div>
                    <div className={classes.countText}>
                      {t('Files will be indexed')}
                    </div>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <div className={classes.count}>
                      {b(dataToIndex)}
                    </div>
                    <div className={classes.countText}>
                      {t('Of data will be indexed')}
                    </div>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
            <Grid item={true} xs={6} style={{ marginTop: 30 }}>
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
                      {(isStarted ? n(indexedFiles) : '-')} / {n(totalFiles)}
                    </div>
                    <div className={classes.countText}>
                      {t('Files indexed')}
                    </div>
                  </Grid>
                  <Grid item={true} xs={4}>
                    <div className={classes.count}>
                      {(isStarted ? n(volumeIndexed) : '-')} / {b(dataToIndex)}
                    </div>
                    <div className={classes.countText}>
                      {t('Volume indexed')}
                    </div>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        )}
    </div>
  );
};

export default FileIndexingConfiguration;
