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
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import {
  FileIndexingConfigurationAndMonitoringQuery$data,
} from '@components/settings/file_indexing/__generated__/FileIndexingConfigurationAndMonitoringQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 20,
    borderRadius: 6,
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
  mimeType: {
    fontWeight: 500,
    color: theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
  },
  mimeTypeCount: {
    color: theme.palette.primary.main,
  },
}));

interface FileIndexingConfigurationProps {
  filesMetrics: FileIndexingConfigurationAndMonitoringQuery$data['filesMetrics']
}

const FileIndexingConfiguration: FunctionComponent<FileIndexingConfigurationProps> = ({
  filesMetrics,
}) => {
  const { n, t, b } = useFormatter();
  const classes = useStyles();
  const totalFiles = filesMetrics?.globalCount ?? 0;
  const dataToIndex = filesMetrics?.globalSize ?? 0;
  const metricsByMimeType = filesMetrics?.metricsByMimeType ?? [];

  return (
    <div>
      <Typography variant="h4" gutterBottom={true}>
        {t('Configuration and impact')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={4}>
            <div className={classes.count}>
              {n(totalFiles)}
            </div>
            <div className={classes.countText}>
              {t('Files will be indexed')}
            </div>
          </Grid>
          <Grid item={true} xs={4}>
            <div className={classes.count}>
              {b(dataToIndex)}
            </div>
            <div className={classes.countText}>
              {t('Storage size')}
            </div>
          </Grid>
          <Grid item={true} xs={4}>
              <List>
                { metricsByMimeType.map((metrics) => (
                  <ListItem key={metrics.mimeType} divider={true}>
                    <ListItemText primary={t(metrics.mimeType)} className={classes.mimeType}/>
                    <ListItemText primary={`${metrics.count}`} className={classes.mimeTypeCount}/>
                    <ListItemText primary={'files for'}/>
                    <ListItemText primary={`${b(metrics.size)}`} className={classes.mimeTypeCount}/>
                  </ListItem>
                ))}
              </List>
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default FileIndexingConfiguration;
