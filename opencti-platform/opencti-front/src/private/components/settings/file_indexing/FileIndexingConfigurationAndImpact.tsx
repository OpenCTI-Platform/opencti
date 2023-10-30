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
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';

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
}));

interface FileIndexingConfigurationAndImpactProps {
  totalFiles: number | undefined // TODO undefined??
  dataToIndex: number | undefined
}

const FileIndexingConfigurationAndImpact: FunctionComponent<FileIndexingConfigurationAndImpactProps> = ({
  totalFiles,
  dataToIndex,
}) => {
  const { n, t, b } = useFormatter();
  const classes = useStyles();

  return (
    <div>
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
      </div>
  );
};

export default FileIndexingConfigurationAndImpact;
