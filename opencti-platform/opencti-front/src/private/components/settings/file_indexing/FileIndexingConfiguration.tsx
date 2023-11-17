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
import { Field, Form, Formik } from 'formik';
import {
  FileIndexingConfigurationQuery$data,
} from '@components/settings/file_indexing/__generated__/FileIndexingConfigurationQuery.graphql';
import { FormikConfig } from 'formik/dist/types';
import { useMutation } from 'react-relay';
import { fileIndexingConfigurationFieldPatch } from '@components/settings/file_indexing/FileIndexing';
import Checkbox from '@mui/material/Checkbox';
import Divider from '@mui/material/Divider';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { handleErrorInForm } from '../../../../relay/environment';
import SwitchField from '../../../../components/SwitchField';

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
  managerConfiguration: FileIndexingConfigurationQuery$data['managerConfigurationByManagerId']
}

interface FileIndexingConfigurationFormValues {
  accept_mime_types: string[];
  include_global_files: boolean;
  max_file_size: number;
}

const FileIndexingConfiguration: FunctionComponent<FileIndexingConfigurationProps> = ({
  filesMetrics,
  managerConfiguration,
}) => {
  const { n, t, b } = useFormatter();
  const classes = useStyles();
  const totalFiles = filesMetrics?.globalCount ?? 0;
  const dataToIndex = filesMetrics?.globalSize ?? 0;
  const metricsByMimeType = filesMetrics?.metricsByMimeType ?? [];
  const manager_setting = managerConfiguration?.manager_setting;
  const defaultMimeTypes = ['application/pdf', 'text/plain', 'text/csv', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];
  const initialValues = {
    accept_mime_types: manager_setting.accept_mime_types,
    include_global_files: manager_setting.include_global_files,
    max_file_size: manager_setting.max_file_size,
  };
  const [commitManagerSetting] = useMutation(fileIndexingConfigurationFieldPatch);
  const onSubmitForm: FormikConfig<FileIndexingConfigurationFormValues>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    setSubmitting(true);
    commitManagerSetting({
      variables: {
        id: managerConfiguration?.id,
        input: { key: 'manager_setting', value: values },
      },
      onCompleted: () => {
        setSubmitting(false);
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  return (
    <div>
      <Typography variant="h4" gutterBottom={true}>
        {t('Configuration and impact')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={2}>
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
                <ListItem key={metrics.mimeType} divider={true} dense={true} style={{ height: 32 }}>
                  <ListItemText primary={t(metrics.mimeType)} className={classes.mimeType}/>
                  <ListItemText primary={`${metrics.count}`} className={classes.mimeTypeCount}/>
                  <ListItemText primary={'files for'}/>
                  <ListItemText primary={`${b(metrics.size)}`} className={classes.mimeTypeCount}/>
                </ListItem>
              ))}
            </List>
          </Grid>
        </Grid>
        <Divider style={{ marginBottom: 30, marginTop: 30 }} />
        <Formik
          initialValues={initialValues}
          onSubmit={onSubmitForm}
        >
        {({ submitForm, setFieldValue, values }) => (
          <Form>
              <Typography variant="h4" gutterBottom={true}>
                  {t('Mime-Types to index')}
              </Typography>
            <List style={{ marginLeft: 25 }}>
            { defaultMimeTypes.map((mimeType) => (
              <ListItem key={mimeType} divider={true} dense={true} style={{ height: 36 }}>
                <ListItemText primary={t(mimeType)} className={classes.mimeType}/>
                <Checkbox
                  edge="start"
                  disableRipple={true}
                  checked={values.accept_mime_types.includes(mimeType)}
                  onChange={() => {
                    if (values.accept_mime_types.includes(mimeType)) {
                      setFieldValue('accept_mime_types', values.accept_mime_types.filter((v) => v !== mimeType));
                    } else {
                      setFieldValue('accept_mime_types', [...values.accept_mime_types, mimeType]);
                    }
                    submitForm();
                  }}
                />
              </ListItem>
            ))}
            </List>
            <Field
              component={SwitchField}
              type="checkbox"
              name="include_global_files"
              label={t('Indexing global files')}
              containerstyle={{ marginTop: 20 }}
              onChange={submitForm}
            />
          </Form>
        )}
        </Formik>
      </Paper>
    </div>
  );
};

export default FileIndexingConfiguration;
