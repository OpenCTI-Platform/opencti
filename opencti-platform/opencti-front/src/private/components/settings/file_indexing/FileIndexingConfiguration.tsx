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
import {
  fileIndexingDefaultMaxFileSize,
  fileIndexingDefaultMimeTypes,
} from '@components/settings/file_indexing/FileIndexingConfigurationAndMonitoring';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { handleErrorInForm } from '../../../../relay/environment';
import SwitchField from '../../../../components/SwitchField';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';
import useAuth from '../../../../utils/hooks/useAuth';
import TextField from '../../../../components/TextField';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 20,
    borderRadius: 6,
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
  icon: {
    paddingTop: 4,
    paddingRight: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
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
  filesMetrics: FileIndexingConfigurationAndMonitoringQuery$data['filesMetrics'];
  managerConfiguration: FileIndexingConfigurationQuery$data['managerConfigurationByManagerId'];
}

interface FileIndexingConfigurationFormValues {
  accept_mime_types: string[];
  include_global_files: boolean;
  max_file_size: number;
  entity_types: string[];
}

const FileIndexingConfiguration: FunctionComponent<FileIndexingConfigurationProps> = ({
  filesMetrics,
  managerConfiguration,
}) => {
  const { n, t, b } = useFormatter();
  const { schema } = useAuth();
  const { sdos, scos } = schema;
  const classes = useStyles();
  const totalFiles = filesMetrics?.globalCount ?? 0;
  const dataToIndex = filesMetrics?.globalSize ?? 0;
  const metricsByMimeType = filesMetrics?.metricsByMimeType ?? [];
  const manager_setting = managerConfiguration?.manager_setting;
  const defaultMimeTypes = [...fileIndexingDefaultMimeTypes];
  const initialMaxFileSizeInBytes = manager_setting?.max_file_size ? parseInt(manager_setting.max_file_size, 10) : fileIndexingDefaultMaxFileSize;
  const initialValues = {
    accept_mime_types: manager_setting?.accept_mime_types ?? defaultMimeTypes,
    include_global_files: manager_setting?.include_global_files || false,
    max_file_size: Math.floor(initialMaxFileSizeInBytes / (1024 * 1024)),
    entity_types: manager_setting?.entity_types ?? [],
  };
  const availableEntityTypes = sdos.map((sdo) => sdo.id)
    .concat(scos.map((sco) => sco.id));
  const [commitManagerSetting] = useMutation(fileIndexingConfigurationFieldPatch);
  const onSubmitForm: FormikConfig<FileIndexingConfigurationFormValues>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    setSubmitting(true);
    const managerSettingValues = {
      accept_mime_types: values.accept_mime_types,
      include_global_files: values.include_global_files,
      max_file_size: parseInt(String(values.max_file_size), 10) * 1024 * 1024, // in bytes
      entity_types: values.entity_types,
    };
    commitManagerSetting({
      variables: {
        id: managerConfiguration?.id,
        input: { key: 'manager_setting', value: managerSettingValues },
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

  const formValidation = () => Yup.object().shape({
    max_file_size: Yup.number().min(1).max(100).required(t('This field is required')),
  });

  return (
    <div>
      <Typography variant="h4" gutterBottom={true}>
        {t('Configuration and impact')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={2}>
          <Grid item={true} xs={4}>
            <div className={classes.countContainer}>
              <div className={classes.count}>
                {n(totalFiles)}
              </div>
              <div className={classes.countText}>
                {t('Files will be indexed')}
              </div>
            </div>
          </Grid>
          <Grid item={true} xs={4}>
            <div className={classes.countContainer}>
              <div className={classes.count}>
                {b(dataToIndex)}
              </div>
              <div className={classes.countText}>
                {t('Storage size')}
              </div>
            </div>
          </Grid>
          <Grid item={true} xs={4} style={{ paddingTop: 0 }}>
            <List>
              {metricsByMimeType.map((metrics) => (
                <ListItem key={metrics.mimeType} divider={true} dense={true} style={{ height: 32, padding: 0 }}>
                  <ListItemText primary={t(metrics.mimeType)} className={classes.mimeType} style={{ width: '18%' }} />
                  <ListItemText primary={`~${metrics.count}`} className={classes.mimeTypeCount} style={{ width: '25%' }}/>
                  <ListItemText primary={'files for'} style={{ width: '27%' }}/>
                  <ListItemText primary={`${b(metrics.size)}`} className={classes.mimeTypeCount} style={{ width: '30%' }}/>
                </ListItem>
              ))}
            </List>
          </Grid>
        </Grid>
        <Divider style={{ marginBottom: 30, marginTop: 30 }} />
        <Formik
          initialValues={initialValues}
          validationSchema={formValidation()}
          onSubmit={onSubmitForm}
        >
        {({ submitForm, setFieldValue, values }) => (
          <Form>
            <Typography variant="h4" gutterBottom={true}>
              {t('File types to index')}
            </Typography>
            <List style={{ marginBottom: 12 }}>
            {defaultMimeTypes.map((mimeType) => (
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
              component={TextField}
              variant="standard"
              name="max_file_size"
              label={t('Max file size (in Mb)')}
              fullWidth={false}
              type="number"
              style={{ marginBottom: 20 }}
              onChange={submitForm}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="include_global_files"
              label={t('Include files not related to any knowledge (data import and analyst workbench)')}
              containerstyle={{ marginBottom: 20 }}
              onChange={submitForm}
            />
            <Field
              component={AutocompleteField}
              name="entity_types"
              multiple={true}
              textfieldprops={{
                variant: 'standard',
                label: t('Restrict to specific entity types'),
              }}
              options={availableEntityTypes}
              isOptionEqualToValue={(option: string, value: string) => option === value}
              style={{ marginBottom: 12 }}
              onChange={submitForm}
              renderOption={(
                props: React.HTMLAttributes<HTMLLIElement>,
                option: string,
              ) => (
                <li {...props}>
                  <div className={classes.icon}>
                    <ItemIcon type={option} />
                  </div>
                  <ListItemText primary={t(`entity_${option}`)} />
                </li>
              )}
            />
          </Form>
        )}
        </Formik>
      </Paper>
    </div>
  );
};

export default FileIndexingConfiguration;
