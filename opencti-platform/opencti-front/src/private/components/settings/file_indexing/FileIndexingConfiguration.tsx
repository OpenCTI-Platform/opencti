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

import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import { Field, Form, Formik } from 'formik';
import { FileIndexingConfigurationQuery$data } from '@components/settings/file_indexing/__generated__/FileIndexingConfigurationQuery.graphql';
import { FormikConfig } from 'formik/dist/types';
import { fileIndexingConfigurationFieldPatch } from '@components/settings/file_indexing/FileIndexing';
import Checkbox from '@mui/material/Checkbox';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { handleErrorInForm } from '../../../../relay/environment';
import SwitchField from '../../../../components/fields/SwitchField';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';
import TextField from '../../../../components/TextField';
import useAttributes from '../../../../utils/hooks/useAttributes';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Card from '../../../../components/common/card/Card';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  icon: {
    paddingTop: 4,
    paddingRight: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
}));

interface FileIndexingConfigurationProps {
  managerConfiguration: FileIndexingConfigurationQuery$data['managerConfigurationByManagerId'];
}

interface FileIndexingConfigurationFormValues {
  accept_mime_types: string[];
  include_global_files: boolean;
  max_file_size: number;
  entity_types: string[];
}

const FileIndexingConfiguration: FunctionComponent<
  FileIndexingConfigurationProps
> = ({ managerConfiguration }) => {
  const { t_i18n } = useFormatter();
  const { stixCoreObjectTypes: availableEntityTypes } = useAttributes();
  const classes = useStyles();
  const manager_setting = managerConfiguration?.manager_setting;
  const initialValues = {
    accept_mime_types: manager_setting?.accept_mime_types,
    include_global_files: manager_setting?.include_global_files,
    max_file_size: manager_setting?.max_file_size,
    entity_types: manager_setting?.entity_types,
  };
  const [commitManagerSetting] = useApiMutation(
    fileIndexingConfigurationFieldPatch,
  );
  const onSubmitForm: FormikConfig<FileIndexingConfigurationFormValues>['onSubmit'] = (values, { setSubmitting, setErrors }) => {
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
    max_file_size: Yup.number()
      .min(1)
      .max(100)
      .required(t_i18n('This field is required')),
  });

  return (
    <Card title={t_i18n('Configuration')}>
      <Formik
        initialValues={initialValues}
        validationSchema={formValidation()}
        onSubmit={onSubmitForm}
      >
        {({ submitForm, setFieldValue, values }) => (
          <Form>
            <Typography variant="h4" gutterBottom={true}>
              {t_i18n('File types to index')}
            </Typography>
            <List style={{ marginBottom: 12 }}>
              {(manager_setting?.supported_mime_types || []).map((mimeType: string) => (
                <ListItem
                  key={mimeType}
                  divider={true}
                  dense={true}
                  style={{ height: 36 }}
                >
                  <ListItemText primary={t_i18n(mimeType)} />
                  <Checkbox
                    edge="start"
                    disableRipple={true}
                    checked={values.accept_mime_types.includes(mimeType)}
                    onChange={() => {
                      if (values.accept_mime_types.includes(mimeType)) {
                        setFieldValue(
                          'accept_mime_types',
                          values.accept_mime_types.filter(
                            (v: string) => v !== mimeType,
                          ),
                        );
                      } else {
                        setFieldValue('accept_mime_types', [
                          ...values.accept_mime_types,
                          mimeType,
                        ]);
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
              label={t_i18n('Max file size (in MB)')}
              fullWidth={true}
              type="number"
              style={{ marginBottom: 20 }}
              onChange={submitForm}
            />
            <Field
              component={AutocompleteField}
              name="entity_types"
              multiple={true}
              fullWidth={true}
              textfieldprops={{
                variant: 'standard',
                label: t_i18n('Restrict to specific entity types'),
              }}
              options={availableEntityTypes}
              isOptionEqualToValue={(option: string, value: string) => option === value
              }
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
                  <ListItemText primary={t_i18n(`entity_${option}`)} />
                </li>
              )}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="include_global_files"
              label={t_i18n(
                'Include files not related to any knowledge (data import)',
              )}
              containerstyle={{ marginBottom: 20 }}
              onChange={submitForm}
            />
          </Form>
        )}
      </Formik>
    </Card>
  );
};

export default FileIndexingConfiguration;
