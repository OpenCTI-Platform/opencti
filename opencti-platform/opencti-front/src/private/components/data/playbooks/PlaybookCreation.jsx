/*
Copyright (c) 2021-2024 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { insertNode } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import { useSchemaCreationValidation, useMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const PlaybookCreationMutation = graphql`
  mutation PlaybookCreationMutation($input: PlaybookAddInput!) {
    playbookAdd(input: $input) {
      ...PlaybookLine_node
    }
  }
`;

const OBJECT_TYPE = 'Playbook';

const PlaybookCreation = ({ paginationOptions }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const basicShape = {
    name: Yup.string(),
    description: Yup.string().nullable(),
  };
  const mandatoryAttributes = useMandatorySchemaAttributes(OBJECT_TYPE);
  const validator = useSchemaCreationValidation(
    OBJECT_TYPE,
    basicShape,
  );

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    commitMutation({
      mutation: PlaybookCreationMutation,
      variables: {
        input: values,
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_playbooks',
          paginationOptions,
          'playbookAdd',
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };
  return (
    <Drawer
      title={t_i18n('Create a playbook')}
      variant={DrawerVariant.createWithPanel}
    >
      {({ onClose }) => (
        <Formik
          initialValues={{
            name: '',
            description: '',
          }}
          validationSchema={validator}
          onSubmit={(values, formikHelpers) => {
            onSubmit(values, formikHelpers);
            onClose();
          }}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                required={(mandatoryAttributes.includes('name'))}
                fullWidth={true}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t_i18n('Description')}
                required={(mandatoryAttributes.includes('description'))}
                fullWidth={true}
                style={{ marginTop: 20 }}
              />
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default PlaybookCreation;
