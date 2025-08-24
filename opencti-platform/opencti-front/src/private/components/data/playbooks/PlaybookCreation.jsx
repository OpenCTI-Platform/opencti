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

import React, { useRef } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom';
import ToggleButton from '@mui/material/ToggleButton';
import { FileUploadOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import Drawer from '../../common/drawer/Drawer';
import { commitMutation, handleError } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { insertNode } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

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
      id
      ...PlaybooksLine_node
    }
  }
`;

const playbookCreationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
});

export const importMutation = graphql`
  mutation PlaybookCreationImportMutation($file: Upload!) {
    playbookImport(file: $file)
  }
`;

const PlaybookCreation = ({ paginationOptions }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const inputRef = useRef();
  const theme = useTheme();
  const [commitImportMutation] = useApiMutation(importMutation);
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
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        navigate(`${resolveLink('Playbook')}/${response.playbookAdd.id}`);
      },
    });
  };
  const handleImport = (event) => {
    const importedFile = event.target.files[0];
    commitImportMutation({
      variables: { file: importedFile },
      onCompleted: (data) => {
        inputRef.current.value = null; // Reset the input uploader ref
        navigate(
          `${resolveLink('Playbook')}/${data.playbookImport}`,
        );
      },
      onError: (error) => {
        inputRef.current.value = null; // Reset the input uploader ref
        handleError(error);
      },
    });
  };
  const CreatePlaybookControlledDial = (props) => (
    <>
      <ToggleButton
        value="import"
        size="small"
        onClick={() => inputRef.current?.click()}
        sx={{ marginLeft: theme.spacing(1) }}
        data-testid='ImporPlaybook'
        title={t_i18n('Import playbook')}
      >
        <FileUploadOutlined fontSize="small" color={'primary'} />
      </ToggleButton>
      <CreateEntityControlledDial
        entityType='Playbook'
        {...props}
      />
    </>
  );
  return (
    <>
      <VisuallyHiddenInput type="file" accept={'application/JSON'} ref={inputRef} onChange={handleImport} />
      <Drawer
        title={t_i18n('Create a playbook')}
        controlledDial={CreatePlaybookControlledDial}
      >
        {({ onClose }) => (
          <Formik
            initialValues={{
              name: '',
              description: '',
            }}
            validationSchema={playbookCreationValidation(t_i18n)}
            onSubmit={(values, formikHelpers) => {
              onSubmit(values, formikHelpers);
              onClose();
            }}
            onReset={onClose}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="description"
                  label={t_i18n('Description')}
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
    </>
  );
};

export default PlaybookCreation;
