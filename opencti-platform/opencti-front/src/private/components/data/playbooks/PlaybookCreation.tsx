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

import React, { InputHTMLAttributes, useRef } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import ToggleButton from '@mui/material/ToggleButton';
import { FileUploadOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import { FormikConfig } from 'formik/dist/types';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import Drawer, { DrawerControlledDialType } from '../../common/drawer/Drawer';
import { handleError } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { PlaybookCreationImportMutation } from './__generated__/PlaybookCreationImportMutation.graphql';
import { PlaybookCreationMutation } from './__generated__/PlaybookCreationMutation.graphql';
import type { Theme } from '../../../../components/Theme';

const playbookCreationMutation = graphql`
  mutation PlaybookCreationMutation($input: PlaybookAddInput!) {
    playbookAdd(input: $input) {
      id
      ...PlaybooksLine_node
    }
  }
`;

const playbookImportMutation = graphql`
  mutation PlaybookCreationImportMutation($file: Upload!) {
    playbookImport(file: $file)
  }
`;

interface PlaybookCreationForm {
  name: string;
  description: string;
}

const PlaybookCreation = () => {
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const inputRef = useRef<HTMLInputElement>(null);

  const [importMutation] = useApiMutation<PlaybookCreationImportMutation>(playbookImportMutation);
  const [createMutation] = useApiMutation<PlaybookCreationMutation>(playbookCreationMutation);

  const playbookCreationValidation = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
  });
  const initialValues = {
    name: '',
    description: '',
  };

  const onSubmit: FormikConfig<PlaybookCreationForm>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    setSubmitting(true);
    createMutation({
      variables: { input: values },
      onCompleted: (response) => {
        resetForm();
        setSubmitting(false);
        if (response.playbookAdd) {
          navigate(`${resolveLink('Playbook')}/${response.playbookAdd.id}`);
        }
      },
    });
  };

  const handleImport: InputHTMLAttributes<HTMLInputElement>['onChange'] = (event) => {
    const importedFile = event.target?.files?.[0];
    if (importedFile) {
      importMutation({
        variables: { file: importedFile },
        onError: handleError,
        onCompleted: (data) => {
          navigate(`${resolveLink('Playbook')}/${data.playbookImport}`);
        },
      });
    }
    if (inputRef.current) {
      // Reset the input uploader ref
      inputRef.current.value = '';
    }
  };

  const CreatePlaybookControlledDial: DrawerControlledDialType = (props) => (
    <>
      <ToggleButton
        value="import"
        size="small"
        onClick={() => inputRef.current?.click()}
        sx={{ marginLeft: theme.spacing(1) }}
        data-testid="ImporPlaybook"
        title={t_i18n('Import playbook')}
      >
        <FileUploadOutlined fontSize="small" color="primary" />
      </ToggleButton>
      <CreateEntityControlledDial
        entityType="Playbook"
        {...props}
      />
    </>
  );

  return (
    <>
      <VisuallyHiddenInput
        ref={inputRef}
        type="file"
        accept="application/JSON"
        onChange={handleImport}
      />
      <Drawer
        title={t_i18n('Create a playbook')}
        controlledDial={CreatePlaybookControlledDial}
      >
        {({ onClose }) => (
          <Formik<PlaybookCreationForm>
            initialValues={initialValues}
            validationSchema={playbookCreationValidation}
            onReset={onClose}
            onSubmit={(values, formikHelpers) => {
              onSubmit(values, formikHelpers);
              onClose();
            }}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="description"
                  label={t_i18n('Description')}
                  style={fieldSpacingContainerStyle}
                  fullWidth
                />
                <div style={{
                  ...fieldSpacingContainerStyle,
                  display: 'flex',
                  justifyContent: 'end',
                  gap: theme.spacing(2),
                }}
                >
                  <Button
                    onClick={handleReset}
                    disabled={isSubmitting}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
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
