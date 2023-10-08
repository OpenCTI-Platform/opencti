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

import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';

const useStyles = makeStyles((theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 0px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

export const playbookMutationFieldPatch = graphql`
  mutation PlaybookEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    playbookFieldPatch(id: $id, input: $input) {
      ...PlaybookEdition_playbook
    }
  }
`;

const playbookValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
});

const PlaybookEditionContainer = ({ handleClose, playbook }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const initialValues = R.pickAll(['name', 'description'], playbook);
  const handleSubmitField = (name, value) => {
    playbookValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: playbookMutationFieldPatch,
          variables: {
            id: playbook.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  };
  return (
    <>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6">{t('Update a playbook')}</Typography>
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={playbookValidation(t)}
        >
          {() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth={true}
                onSubmit={handleSubmitField}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t('Description')}
                fullWidth={true}
                style={{ marginTop: 20 }}
                onSubmit={handleSubmitField}
              />
            </Form>
          )}
        </Formik>
      </div>
    </>
  );
};

const PlaybookEditionFragment = createFragmentContainer(
  PlaybookEditionContainer,
  {
    playbook: graphql`
      fragment PlaybookEdition_playbook on Playbook {
        id
        name
        description
        playbook_running
        playbook_definition
      }
    `,
  },
);

export default PlaybookEditionFragment;
