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
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Drawer from '../../common/drawer/Drawer';
import { useSchemaEditionValidation, useMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';

export const playbookMutationFieldPatch = graphql`
  mutation PlaybookEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    playbookFieldPatch(id: $id, input: $input) {
      ...PlaybookEdition_playbook
    }
  }
`;

const OBJECT_TYPE = 'Playbook';

const PlaybookEditionContainer = ({ handleClose, playbook, open }) => {
  const { t_i18n } = useFormatter();

  const basicShape = {
    name: Yup.string(),
    description: Yup.string().nullable(),
  };
  const mandatoryAttributes = useMandatorySchemaAttributes(OBJECT_TYPE);
  const validator = useSchemaEditionValidation(
    OBJECT_TYPE,
    basicShape,
  );

  const initialValues = R.pickAll(['name', 'description'], playbook);
  const handleSubmitField = (name, value) => {
    validator
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
    <Drawer
      title={t_i18n('Update a playbook')}
      open={open}
      onClose={handleClose}
    >
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={validator}
      >
        {() => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              required={(mandatoryAttributes.includes('name'))}
              fullWidth={true}
              onSubmit={handleSubmitField}
            />
            <Field
              component={TextField}
              variant="standard"
              name="description"
              label={t_i18n('Description')}
              required={(mandatoryAttributes.includes('description'))}
              fullWidth={true}
              style={{ marginTop: 20 }}
              onSubmit={handleSubmitField}
            />
          </Form>
        )}
      </Formik>
    </Drawer>
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
