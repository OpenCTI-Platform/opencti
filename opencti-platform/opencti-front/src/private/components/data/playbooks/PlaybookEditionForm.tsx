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

import React from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { PlaybookEditionFormQuery } from '@components/data/playbooks/__generated__/PlaybookEditionFormQuery.graphql';
import { FormikConfig } from 'formik/dist/types';
import { PlaybookEditionForm_playbook$key } from '@components/data/playbooks/__generated__/PlaybookEditionForm_playbook.graphql';
import { Stack } from '@mui/material';
import PlaybookDeletion from '@components/data/playbooks/PlaybookDeletion';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const playbookEditionFormQuery = graphql`
  query PlaybookEditionFormQuery($id: String!) {
    playbook(id: $id) {
      id
      ...PlaybookEditionForm_playbook
    }
  }
`;

const playbookEditionFragment = graphql`
  fragment PlaybookEditionForm_playbook on Playbook {
    id
    name
    description
    playbook_running
    playbook_definition
  }
`;

export const playbookMutationFieldPatch = graphql`
  mutation PlaybookEditionFormFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    playbookFieldPatch(id: $id, input: $input) {
      ...PlaybookEditionForm_playbook
    }
  }
`;

interface PlaybookEditionFormData {
  name: string
  description: string | null | undefined
}

const PlaybookEditionForm = ({ queryRef }: { queryRef: PreloadedQuery<PlaybookEditionFormQuery> }) => {
  const { playbook } = usePreloadedQuery<PlaybookEditionFormQuery>(playbookEditionFormQuery, queryRef);
  const playbookData = useFragment<PlaybookEditionForm_playbook$key>(playbookEditionFragment, playbook);
  if (!playbookData) return <div/>;

  const { t_i18n } = useFormatter();
  const initialValues: PlaybookEditionFormData = {
    name: playbookData.name,
    description: playbookData.description,
  };

  const playbookValidation = () => Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
  });

  const [commitUpdate] = useApiMutation(playbookMutationFieldPatch);

  const handleSubmitField = (name: string, value: string) => {
    playbookValidation()
      .validateAt(name, { [name]: value })
      .then(() => {
        commitUpdate({
          variables: {
            id: playbookData.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  };
  const onSubmit: FormikConfig<PlaybookEditionFormData>['onSubmit'] = () => {};

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={playbookValidation()}
      onSubmit={onSubmit}
    >
      {() => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onSubmit={handleSubmitField}
          />
          <Field
            component={TextField}
            variant="standard"
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onSubmit={handleSubmitField}
          />
          <Stack flexDirection="row" justifyContent="flex-end" gap={2}>
            <PlaybookDeletion
              id={playbookData.id}
            />
          </Stack>
        </Form>
      )}
    </Formik>
  );
};

export default PlaybookEditionForm;
