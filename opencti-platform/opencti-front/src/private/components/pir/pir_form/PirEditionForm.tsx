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

import * as Yup from 'yup';
import { Field, Form, Formik } from 'formik';
import React from 'react';
import { PirEditionFormData } from './pir-form-utils';
import { useFormatter } from '../../../../components/i18n';
import { PirEditionFragment$data } from './__generated__/PirEditionFragment.graphql';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

export type PirEditionFormInputKeys = keyof PirEditionFormData;

interface PirEditionFormProps {
  onSubmitField: (field: PirEditionFormInputKeys, value: unknown) => void
  pir: PirEditionFragment$data
}

const PirEditionForm = ({ onSubmitField, pir }: PirEditionFormProps) => {
  const { t_i18n } = useFormatter();

  const validation = Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
  });

  const initialValues: PirEditionFormData = {
    name: pir.name,
    description: pir.description ?? '',
  };

  const updateField = async (field: PirEditionFormInputKeys, value: unknown) => {
    validation.validateAt(field, { [field]: value })
      .then(() => onSubmitField(field, value))
      .catch(() => false);
  };

  return (
    <Formik<PirEditionFormData>
      enableReinitialize
      validationSchema={validation}
      initialValues={initialValues}
      onSubmit={() => {}}
    >
      {() => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            required
            onSubmit={updateField}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            style={fieldSpacingContainerStyle}
            multiline
            rows="4"
            onSubmit={updateField}
          />
        </Form>
      )}
    </Formik>
  );
};

export default PirEditionForm;
