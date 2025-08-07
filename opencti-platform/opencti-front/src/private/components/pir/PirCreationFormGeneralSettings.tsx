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

import { Field } from 'formik';
import React from 'react';
import MenuItem from '@mui/material/MenuItem';
import MarkdownField from '../../../components/fields/MarkdownField/MarkdownField';
import { useFormatter } from '../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/fields/SelectField';

const PirCreationFormGeneralSettings = () => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field
        name="name"
        required
        component={TextField}
        variant="standard"
        label={t_i18n('Name')}
        style={fieldSpacingContainerStyle}
      />
      <Field
        component={MarkdownField}
        name="description"
        label={t_i18n('Description')}
        rows="4"
        style={fieldSpacingContainerStyle}
      />
      <Field
        component={SelectField}
        required
        variant="standard"
        name="pir_rescan_days"
        label={t_i18n('Rescan period (days)')}
        fullWidth={true}
        containerstyle={{ marginTop: 20, width: '100%' }}
        helpertext={t_i18n('Period of events on which a rescan is done to flag elements at PIR creation')}
      >
        <MenuItem value={0}>{t_i18n('No rescan')}</MenuItem>
        <MenuItem value={1}>{t_i18n('1 day')}</MenuItem>
        <MenuItem value={30}>{t_i18n('1 month')}</MenuItem>
        <MenuItem value={182}>{t_i18n('6 months')}</MenuItem>
      </Field>
    </>
  );
};

export default PirCreationFormGeneralSettings;
