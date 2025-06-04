import { Field, useFormikContext } from 'formik';
import React from 'react';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import MenuItem from '@mui/material/MenuItem';
import { PirCreationFormData } from '@components/pir/pir-form-utils';
import MarkdownField from '../../../components/fields/MarkdownField';
import { useFormatter } from '../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/fields/SelectField';

const PirCreationFormGeneralSettings = () => {
  const { t_i18n } = useFormatter();
  const { setFieldValue } = useFormikContext<PirCreationFormData>();

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
      <ObjectMarkingField
        name="markings"
        style={fieldSpacingContainerStyle}
        setFieldValue={setFieldValue}
      />
      <Field
        component={SelectField}
        required
        variant="standard"
        name="pir_rescan_days"
        label={t_i18n('PIR Rescan period (days)')}
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
