import { Field, useFormikContext } from 'formik';
import React from 'react';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import TextField from '../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import { useFormatter } from '../../../components/i18n';
import MarkdownField from '../../../components/fields/MarkdownField';

const PirCreationFormGeneralSettings = () => {
  const { t_i18n } = useFormatter();
  const { setFieldValue } = useFormikContext();

  return (
    <>
      <Field
        name="name"
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
    </>
  );
};

export default PirCreationFormGeneralSettings;
