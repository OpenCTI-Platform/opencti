import { Field } from 'formik';
import React from 'react';
import SelectFieldFds, { SelectItem } from '../../../components/fields/SelectFieldFds';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import { useFormatter } from '../../../components/i18n';

interface IngestionSchedulingProps {
  handleSubmitField?: (name: string, value: string) => void;
}

const IngestionSchedulingField = ({ handleSubmitField }: IngestionSchedulingProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Field
      component={SelectFieldFds}
      variant="outlined"
      name="scheduling_period"
      label={t_i18n('Schedule period')}
      fullWidth={true}
      onChange={handleSubmitField}
      containerstyle={fieldSpacingContainerStyle}
    >
      <SelectItem value="auto">{t_i18n('Platform default')} ({t_i18n('around 30 secs')})</SelectItem>
      <SelectItem value="PT5M">{t_i18n('5 minutes')}</SelectItem>
      <SelectItem value="PT15M">{t_i18n('15 minutes')}</SelectItem>
      <SelectItem value="PT30M">{t_i18n('30 minutes')}</SelectItem>
      <SelectItem value="PT1H">{t_i18n('1 hour')}</SelectItem>
      <SelectItem value="PT6H">{t_i18n('6 hours')}</SelectItem>
      <SelectItem value="PT12H">{t_i18n('12 hours')}</SelectItem>
      <SelectItem value="PT1D">{t_i18n('24 hours')}</SelectItem>
    </Field>
  );
};

export default IngestionSchedulingField;
