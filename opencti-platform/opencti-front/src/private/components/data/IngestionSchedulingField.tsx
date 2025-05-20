import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import React from 'react';
import SelectField from '../../../components/fields/SelectField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../utils/field';
import { useFormatter } from '../../../components/i18n';

interface IngestionSchedulingProps {
  handleSubmitField?: (name: string, value: FieldOption[]) => void | null;
}

const IngestionSchedulingField = ({ handleSubmitField }: IngestionSchedulingProps) => {
  const { t_i18n } = useFormatter();
  return <Field component={SelectField}
    variant="standard"
    name="scheduling_period"
    label={t_i18n('Schedule period')}
    fullWidth={true}
    onChange={handleSubmitField}
    containerstyle={fieldSpacingContainerStyle}
         >
    <MenuItem value="auto">{t_i18n('Platform default')} ({t_i18n('around 30 secs')})</MenuItem>
    <MenuItem value="PT5M">{t_i18n('5 minutes')}</MenuItem>
    <MenuItem value="PT15M">{t_i18n('15 minutes')}</MenuItem>
    <MenuItem value="PT30M">{t_i18n('30 minutes')}</MenuItem>
    <MenuItem value="PT1H">{t_i18n('1 hour')}</MenuItem>
    <MenuItem value="PT6H">{t_i18n('6 hours')}</MenuItem>
    <MenuItem value="PT12H">{t_i18n('12 hours')}</MenuItem>
    <MenuItem value="PT1D">{t_i18n('24 hours')}</MenuItem>
  </Field>;
};

export default IngestionSchedulingField;
