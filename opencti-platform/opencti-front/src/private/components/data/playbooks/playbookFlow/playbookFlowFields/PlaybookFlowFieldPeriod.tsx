import { MenuItem } from '@mui/material';
import { Field } from 'formik';
import SelectField from '../../../../../../components/fields/SelectField';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import { useFormatter } from '../../../../../../components/i18n';

const PlaybookFlowFieldPeriod = () => {
  const { t_i18n } = useFormatter();

  return (
    <Field
      fullWidth
      component={SelectField}
      variant="standard"
      name="period"
      label={t_i18n('Period')}
      containerstyle={fieldSpacingContainerStyle}
    >
      <MenuItem value="hour">{t_i18n('hour')}</MenuItem>
      <MenuItem value="day">{t_i18n('day')}</MenuItem>
      <MenuItem value="week">{t_i18n('week')}</MenuItem>
      <MenuItem value="month">{t_i18n('month')}</MenuItem>
    </Field>
  );
};

export default PlaybookFlowFieldPeriod;
