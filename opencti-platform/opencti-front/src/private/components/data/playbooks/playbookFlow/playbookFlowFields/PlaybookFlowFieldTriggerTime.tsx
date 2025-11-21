import { MenuItem } from '@mui/material';
import { Field, useFormikContext } from 'formik';
import SelectField from '../../../../../../components/fields/SelectField';
import TimePickerField from '../../../../../../components/TimePickerField';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import { useFormatter } from '../../../../../../components/i18n';

interface TriggerTimeForm {
  period: string
}

const PlaybookFlowFieldTriggerTime = () => {
  const { t_i18n } = useFormatter();
  const { values } = useFormikContext<TriggerTimeForm>();

  return (
    <div>
      {values.period === 'week' && (
        <Field
          fullWidth
          name="day"
          variant="standard"
          component={SelectField}
          label={t_i18n('Week day')}
          containerstyle={fieldSpacingContainerStyle}
        >
          <MenuItem value="1">{t_i18n('Monday')}</MenuItem>
          <MenuItem value="2">{t_i18n('Tuesday')}</MenuItem>
          <MenuItem value="3">{t_i18n('Wednesday')}</MenuItem>
          <MenuItem value="4">{t_i18n('Thursday')}</MenuItem>
          <MenuItem value="5">{t_i18n('Friday')}</MenuItem>
          <MenuItem value="6">{t_i18n('Saturday')}</MenuItem>
          <MenuItem value="7">{t_i18n('Sunday')}</MenuItem>
        </Field>
      )}

      {values.period === 'month' && (
        <Field
          fullWidth
          name="day"
          variant="standard"
          component={SelectField}
          label={t_i18n('Month day')}
          containerstyle={fieldSpacingContainerStyle}
        >
          {Array.from(Array(31).keys()).map((idx) => (
            <MenuItem key={idx} value={(idx + 1).toString()}>
              {(idx + 1).toString()}
            </MenuItem>
          ))}
        </Field>
      )}

      {values.period !== 'minute' && values.period !== 'hour' && (
        <Field
          name="time"
          withMinutes
          component={TimePickerField}
          textFieldProps={{
            label: t_i18n('Time'),
            variant: 'standard',
            fullWidth: true,
            style: fieldSpacingContainerStyle,
          }}
        />
      )}
    </div>
  );
};

export default PlaybookFlowFieldTriggerTime;
