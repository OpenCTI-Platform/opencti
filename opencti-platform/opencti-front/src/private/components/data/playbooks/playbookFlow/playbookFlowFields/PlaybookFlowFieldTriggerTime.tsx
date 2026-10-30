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

import { Field, useFormikContext } from 'formik';
import SelectFieldFds, { SelectItem } from '../../../../../../components/fields/SelectFieldFds';
import TimePickerField from '../../../../../../components/TimePickerField';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import { useFormatter } from '../../../../../../components/i18n';

interface TriggerTimeForm {
  period: string;
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
          variant="outlined"
          component={SelectFieldFds}
          label={t_i18n('Week day')}
          containerstyle={fieldSpacingContainerStyle}
        >
          <SelectItem value="1">{t_i18n('Monday')}</SelectItem>
          <SelectItem value="2">{t_i18n('Tuesday')}</SelectItem>
          <SelectItem value="3">{t_i18n('Wednesday')}</SelectItem>
          <SelectItem value="4">{t_i18n('Thursday')}</SelectItem>
          <SelectItem value="5">{t_i18n('Friday')}</SelectItem>
          <SelectItem value="6">{t_i18n('Saturday')}</SelectItem>
          <SelectItem value="7">{t_i18n('Sunday')}</SelectItem>
        </Field>
      )}

      {values.period === 'month' && (
        <Field
          fullWidth
          name="day"
          variant="outlined"
          component={SelectFieldFds}
          label={t_i18n('Month day')}
          containerstyle={fieldSpacingContainerStyle}
        >
          {Array.from(Array(31).keys()).map((idx) => (
            <SelectItem key={idx} value={(idx + 1).toString()}>
              {(idx + 1).toString()}
            </SelectItem>
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
            variant: 'outlined',
            fullWidth: true,
            style: fieldSpacingContainerStyle,
          }}
        />
      )}
    </div>
  );
};

export default PlaybookFlowFieldTriggerTime;
