import { useState } from 'react';
import { useIntl } from 'react-intl';
import { DatePicker } from '@filigran/design-system';
import type { ValueInputProps } from '../DashboardVariableValueInput';

const toDate = (value: string) => (value ? new Date(value) : null);

/**
 * Date value, emitted as an ISO string. As in `FilterDate`, a typed date is committed on accept (a day picked in the
 * calendar, Enter, blur), never on each keystroke: the typed date is only a draft until then.
 */
const DateValueInput = ({ value, onChange, disabled, label, commitOn }: ValueInputProps) => {
  const { locale } = useIntl();
  const [date, setDate] = useState<Date | null>(toDate(value));
  const [received, setReceived] = useState(value);
  if (value !== received) {
    setReceived(value);
    setDate(toDate(value));
  }

  const commit = (next: Date | null) => {
    if (next === null) {
      // A cleared date: a form takes it as no value, a live filter (the chips) has no such thing as an empty value.
      if (commitOn === 'change' && value !== '') onChange('');
    } else if (!Number.isNaN(next.getTime()) && next.toISOString() !== value) {
      onChange(next.toISOString());
    }
  };

  return (
    <DatePicker
      label={label}
      locale={locale}
      value={date}
      disabled={disabled}
      onChange={setDate}
      onAccept={commit}
    />
  );
};

export default DateValueInput;
