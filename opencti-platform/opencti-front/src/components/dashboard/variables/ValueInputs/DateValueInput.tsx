import { useState } from 'react';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import type { ValueInputProps } from '../DashboardVariableValueInput';

const toDate = (value: string) => (value ? new Date(value) : null);

/**
 * Date value, emitted as an ISO string. As in `FilterDate`, a typed date is committed on accept, Enter or blur,
 * never on each keystroke.
 */
const DateValueInput = ({ value, onChange, disabled, label, commitOn }: ValueInputProps) => {
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
      value={date}
      disabled={disabled}
      onChange={setDate}
      onAccept={commit}
      slotProps={{
        textField: {
          size: 'small',
          variant: 'outlined',
          fullWidth: true,
          onKeyDown: (event) => {
            if (event.key === 'Enter') commit(date);
          },
          onBlur: () => commit(date),
        },
      }}
    />
  );
};

export default DateValueInput;
