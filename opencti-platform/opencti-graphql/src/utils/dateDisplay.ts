import { DateFormat, type EditInput, TimeFormat } from '../generated/graphql';
import { UnsupportedError } from '../config/errors';

const checkSingleValue = (input: EditInput | undefined, allowedValues: string[], reason: string) => {
  if (!input) return;
  const { value } = input;
  if (!Array.isArray(value) || value.length !== 1 || !allowedValues.includes(value[0])) {
    throw UnsupportedError(reason, { key: input.key, value, allowedValues });
  }
};

/**
 * Rejects a date or time format the tables cannot display, for the platform settings or a user.
 */
export const checkDateDisplayInput = (inputs: EditInput[], dateFormatKey: string, timeFormatKey: string) => {
  for (const input of inputs) {
    if (input.key === dateFormatKey) checkSingleValue(input, Object.values(DateFormat), 'Unsupported date format');
    if (input.key === timeFormatKey) checkSingleValue(input, Object.values(TimeFormat), 'Unsupported time format');
  }
};
