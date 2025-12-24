import { ControlProps, rankWith, schemaMatches } from '@jsonforms/core';
import { withJsonFormsControlProps } from '@jsonforms/react';
import { DateTimePicker } from '@mui/x-date-pickers';

export const JsonFormTimestampRendererBase = (props: ControlProps) => {
  const { data, handleChange, path, schema } = props;

  const label =
    schema?.title || (path ? path.split('/').pop()?.replace(/_/g, ' ') : 'Unknown');
  const description = schema?.description;

  const numericData = data ? Number(data) : undefined;
  const date = numericData !== undefined ? new Date(numericData) : null;

  return (
    <DateTimePicker
      label={label}
      value={date}
      onChange={(date) => handleChange(path, date ? date.getTime() : null)}
      slotProps={{
        textField: { helperText: description, fullWidth: true },
      }}
    />
  );
};

export const jsonFormTimestampTester = rankWith(
  100,
  schemaMatches((schema) => {
    return schema?.type === 'integer' && schema?.format === 'date-time';
  })
);

export default withJsonFormsControlProps(JsonFormTimestampRendererBase);
