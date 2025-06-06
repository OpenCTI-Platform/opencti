import { FieldProps } from 'formik';
import React from 'react';
import EntitySelect, { EntityOption } from '@components/common/form/EntitySelect';

interface EntitySelectFieldProps extends FieldProps<EntityOption | null> {
  label: string
  types: string[]
  onChange?: (val: EntityOption | EntityOption[] | null) => void
  multiple?: boolean
}

const EntitySelectField = ({
  form: { setFieldValue },
  field: { value, name },
  label,
  types,
  onChange,
  multiple = false,
}: EntitySelectFieldProps) => {
  return (
    <EntitySelect
      multiple={multiple}
      value={value}
      label={label}
      types={types}
      onChange={(v) => {
        setFieldValue(name, v);
        onChange?.(v);
      }}
    />
  );
};

export default EntitySelectField;
