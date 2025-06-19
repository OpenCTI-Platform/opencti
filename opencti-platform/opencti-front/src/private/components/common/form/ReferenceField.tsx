import { Field } from 'formik';
import React, { FunctionComponent, ReactElement } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import ItemIcon from '../../../../components/ItemIcon';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
}));

interface RelationFieldProps {
  name: string;
  label: string;
  variant?: string;
  helperText?: string;
  onFocus: () => void;
  noOptionsText?: string;
  options: FieldOption[];
  onChange: (name: string, value: FieldOption) => void;
  onInputChange: (v: string | null) => void;
  value: unknown;
}

const ReferenceField: FunctionComponent<RelationFieldProps> = ({
  name,
  label,
  variant = 'standard',
  helperText,
  onFocus,
  noOptionsText = 'No available options',
  options,
  onChange,
  onInputChange,
  value,
}): ReactElement => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  return (
    <Field
      component={AutocompleteField}
      style={fieldSpacingContainerStyle}
      name={name}
      textfieldprops={{
        variant,
        label: t_i18n(label),
        helperText,
        onFocus,
      }}
      noOptionsText={t_i18n(noOptionsText)}
      options={options}
      onInputChange={(v: InputEvent) => onInputChange(v?.data ?? null)}
      value={value}
      onChange={onChange}
      renderOption={(props: Record<string, unknown>, option: FieldOption) => (
        <li {...props}>
          <div className={classes.icon} style={{ color: option.color }}>
            <ItemIcon type={option.type} />
          </div>
          <div className={classes.text}>{option.label}</div>
        </li>
      )}
    />
  );
};

export default ReferenceField;
