import { Field } from 'formik';
import React, { FunctionComponent, ReactElement, ReactNode } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ItemIcon from '../../../../components/ItemIcon';

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

export interface Option {
  value: string;
  label: string;
  color?: string;
  [key: string]: ReactNode;
  type?: string;
}

interface RelationFieldProps {
  name: string;
  label: string;
  variant?: string;
  helperText?: string;
  onFocus: () => void;
  noOptionsText?: string;
  options: Option[];
  onChange: (name: string, value: Option) => void;
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
  const { t } = useFormatter();
  return (
    <Field
      component={AutocompleteField}
      style={fieldSpacingContainerStyle}
      name={name}
      textfieldprops={{
        variant,
        label: t(label),
        helperText,
        onFocus,
      }}
      noOptionsText={t(noOptionsText)}
      options={options}
      onInputChange={(v: InputEvent) => onInputChange(v?.data ?? null)}
      value={value}
      onChange={onChange}
      renderOption={(props: Record<string, unknown>, option: Option) => (
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
