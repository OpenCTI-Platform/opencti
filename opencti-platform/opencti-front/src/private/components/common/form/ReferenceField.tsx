import { Field } from 'formik';
import React, { FunctionComponent, ReactElement } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import type { ComboboxChangeMeta } from '@filigran/design-system';
import ComboboxField from '../../../../components/ComboboxField';
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
      component={ComboboxField}
      style={fieldSpacingContainerStyle}
      name={name}
      label={t_i18n(label)}
      helperText={helperText}
      onFocusInput={onFocus}
      noOptionsText={t_i18n(noOptionsText)}
      options={options}
      // This used to forward `InputEvent.data` — the ONE character just typed, not the
      // accumulated text — so ArtifactField's setSearch always held a single letter.
      onInputChange={(search: string, meta: ComboboxChangeMeta) => {
        if (meta.cause === 'type') onInputChange(search || null);
      }}
      value={value}
      onChange={onChange}
      renderOption={(option: FieldOption) => (
        <>
          <div className={classes.icon} style={{ color: option.color }}>
            <ItemIcon type={option.type} />
          </div>
          <div className={classes.text}>{option.label}</div>
        </>
      )}
    />
  );
};

export default ReferenceField;
