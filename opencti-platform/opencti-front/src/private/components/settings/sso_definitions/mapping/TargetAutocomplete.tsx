import { Field } from 'formik';
import AutocompleteField from 'src/components/AutocompleteField';
import React from 'react';
import ItemIcon from 'src/components/ItemIcon';
import { useFormatter } from 'src/components/i18n';

type TargetAutocompleteProps = {
  fieldName: string;
  handleChange: (_: React.SyntheticEvent, value: string) => void;
  itemIcon: string;
  label: string;
  options: string[];
};

const TargetAutocomplete = ({
  fieldName,
  handleChange,
  itemIcon,
  label,
  options,
}: TargetAutocompleteProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Field
      component={AutocompleteField}
      freeSolo
      preserveCase
      name={fieldName}
      textfieldprops={{
        variant: 'standard',
        label: label,
      }}
      noOptionsText={t_i18n('No available options')}
      options={options}
      onInputChange={handleChange}
      renderOption={(renderProps: React.HTMLAttributes<HTMLLIElement>, option: string) => {
        return (
          <li {...renderProps}>
            <div style={{ paddingTop: 4, display: 'inline-block' }}>
              <ItemIcon type={itemIcon} />
            </div>
            <div style={{ display: 'inline-block', flexGrow: 1, marginLeft: 10 }}>{option}</div>
          </li>
        );
      }}
    />
  );
};

export default TargetAutocomplete;
