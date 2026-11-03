import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import { styled } from '@mui/material/styles';
import ComboboxField from '../../../../components/ComboboxField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import useAuth from '../../../../utils/hooks/useAuth';

const OptionIcon = styled('div')(({ theme }) => ({
  paddingTop: 4,
  paddingRight: 4,
  display: 'inline-block',
  color: theme.palette.primary.main,
}));

interface ObservableTypesFieldProps {
  name: string;
  label: string;
  multiple?: boolean;
  onChange?: (name: string, value: string | string[]) => void;
  style?: Record<string, string | number>;
  disabled?: boolean;
  required?: boolean;
}
const ObservableTypesField: FunctionComponent<ObservableTypesFieldProps> = ({
  name,
  label,
  multiple,
  onChange,
  style,
  disabled,
  required = false,
}) => {
  const { t_i18n } = useFormatter();

  const { schema } = useAuth();
  const { scos } = schema;
  const allObservableTypes = scos.map((sco) => sco.id);

  return (
    <Field
      component={ComboboxField}
      name={name}
      multiple={multiple || false}
      disabled={disabled}
      label={label}
      required={required}
      options={allObservableTypes}
      getOptionLabel={(option: string) => t_i18n(`entity_${option}`)}
      onChange={typeof onChange === 'function' ? onChange : null}
      isOptionEqualToValue={(option: string, value: string) => option === value}
      style={style}
      renderOption={(option: string) => (
        <>
          <OptionIcon>
            <ItemIcon type={option} />
          </OptionIcon>
          <span>{t_i18n(`entity_${option}`)}</span>
        </>
      )}
    />
  );
};

export default ObservableTypesField;
