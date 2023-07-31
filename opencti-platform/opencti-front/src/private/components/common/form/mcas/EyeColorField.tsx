import { FunctionComponent, ReactElement } from 'react';
import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import { Disposable } from 'relay-runtime';
import { useFormatter } from '../../../../../components/i18n';
import SelectField from '../../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../../components/Subscription';

export enum EyeColors {
  Black = 'Black',
  Brown = 'Brown',
  Green = 'Green',
  Blue = 'Blue',
  Other = 'Other',
}

interface EyeColorFieldProps {
  name: string,
  label: string,
  variant: string,
  onChange: (name: string, value: string) => void,
  onFocus?: (name: string) => Disposable,
  containerStyle: {
    marginTop: number;
    width: string;
  },
  editContext?: readonly {
    readonly focusOn: string | null;
    readonly name: string;
  }[] | null,
  disabled?: boolean,
}

const EyeColorField: FunctionComponent<EyeColorFieldProps> = ({
  name,
  label,
  variant,
  onChange,
  onFocus,
  containerStyle,
  editContext = [],
  disabled = false,
}): ReactElement => {
  const { t } = useFormatter();
  const options = Object.entries(EyeColors).map(
    ([key, value]) => <MenuItem id={`eye-color-${key.toLowerCase()}`} value={key} key={key}>
      {t(value)}
    </MenuItem>,
  );

  return variant === 'edit'
    ? <Field
        component={SelectField}
        variant="standard"
        name={name}
        onFocus={onFocus}
        onChange={onChange}
        label={label}
        fullWidth={true}
        disabled={disabled}
        containerstyle={containerStyle}
        helpertext={
          <SubscriptionFocus context={editContext} fieldName={name} />
        }
      >
        {options}
      </Field>
    : <Field
        component={SelectField}
        type="string"
        variant="standard"
        name={name}
        label={label}
        fullWidth={true}
        containerstyle={containerStyle}
      >
        {options}
      </Field>;
};

export default EyeColorField;
