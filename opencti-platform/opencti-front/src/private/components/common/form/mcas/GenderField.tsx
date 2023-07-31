import { FunctionComponent, ReactElement } from 'react';
import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import { Disposable } from 'relay-runtime';
import SelectField from '../../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../../components/Subscription';
import { useFormatter } from '../../../../../components/i18n';

export enum Genders {
  Male = 'Male',
  Female = 'Female',
  Nonbinary = 'Nonbinary',
  Other = 'Other',
}

interface GenderFieldProps {
  name: string,
  label: string,
  variant: string,
  onChange: (name: string, value: string) => void,
  onFocus?: (name: string) => Disposable,
  containerStyle: {
    marginTop: number;
    width: string;
  },
  editContext: readonly {
    readonly focusOn: string | null;
    readonly name: string;
  }[] | null,
  disabled?: boolean,
}

const GenderField: FunctionComponent<GenderFieldProps> = ({
  name,
  label,
  variant,
  onChange,
  onFocus,
  containerStyle,
  editContext,
  disabled = false,
}): ReactElement => {
  const { t } = useFormatter();
  const options = Object.entries(Genders).map(
    ([key, value]) => <MenuItem id={key} value={key} key={key}>
        {t(value)}
      </MenuItem>,
  );

  return variant === 'edit'
    ? <Field
        component={SelectField}
        variant='standard'
        name={name}
        onFocus={onFocus}
        onChange={onChange}
        label={t(label)}
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
        label={t(label)}
        fullWidth={true}
        containerstyle={containerStyle}
      >
        {options}
      </Field>;
};

export default GenderField;
