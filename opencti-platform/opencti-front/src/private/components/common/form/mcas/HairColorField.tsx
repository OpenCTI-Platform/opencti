import { FunctionComponent, ReactElement } from 'react';
import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import { Disposable } from 'relay-runtime';
import { useFormatter } from '../../../../../components/i18n';
import SelectField from '../../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../../components/Subscription';

export enum HairColors {
  Black = 'Black',
  Brown = 'Brown',
  Blond = 'Blond',
  Red = 'Red',
  Blue = 'Blue',
  Green = 'Green',
  Yellow = 'Yellow',
  Other = 'Other',
}

interface HairColorFieldProps {
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

const HairColorField: FunctionComponent<HairColorFieldProps> = ({
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
  const options = Object.entries(HairColors).map(
    ([key, value]) => <MenuItem id={`hair-color-${key.toLowerCase()}`} value={key} key={key}>
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

export default HairColorField;
