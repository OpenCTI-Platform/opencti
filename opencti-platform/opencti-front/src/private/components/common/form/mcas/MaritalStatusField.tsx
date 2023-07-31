import { FunctionComponent, ReactElement } from 'react';
import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import { Disposable } from 'relay-runtime';
import { useFormatter } from '../../../../../components/i18n';
import SelectField from '../../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../../components/Subscription';

export enum MaritalStatus {
  Annulled = 'Annulled',
  Divorced = 'Divorced',
  DomesticPartner = 'Domestic Partner',
  LegallySeparated = 'Legally Separated',
  Separated = 'Separated',
  Married = 'Married',
  Polygamous = 'Polygamous',
  Single = 'Single',
  Widowed = 'Widowed',
  Other = 'Other',
}

interface MaritalStatusFieldProps {
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

const MaritalStatusField: FunctionComponent<MaritalStatusFieldProps> = ({
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
  const options = Object.entries(MaritalStatus).map(
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

export default MaritalStatusField;
