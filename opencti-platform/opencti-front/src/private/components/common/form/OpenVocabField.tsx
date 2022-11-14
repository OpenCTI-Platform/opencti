import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { openVocabularies } from '../../../../utils/Entity';
import { Option } from './ReferenceField';

interface OpenVocabProps {
  type: string,
  name: string
  label: string
  variant?: string
  onChange?: (name: string, value: Option) => void,
  onFocus?: (name: string, value: Option) => void,
  multiple: boolean
  containerStyle: Record<string, string | number>
  editContext?: unknown
}

const OpenVocabField: FunctionComponent<OpenVocabProps> = ({
  type,
  name,
  label,
  variant,
  onChange,
  onFocus,
  multiple,
  containerStyle,
  editContext,
}) => {
  const { t } = useFormatter();
  const openVocabList = openVocabularies[type];
  if (variant === 'edit') {
    return (
        <Field component={SelectField}
          variant="standard"
          name={name}
          label={label}
          onFocus={onFocus}
          onChange={onChange}
          fullWidth={true}
          multiple={multiple}
          containerstyle={containerStyle}
          helpertext={<SubscriptionFocus context={editContext} fieldName={name} />}>
          {openVocabList.map((openVocab) => (
            <MenuItem key={openVocab.key} value={openVocab.key}>
              {t(openVocab.key)}
            </MenuItem>
          ))}
        </Field>
    );
  }
  return (
      <Field component={SelectField}
        variant="standard"
        name={name}
        label={label}
        fullWidth={true}
        multiple={multiple}
        containerstyle={containerStyle}>
        {openVocabList.map((openVocab) => (
          <MenuItem key={openVocab.key} value={openVocab.key}>
            {t(openVocab.key)}
          </MenuItem>
        ))}
      </Field>
  );
};

export default OpenVocabField;
