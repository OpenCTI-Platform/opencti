import React, { Component } from 'react';
import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { openVocabularies } from '../../../../utils/Entity';

class OpenVocabField extends Component {
  render() {
    const {
      t,
      type,
      name,
      label,
      variant,
      onChange,
      onFocus,
      multiple,
      containerstyle,
      editContext,
    } = this.props;
    const openVocabList = openVocabularies[type];
    if (variant === 'edit') {
      return (
        <Field
          component={SelectField}
          variant="standard"
          name={name}
          onFocus={onFocus}
          onChange={onChange}
          label={label}
          fullWidth={true}
          multiple={multiple}
          containerstyle={containerstyle}
          helpertext={
            <SubscriptionFocus context={editContext} fieldName={name} />
          }
        >
          {openVocabList.map((openVocab) => (
            <MenuItem key={openVocab.key} value={openVocab.key}>
              {t(openVocab.key)}
            </MenuItem>
          ))}
        </Field>
      );
    }
    return (
      <Field
        component={SelectField}
        variant="standard"
        name={name}
        label={label}
        fullWidth={true}
        multiple={multiple}
        containerstyle={containerstyle}
      >
        {openVocabList.map((openVocab) => (
          <MenuItem key={openVocab.key} value={openVocab.key}>
            {t(openVocab.key)}
          </MenuItem>
        ))}
      </Field>
    );
  }
}

export default inject18n(OpenVocabField);
