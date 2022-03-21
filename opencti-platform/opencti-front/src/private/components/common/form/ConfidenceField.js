import React, { Component } from 'react';
import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';

class ConfidenceField extends Component {
  render() {
    const {
      t,
      name,
      label,
      variant,
      onChange,
      onFocus,
      containerstyle,
      editContext,
      disabled,
    } = this.props;
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
          disabled={disabled}
          containerstyle={containerstyle}
          helpertext={
            <SubscriptionFocus context={editContext} fieldName={name} />
          }
        >
          <MenuItem value="0">{t('None')}</MenuItem>
          <MenuItem value="15">{t('Low')}</MenuItem>
          <MenuItem value="50">{t('Moderate')}</MenuItem>
          <MenuItem value="75">{t('Good')}</MenuItem>
          <MenuItem value="85">{t('Strong')}</MenuItem>
        </Field>
      );
    }
    return (
      <Field
        component={SelectField}
        type="number"
        variant="standard"
        name={name}
        label={label}
        fullWidth={true}
        containerstyle={containerstyle}
      >
        <MenuItem value="0">{t('None')}</MenuItem>
        <MenuItem value="15">{t('Low')}</MenuItem>
        <MenuItem value="50">{t('Moderate')}</MenuItem>
        <MenuItem value="75">{t('Good')}</MenuItem>
        <MenuItem value="85">{t('Strong')}</MenuItem>
      </Field>
    );
  }
}

export default inject18n(ConfidenceField);
