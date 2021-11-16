/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';

class AssetType extends Component {
  render() {
    const {
      t,
      name,
      size,
      label,
      style,
      variant,
      onChange,
      onFocus,
      containerstyle,
      editContext,
      disabled,
      helperText,
    } = this.props;
    return (
      <Field
        component={SelectField}
        name={name}
        label={label}
        fullWidth={true}
        containerstyle={containerstyle}
        variant={variant}
        disabled={disabled || false}
        size={size}
        style={style}
        helperText={helperText}
      >
        <MenuItem key="physical-devices" value="physical-devices">
           {t('Physical Device')}
        </MenuItem>
        <MenuItem key="network" value="network">
            {t('Network')}
        </MenuItem>
        <MenuItem key="software" value="software">
            {t('Software')}
        </MenuItem>
      </Field>
    );
  }
}

export default inject18n(AssetType);
