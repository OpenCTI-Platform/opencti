/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import ItemIcon from '../../../../components/ItemIcon';

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
        <MenuItem key="physical_device" value="physical_device">
          <ItemIcon variant='inline' type='physical_device' />&nbsp;{t(' Physical Device')}
        </MenuItem>
        <MenuItem key="appliance" value="appliance">
          <ItemIcon variant='inline' type='appliance' />&nbsp;{t('Appliance')}
        </MenuItem>
        <MenuItem key="storage_array" value="storage_array">
          <ItemIcon variant='inline' type='storage_array' />&nbsp;{t('Storage Array')}
        </MenuItem>
        <MenuItem key="firewall" value="firewall">
          <ItemIcon variant='inline' type='firewall' />&nbsp;{t('Firewall')}
        </MenuItem>
        <MenuItem key="network" value="network">
          <ItemIcon variant='inline' type='network' />&nbsp;&nbsp;{t('Network')}
        </MenuItem>
        <MenuItem key="network_device" value="network_device">
          <ItemIcon variant='inline' type='network_device' />&nbsp;{t('Network Device')}
        </MenuItem>
        <MenuItem key="router" value="router">
          <ItemIcon variant='inline' type='router' />&nbsp;{t('Router')}
        </MenuItem>
        <MenuItem key="server" value="server">
          <ItemIcon variant='inline' type='server' />&nbsp;{t('Server')}
        </MenuItem>
        <MenuItem key="software" value="software">
          <ItemIcon variant='inline' type='software' />&nbsp;&nbsp;{t('Software')}
        </MenuItem>
        <MenuItem key="workstation" value="workstation">
          <ItemIcon variant='inline' type='workstation' />&nbsp;{t('Workstation')}
        </MenuItem>
        <MenuItem key="voip_handset" value="voip_handset">
          <ItemIcon variant='inline' type='voip_handset' />&nbsp;{t('VoIP Handset')}
        </MenuItem>
        <MenuItem key="pbx" value="pbx">
          <ItemIcon variant='inline' type='pbx' />&nbsp;{t('PBX')}
        </MenuItem>
        <MenuItem key="compute_device" value="compute_device">
          <ItemIcon variant='inline' type='compute_device' />&nbsp;{t('Compute Device')}
        </MenuItem>
        <MenuItem key="voip_router" value="voip_router">
          <ItemIcon variant='inline' type='voip_router' />&nbsp;{t('VoIP Router')}
        </MenuItem>
        <MenuItem key="switch" value="switch">
          <ItemIcon variant='inline' type='switch' />&nbsp;{t('Switch')}
        </MenuItem>
      </Field>
    );
  }
}

export default inject18n(AssetType);
