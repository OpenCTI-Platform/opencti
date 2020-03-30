import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field } from 'formik';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../components/i18n';
import SelectField from '../../../components/SelectField';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class TypesField extends Component {
  render() {
    const {
      t, name, label, containerstyle,
    } = this.props;
    return (
      <Field
        component={SelectField}
        name={name}
        label={label}
        fullWidth={true}
        containerstyle={containerstyle}
      >
        <MenuItem value="Autonomous-System">{t('Autonomous system')}</MenuItem>
        <MenuItem value="Directory">{t('Directory')}</MenuItem>
        <MenuItem value="Domain">{t('Domain')}</MenuItem>
        <MenuItem value="Email-Address">{t('Email address')}</MenuItem>
        <MenuItem value="Email-Subject">{t('Email subject')}</MenuItem>
        <MenuItem value="File-Name">{t('File name')}</MenuItem>
        <MenuItem value="File-Path">{t('File path')}</MenuItem>
        <MenuItem value="File-MD5">{t('File MD5 hash')}</MenuItem>
        <MenuItem value="File-SHA1">{t('File SHA1 hash')}</MenuItem>
        <MenuItem value="File-SHA256">{t('File SHA256 hash')}</MenuItem>
        <MenuItem value="IPv4-Addr">{t('IPv4 address')}</MenuItem>
        <MenuItem value="IPv6-Addr">{t('IPv6 address')}</MenuItem>
        <MenuItem value="Mac-Addr">{t('MAC address')}</MenuItem>
        <MenuItem value="Mutex">{t('Mutex')}</MenuItem>
        <MenuItem value="PDB-Path">{t('PDB Path')}</MenuItem>
        <MenuItem value="Registry-Key">{t('Registry key')}</MenuItem>
        <MenuItem value="Registry-Key-Value">
          {t('Registry key value')}
        </MenuItem>
        <MenuItem value="URL">{t('URL')}</MenuItem>
        <MenuItem value="Windows-Service-Name">
          {t('Windows Service Name')}
        </MenuItem>
        <MenuItem value="Windows-Service-Display-Name">
          {t('Windows Service Display Name')}
        </MenuItem>
        <MenuItem value="Windows-Scheduled-Task">
          {t('Windows Scheduled Task')}
        </MenuItem>
        <MenuItem value="X509-Certificate-Issuer">
          {t('X509 Certificate Issuer')}
        </MenuItem>
        <MenuItem value="X509-Certificate-Serial-Number">
          {t('X509 Certificate Serial number')}
        </MenuItem>
      </Field>
    );
  }
}

TypesField.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(TypesField);
