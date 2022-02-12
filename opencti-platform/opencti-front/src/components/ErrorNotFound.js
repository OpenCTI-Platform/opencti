import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/lab/AlertTitle/AlertTitle';
import inject18n from './i18n';

class ErrorNotFound extends Component {
  render() {
    const { t } = this.props;
    return (
      <Alert severity="info">
        <AlertTitle>{t('Error')}</AlertTitle>
        {t('This page is not found on this OpenCTI application.')}
      </Alert>
    );
  }
}

ErrorNotFound.propTypes = {
  t: PropTypes.func,
};

export default inject18n(ErrorNotFound);
