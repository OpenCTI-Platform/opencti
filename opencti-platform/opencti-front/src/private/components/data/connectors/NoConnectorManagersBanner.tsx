import React, { FunctionComponent } from 'react';
import Alert from '@mui/material/Alert';
import { Typography } from '@mui/material';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';

const URL = 'https://docs.opencti.io/latest/';

const NoConnectorManagersBanner: FunctionComponent = () => {
  const { t_i18n } = useFormatter();

  return (
    <Alert severity="warning">
      <Typography>
        {t_i18n('To be able to deploy a connector, you must deploy the composer')}
        <Link style={{ marginLeft: 4 }} to={URL} target="_blank" rel="noopener">
          {t_i18n('Learn more')}
        </Link>
      </Typography>
    </Alert>
  );
};

export default NoConnectorManagersBanner;
