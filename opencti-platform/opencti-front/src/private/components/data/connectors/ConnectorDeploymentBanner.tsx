import React, { FunctionComponent } from 'react';
import Alert from '@mui/material/Alert';
import { Typography } from '@mui/material';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

const URL = 'https://docs.opencti.io/latest/deployment/integration-manager/';

type ConnectorDeploymentBannerProps = {
  hasActiveManagers: boolean;
  isVerified?: boolean;
};

const ConnectorDeploymentBanner: FunctionComponent<ConnectorDeploymentBannerProps> = ({
  hasActiveManagers,
  isVerified,
}) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();

  if (!isEnterpriseEdition) {
    return (
      <Alert severity="info" variant="outlined">
        <Typography>
          {t_i18n('The deployment of connectors from this catalog requires an Enterprise Edition license.')}
        </Typography>
      </Alert>
    );
  }

  if (!hasActiveManagers) {
    return (
      <Alert severity="warning">
        <Typography>
          {t_i18n('Deploying connectors from this catalog requires the installation of our')}
          <Link style={{ marginLeft: 4 }} to={URL} target="_blank" rel="noopener">
            {t_i18n('Integration Manager')}
          </Link>
        </Typography>
      </Alert>
    );
  }

  if (isVerified === false) {
    return (
      <Alert severity="warning">
        <Typography>
          {t_i18n('This connector has not been developed and verified by Filigran. As such, Filigran cannot be held liable for any issues that may occur during its use.')}
        </Typography>
      </Alert>
    );
  }

  return null;
};

export default ConnectorDeploymentBanner;
