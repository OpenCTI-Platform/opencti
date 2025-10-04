import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { Alert, Typography } from '@components';

const URL = 'https://docs.opencti.io/latest/deployment/integration-manager/';

type ConnectorDeploymentBannerProps = {
  hasRegisteredManagers: boolean;
};

const ConnectorDeploymentBanner: FunctionComponent<ConnectorDeploymentBannerProps> = ({ hasRegisteredManagers }) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();

  if (isEnterpriseEdition && hasRegisteredManagers) {
    return null;
  }

  if (isEnterpriseEdition && !hasRegisteredManagers) {
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

  return (
    <Alert severity="info" variant="outlined">
      <Typography>
        {t_i18n('The deployment of connectors from this catalog requires an Enterprise Edition license.')}
      </Typography>
    </Alert>
  );
};

export default ConnectorDeploymentBanner;
