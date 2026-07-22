import React, { FunctionComponent, useState } from 'react';
import Alert from '@mui/material/Alert';
import { Typography } from '@mui/material';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

const URL = 'https://docs.opencti.io/latest/deployment/integration-manager/';

// Persist the dismissal so the banner stays hidden across navigations and reloads.
const DISMISS_STORAGE_KEY = 'connector_deployment_banner_dismissed';

// Storage can be unavailable (private mode, disabled storage): the banner then
// simply shows again on the next load.
const isDismissStored = () => {
  try {
    return localStorage.getItem(DISMISS_STORAGE_KEY) === 'true';
  } catch {
    return false;
  }
};

const storeDismiss = () => {
  try {
    localStorage.setItem(DISMISS_STORAGE_KEY, 'true');
  } catch {
    // ignored: the dismissal only lasts for the current render
  }
};

type ConnectorDeploymentBannerProps = {
  hasActiveManagers: boolean;
  isVerified?: boolean;
};

// The EE license requirement is intentionally not surfaced as a banner: the
// deploy buttons already carry the EE chip and gating.
const ConnectorDeploymentBanner: FunctionComponent<ConnectorDeploymentBannerProps> = ({
  hasActiveManagers,
  isVerified,
}) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();

  const [dismissed, setDismissed] = useState<boolean>(isDismissStored);

  const handleDismiss = () => {
    storeDismiss();
    setDismissed(true);
  };

  if (isEnterpriseEdition && !hasActiveManagers && !dismissed) {
    return (
      <Alert severity="warning" onClose={handleDismiss}>
        <Typography>
          {t_i18n('Deploying some connectors from this catalog requires the installation of our')}
          <Link style={{ marginLeft: 4 }} to={URL} target="_blank" rel="noopener noreferrer">
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
          {t_i18n('This connector has been developed by the community and is not supported by Filigran.')}
        </Typography>
      </Alert>
    );
  }

  return null;
};

export default ConnectorDeploymentBanner;
