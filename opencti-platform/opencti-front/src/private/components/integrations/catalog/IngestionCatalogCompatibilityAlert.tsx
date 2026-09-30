import Alert from '@mui/material/Alert';
import { SxProps } from '@mui/material/styles';
import { IngestionConnector } from '@components/integrations/catalog/types';
import { useFormatter } from '../../../../components/i18n';

type IngestionCatalogCompatibilityAlertProps = {
  connector: Pick<IngestionConnector, 'manager_supported' | 'compatibility'>;
  sx?: SxProps;
};

// Explains why a managed connector cannot be deployed on the current platform version
const IngestionCatalogCompatibilityAlert = ({ connector, sx }: IngestionCatalogCompatibilityAlertProps) => {
  const { t_i18n } = useFormatter();
  const { compatibility } = connector;
  if (!connector.manager_supported || compatibility?.is_compatible !== false) {
    return null;
  }

  const getMessage = () => {
    if (compatibility.minimum_platform_version) {
      return t_i18n('This connector is not compatible with your current platform version. Please upgrade your platform to {version} or above.', {
        values: { version: compatibility.minimum_platform_version },
      });
    }
    if (compatibility.maximum_platform_version) {
      return t_i18n('This connector is not compatible with your current platform version. It supports platform versions up to {version}.', {
        values: { version: compatibility.maximum_platform_version },
      });
    }
    return t_i18n('This connector is not compatible with your current platform version.');
  };

  return (
    <Alert severity="info" sx={sx}>
      {getMessage()}
    </Alert>
  );
};

export default IngestionCatalogCompatibilityAlert;
