import Alert from '@mui/material/Alert';
import { SxProps } from '@mui/material/styles';
import { IngestionConnector } from '@components/integrations/catalog/types';
import useConnectorCompatibilityMessage from '@components/integrations/catalog/hooks/useConnectorCompatibilityMessage';

type IngestionCatalogCompatibilityAlertProps = {
  connector: Pick<IngestionConnector, 'manager_supported' | 'compatibility'>;
  sx?: SxProps;
};

// Explains why a managed connector cannot be deployed on the current platform version
const IngestionCatalogCompatibilityAlert = ({ connector, sx }: IngestionCatalogCompatibilityAlertProps) => {
  const message = useConnectorCompatibilityMessage(connector);
  if (!message) {
    return null;
  }
  return (
    <Alert severity="info" sx={sx}>
      {message}
    </Alert>
  );
};

export default IngestionCatalogCompatibilityAlert;
