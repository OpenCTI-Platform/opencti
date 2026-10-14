import { IngestionConnector } from '@components/integrations/catalog/types';
import { useFormatter } from '../../../../../components/i18n';

type CompatibilityConnector = Pick<IngestionConnector, 'manager_supported' | 'compatibility'>;

// Why a managed connector cannot be deployed on the current platform version, null when it can
const useConnectorCompatibilityMessage = (connector: CompatibilityConnector | null | undefined) => {
  const { t_i18n } = useFormatter();
  const compatibility = connector?.compatibility;
  if (!connector?.manager_supported || !compatibility || compatibility.is_compatible) {
    return null;
  }
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

export default useConnectorCompatibilityMessage;
