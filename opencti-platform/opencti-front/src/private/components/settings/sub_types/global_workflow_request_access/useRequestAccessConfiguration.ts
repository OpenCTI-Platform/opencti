import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';

/**
 * The entity type's request access configuration, or `null` when it cannot be configured:
 * Enterprise Edition off, entity type without the setting, or no configuration yet.
 */
const useRequestAccessConfiguration = () => {
  const { subType } = useSubTypeOutletContext();
  const isEnterpriseEdition = useEnterpriseEdition();
  const configuration = subType.settings.requestAccessConfiguration;
  const isAvailable = isEnterpriseEdition && subType.settings.availableSettings.includes('request_access_workflow');
  return isAvailable && configuration ? configuration : null;
};

export default useRequestAccessConfiguration;
