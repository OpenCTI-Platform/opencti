import useGranted, { getCapabilitiesName, KNOWLEDGE, KNOWLEDGE_KNASKIMPORT } from './useGranted';
import useAuth from './useAuth';
import useHelper from './useHelper';

// Check if the user can only access import data drafts
const useHasOnlyAccessToImportDraftTab = (): boolean => {
  const { me } = useAuth();

  const hasImportCapability = useGranted([KNOWLEDGE_KNASKIMPORT]);
  const userCapabilities = getCapabilitiesName(me.capabilities);
  const userCapabilitiesInDraft = getCapabilitiesName(me.capabilitiesInDraft);

  const { isFeatureEnable } = useHelper();
  const isCapabilitiesInDraftEnabled = isFeatureEnable('CAPABILITIES_IN_DRAFT');
  if (!isCapabilitiesInDraftEnabled || hasImportCapability) {
    return false;
  }
  return [...userCapabilities, ...userCapabilitiesInDraft].some((capabilityInDraft) => capabilityInDraft.includes(KNOWLEDGE));
};

export default useHasOnlyAccessToImportDraftTab;
