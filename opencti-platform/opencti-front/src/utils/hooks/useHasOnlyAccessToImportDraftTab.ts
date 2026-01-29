import useGranted, { getCapabilitiesName, KNOWLEDGE, KNOWLEDGE_KNASKIMPORT } from './useGranted';
import useAuth from './useAuth';

// Check if the user can only access import data drafts
const useHasOnlyAccessToImportDraftTab = (): boolean => {
  const { me } = useAuth();

  const hasImportCapability = useGranted([KNOWLEDGE_KNASKIMPORT]);
  const userCapabilities = getCapabilitiesName(me.capabilities);
  const userCapabilitiesInDraft = getCapabilitiesName(me.capabilitiesInDraft);

  if (hasImportCapability) {
    return false;
  }
  return [...userCapabilities, ...userCapabilitiesInDraft].some((capabilityInDraft) => capabilityInDraft.includes(KNOWLEDGE));
};

export default useHasOnlyAccessToImportDraftTab;
