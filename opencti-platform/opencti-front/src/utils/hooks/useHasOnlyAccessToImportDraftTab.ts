import useGranted, { getCapabilitiesName, KNOWLEDGE, KNOWLEDGE_KNASKIMPORT } from './useGranted';
import useAuth from './useAuth';

// Check if the user can only access import data drafts
const useHasOnlyAccessToImportDraftTab = (): boolean => {
  const { me } = useAuth();
 
  const hasImportCapability = useGranted([KNOWLEDGE_KNASKIMPORT]);
  const userCapabilitiesInDraft = getCapabilitiesName(me.capabilitiesInDraft);
 
  if (hasImportCapability) {
    return false;
  } 
  return userCapabilitiesInDraft.includes(KNOWLEDGE);
};

export default useHasOnlyAccessToImportDraftTab;
