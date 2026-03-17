import { getCapabilitiesName, isBypassUser, KNOWLEDGE_KNUPDATE } from './useGranted';
import useAuth from './useAuth';

// Check if the user has KNOWLEDGE_KNUPDATE in base capabilities (or is bypass)
const useUserCanEditDraft = (): boolean => {
  const { me } = useAuth();

  const isBypassUserFlag = isBypassUser(me);
  const canEditKnowledge = getCapabilitiesName(me.capabilities).includes(KNOWLEDGE_KNUPDATE);

  return canEditKnowledge || isBypassUserFlag;
};

export default useUserCanEditDraft;
