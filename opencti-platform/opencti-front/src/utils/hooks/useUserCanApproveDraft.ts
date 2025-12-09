import { getCapabilitiesName, isBypassUser, KNOWLEDGE_KNUPDATE_KNDELETE } from './useGranted';
import useAuth from './useAuth';

// Check if the user has only KNOWLEDGE_KNUPDATE_KNDELETE in base capabilities (or is bypass)
const useUserCanApproveDraft = (): boolean => {
  const { me } = useAuth();
 
  const isBypassUserFlag = isBypassUser(me);
  const canDeleteKnowledge = getCapabilitiesName(me.capabilities).includes(KNOWLEDGE_KNUPDATE_KNDELETE);

  return canDeleteKnowledge || isBypassUserFlag;
};

export default useUserCanApproveDraft;
