import useAuth from '../../../../utils/hooks/useAuth';
import { getCapabilitiesName, isBypassUser, KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS } from '../../../../utils/hooks/useGranted';

// The backend checks a transition's required inputs with the draft context stripped, so only the
// base capabilities count: `useGranted` would also count the ones granted inside a draft, and the
// form would present a required input as optional to a user the backend then rejects.
const useCanBypassMandatoryFields = (): boolean => {
  const { me } = useAuth();
  return isBypassUser(me)
    || getCapabilitiesName(me.capabilities).some((name) => name.includes(KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS));
};

export default useCanBypassMandatoryFields;
