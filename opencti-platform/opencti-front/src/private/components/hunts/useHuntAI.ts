import { useChatbot } from '@components/chatbox/ChatbotContext';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';

/** Hunt planning and triage run on XTM One agents and are Enterprise Edition capabilities. */
const useHuntAI = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  let xtmOneConfigured: boolean;
  try {
    xtmOneConfigured = useChatbot().xtmOneConfigured === true;
  } catch (_) {
    // Outside of the ChatbotProvider (isolated tests, public pages), no agent is reachable
    xtmOneConfigured = false;
  }
  return {
    isEnterpriseEdition,
    xtmOneConfigured,
    available: isEnterpriseEdition && xtmOneConfigured,
  };
};

export default useHuntAI;
