import { useOptionalChatbot } from '@components/chatbox/ChatbotContext';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';

/** Hunt planning and triage run on XTM One agents and are Enterprise Edition capabilities. */
const useHuntAI = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  // Outside of the ChatbotProvider (isolated tests, public pages), no agent is reachable
  const xtmOneConfigured = useOptionalChatbot()?.xtmOneConfigured === true;
  return {
    isEnterpriseEdition,
    xtmOneConfigured,
    available: isEnterpriseEdition && xtmOneConfigured,
  };
};

export default useHuntAI;
