import useAuth from './useAuth';
import { MESSAGING$ } from '../../relay/environment';

const useConfidenceLevel = () => {
  const { me } = useAuth();
  const effectiveConfidenceLevel = me?.effective_confidence_level;

  const checkConfidenceForEntity = (entity: { confidence?: number | null }, notifyError = false) => {
    if (effectiveConfidenceLevel && entity.confidence && effectiveConfidenceLevel.max_confidence < entity.confidence) {
      if (notifyError) {
        MESSAGING$.notifyError('Your maximum confidence level is insufficient to edit this object.');
      }
      return false;
    } if (!effectiveConfidenceLevel && entity.confidence) {
      if (notifyError) {
        MESSAGING$.notifyError('You need a maximum confidence level to edit objects in the platform.');
      } return false;
    }
    return true;
  };

  return { checkConfidenceForEntity, effectiveConfidenceLevel };
};

export default useConfidenceLevel;
