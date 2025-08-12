import useAuth from './useAuth';
import { MESSAGING$ } from '../../relay/environment';
import { useFormatter } from '../../components/i18n';

const useConfidenceLevel = () => {
  const { me } = useAuth();
  const { t_i18n } = useFormatter();
  const userEffectiveConfidenceLevel = me.effective_confidence_level;
  const overrides = userEffectiveConfidenceLevel?.overrides ?? [];

  const getEffectiveConfidenceLevel = (entityType: string | null | undefined) => {
    if (!userEffectiveConfidenceLevel) {
      return null;
    }
    // asking for the global CL
    if (!entityType) {
      return userEffectiveConfidenceLevel.max_confidence;
    }
    // otherwise, check if an override exist
    const override = overrides.find((n) => n.entity_type === entityType);
    if (override) {
      return override.max_confidence;
    }
    // no override for this entity_type, return the global value
    return userEffectiveConfidenceLevel.max_confidence;
  };

  const checkConfidenceForEntity = (entity: { entity_type?: string | null, confidence?: number | null }, notifyError = false) => {
    if (!userEffectiveConfidenceLevel) {
      if (notifyError) {
        MESSAGING$.notifyError(t_i18n('You need a confidence level to edit objects in the platform.'));
      }
      return false;
    }

    const entityConfidenceLevel = getEffectiveConfidenceLevel(entity.entity_type);
    if (entityConfidenceLevel === null) {
      return false;
    }

    if (entity.confidence && entityConfidenceLevel >= entity.confidence) {
      return true;
    }
    if (entity.confidence) {
      if (notifyError) {
        MESSAGING$.notifyError(t_i18n('Your confidence level is insufficient to edit this object.'));
      }
      return false;
    }

    return true;
  };

  return { checkConfidenceForEntity, getEffectiveConfidenceLevel };
};

export default useConfidenceLevel;
