import useAuth from './useAuth';
import { MESSAGING$ } from '../../relay/environment';
import { useFormatter } from '../../components/i18n';

const useConfidenceLevel = () => {
  const { me } = useAuth();
  const { t_i18n } = useFormatter();
  const userEffectiveConfidenceLevel = me.effective_confidence_level;
  const overrides = userEffectiveConfidenceLevel?.overrides ?? [];

  const effectiveConfidenceLevel = (entityType: string | null | undefined) => {
    if (!entityType) {
      return userEffectiveConfidenceLevel?.max_confidence ?? 0;
    }
    const override = overrides.find((n) => n.entity_type === entityType);
    if (override) {
      return override.max_confidence;
    }
    return userEffectiveConfidenceLevel?.max_confidence ?? 0;
  };

  const checkConfidenceForEntity = (entity: { entity_type?: string | null, confidence?: number | null }, notifyError = false) => {
    if (!userEffectiveConfidenceLevel) {
      if (notifyError) {
        MESSAGING$.notifyError(t_i18n('You need a confidence level to edit objects in the platform.'));
      }
      return false;
    }

    const entityConfidenceLevel = effectiveConfidenceLevel(entity.entity_type);

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

  return { checkConfidenceForEntity, effectiveConfidenceLevel };
};

export default useConfidenceLevel;
