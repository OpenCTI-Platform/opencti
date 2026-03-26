import useEntitySettings from './useEntitySettings';
import { useFormatter } from '../../components/i18n';

const objectTypeTranslationKey = (entityType: string) => `entity_${entityType}`;
const objectTypePluralTranslationKey = (entityType: string) => `entity_plural_${entityType}`;
const relationshipTypeTranslationKey = (entityType: string) => `relationship_${entityType}`;

const useEntityTranslation = () => {
  const { t_i18n } = useFormatter();
  const allEntitySettings = useEntitySettings();

  const translateEntityType = (entityType: string, options?: {
    skipCustom?: boolean;
    plural?: boolean;
  }) => {
    const plural = Boolean(options?.plural);
    const skipCustom = Boolean(options?.skipCustom);
    const setting = !skipCustom
      ? allEntitySettings.find((s) => s.target_type === entityType)
      : undefined;
    if (plural) {
      if (setting?.custom_name_plural) {
        return setting.custom_name_plural;
      }
      const pluralObjectTranslationKey = objectTypePluralTranslationKey(entityType);
      const pluralObjectTranslation = t_i18n(objectTypePluralTranslationKey(entityType));
      if (pluralObjectTranslation !== pluralObjectTranslationKey) {
        return pluralObjectTranslation;
      }
    }
    if (setting?.custom_name) {
      return setting.custom_name;
    }
    const singularObjectTranslationKey = objectTypeTranslationKey(entityType);
    const singularObjectTranslation = t_i18n(objectTypeTranslationKey(entityType));
    if (singularObjectTranslation !== singularObjectTranslationKey) {
      return singularObjectTranslation;
    }
    const singularRelationshipTranslationKey = relationshipTypeTranslationKey(entityType);
    const singularRelationshipTranslation = t_i18n(relationshipTypeTranslationKey(entityType));
    if (singularRelationshipTranslation !== singularRelationshipTranslationKey) {
      return singularRelationshipTranslation;
    }
    return t_i18n(entityType);
  };

  return {
    translateEntityType,
  };
};

export default useEntityTranslation;
