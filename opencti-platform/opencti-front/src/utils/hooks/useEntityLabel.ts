import useEntitySettings from './useEntitySettings';
import { useFormatter } from '../../components/i18n';

/**
 * Hook that resolves the display label for an entity type.
 * If a custom_name is set in EntitySettings, it takes precedence.
 * Otherwise, falls back to the default i18n translation.
 *
 * @param entityType - The internal entity type identifier (e.g. 'Case-Incident')
 * @param plural - Whether to return the plural form
 * @returns The resolved display label
 */
const useEntityLabel = (entityType: string, plural = false): string => {
  const { t_i18n } = useFormatter();
  const entitySettings = useEntitySettings(entityType);

  if (entitySettings.length > 0) {
    const setting = entitySettings[0];
    if (plural && setting.custom_name_plural) {
      return setting.custom_name_plural;
    }
    if (!plural && setting.custom_name) {
      return setting.custom_name;
    }
  }

  // Fallback to default i18n label
  const key = plural ? `entity_${entityType}s` : `entity_${entityType}`;
  return t_i18n(key);
};

export default useEntityLabel;
