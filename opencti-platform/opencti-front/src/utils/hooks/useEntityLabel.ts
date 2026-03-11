import { useFormatter } from '../../components/i18n';
import useEntitySettings from './useEntitySettings';

/**
 * Resolves the display label for an entity type, using the custom name
 * set by an administrator if available, falling back to the default
 * i18n translation.
 *
 * @param entityType - The internal entity type identifier (e.g. 'Report', 'Case-Incident')
 * @param plural - Whether to return the plural form
 * @returns The resolved display label string
 */
const useEntityLabel = (entityType: string, plural = false): string => {
  const { t_i18n } = useFormatter();
  const settings = useEntitySettings(entityType);
  const setting = settings.length > 0 ? settings[0] : undefined;

  if (setting) {
    if (plural && setting.custom_name_plural) {
      return setting.custom_name_plural;
    }
    if (!plural && setting.custom_name) {
      return setting.custom_name;
    }
  }

  // Fallback to default i18n translation
  return t_i18n(`entity_${entityType}`);
};

export default useEntityLabel;
