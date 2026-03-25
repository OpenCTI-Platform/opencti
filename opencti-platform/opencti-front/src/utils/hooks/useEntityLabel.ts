import useEntitySettings from './useEntitySettings';
import { useFormatter } from '../../components/i18n';

/**
 * Hook that returns a resolver function for entity type labels.
 * Loads all entity settings once then returns a function that can
 * resolve the display label for any entity type on the fly.
 *
 * For the singular form, call `resolve(entityType)`.
 * For the plural form, call `resolve(entityType, defaultPluralLabel)` where
 * `defaultPluralLabel` is the i18n key to use when no custom plural name is
 * configured (e.g. `t_i18n('Reports')`).
 *
 * @returns A resolver function
 */
export const useEntityLabelResolver = (): ((entityType: string, defaultLabel?: string) => string) => {
  const { t_i18n } = useFormatter();
  const allEntitySettings = useEntitySettings();

  return (entityType: string, defaultLabel?: string): string => {
    const setting = allEntitySettings.find((s) => s.target_type === entityType);
    if (setting) {
      // If a defaultLabel is provided we treat this as a plural request
      if (defaultLabel !== undefined && setting.custom_name_plural) {
        return setting.custom_name_plural;
      }
      if (defaultLabel === undefined && setting.custom_name) {
        return setting.custom_name;
      }
    }
    // Use the provided default label, or fall back to the singular i18n key
    return defaultLabel ?? t_i18n(`entity_${entityType}`);
  };
};
