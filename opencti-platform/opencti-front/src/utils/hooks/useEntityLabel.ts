import { useFormatter } from '../../components/i18n';
import useEntitySettings from './useEntitySettings';

/**
 * Hook that resolves the display label for an entity type.
 *
 * Resolution order:
 * 1. If a custom_name (or custom_name_plural) is set in the EntitySetting, use it.
 * 2. Otherwise, fall back to the i18n translation of the entity type.
 *
 * @param entityType - The internal entity type identifier (e.g. 'Report', 'Case-Incident').
 * @returns An object with singular and plural display labels.
 *
 * @example
 * ```tsx
 * const { label, labelPlural } = useEntityLabel('Report');
 * // If custom_name is 'Intelligence Product', returns:
 * // { label: 'Intelligence Product', labelPlural: 'Intelligence Products' }
 * // If no custom name is set, returns the i18n translation:
 * // { label: 'Report', labelPlural: 'Reports' }
 * ```
 */
const useEntityLabel = (entityType: string): { label: string; labelPlural: string } => {
  const { t_i18n } = useFormatter();
  const settings = useEntitySettings(entityType);
  const setting = settings.length > 0 ? settings[0] : undefined;

  const customName = setting?.custom_name;
  const customNamePlural = setting?.custom_name_plural;

  // Resolve singular: custom name → i18n fallback
  const label = customName && customName.trim().length > 0
    ? customName
    : t_i18n(`entity_${entityType}`);

  // Resolve plural: custom plural → custom singular + 's' → i18n fallback + 's'
  let labelPlural: string;
  if (customNamePlural && customNamePlural.trim().length > 0) {
    labelPlural = customNamePlural;
  } else if (customName && customName.trim().length > 0) {
    // If only singular custom name is set, naively pluralize
    labelPlural = `${customName}s`;
  } else {
    labelPlural = t_i18n(`entity_${entityType}s`);
  }

  return { label, labelPlural };
};

export default useEntityLabel;
