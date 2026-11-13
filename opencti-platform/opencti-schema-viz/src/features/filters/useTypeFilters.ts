import { useMemo } from 'react';
import type { NormalizedSchema, ToggleableCategory } from '../../data/schemaTypes';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';
import { TOGGLEABLE_CATEGORIES } from '../../shared/theme/typeAppearance';

export interface CategorySummary {
  category: ToggleableCategory;
  enabled: boolean;
  typeIds: string[];
  pinnedCount: number;
}

export const useTypeFilters = (schema: NormalizedSchema) => {
  const enabledCategories = useSchemaGraphStore((state) => state.enabledCategories);
  const pinnedTypeIds = useSchemaGraphStore((state) => state.pinnedTypeIds);

  const typeIdsByCategory = useMemo(() => {
    const byCategory = new Map<ToggleableCategory, string[]>(TOGGLEABLE_CATEGORIES.map((category) => [category, []]));
    for (const typeId of schema.typeIds) {
      const category = schema.types.get(typeId)?.category;
      if (category && category !== 'Abstract') byCategory.get(category)?.push(typeId);
    }
    return byCategory;
  }, [schema]);

  const categories = useMemo<CategorySummary[]>(() => {
    const pinned = new Set(pinnedTypeIds);
    return TOGGLEABLE_CATEGORIES.map((category) => {
      const typeIds = typeIdsByCategory.get(category) ?? [];
      return { category, enabled: enabledCategories[category], typeIds, pinnedCount: typeIds.filter((id) => pinned.has(id)).length };
    });
  }, [typeIdsByCategory, enabledCategories, pinnedTypeIds]);

  return { categories, enabledCount: categories.filter((category) => category.enabled).length };
};
