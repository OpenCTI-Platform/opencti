import type { StoreMarkingDefinition } from '../types/store';

export const getExportContentMarkings = async (markingList: StoreMarkingDefinition[], contentMaxMarkings: StoreMarkingDefinition[]) => {
  if (!contentMaxMarkings.length) return [];

  const excludedMarkings: StoreMarkingDefinition[] = [];

  contentMaxMarkings.forEach(({ definition_type, x_opencti_order }) => {
    excludedMarkings.push(...markingList.filter((marking) => marking.definition_type === definition_type && marking.x_opencti_order > x_opencti_order));
  });

  return excludedMarkings.map(({ id }) => id);
};
