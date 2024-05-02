import type { StoreMarkingDefinition } from '../types/store';

export const getExportContentMarkings = async (markingList: StoreMarkingDefinition[], contentMaxMarkings: string[]) => {
  if (!contentMaxMarkings.length) return [];

  const contentMaxMarkingsList = markingList.filter(({ id }) => contentMaxMarkings.includes(id));

  const excludedMarkings: StoreMarkingDefinition[] = [];

  contentMaxMarkingsList.forEach(({ definition_type, x_opencti_order }) => {
    excludedMarkings.push(...markingList.filter((marking) => marking.definition_type === definition_type && marking.x_opencti_order > x_opencti_order));
  });

  return excludedMarkings.map(({ id }) => id);
};
