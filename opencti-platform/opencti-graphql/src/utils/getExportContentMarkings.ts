import type { StoreMarkingDefinition } from '../types/store';

export const getExportContentMarkings = async (markingList: StoreMarkingDefinition[], contentMaxMarkings: string[]) => {
  if (!contentMaxMarkings.length) return [];

  const contentMaxMarkingsList = markingList.filter(({ id }) => contentMaxMarkings.includes(id));

  return contentMaxMarkingsList.reduce((acc: StoreMarkingDefinition[], cur) => {
    return acc.filter((marking) => {
      return (cur.definition_type === marking.definition_type && cur.x_opencti_order >= marking.x_opencti_order)
        || cur.definition_type !== marking.definition_type;
    });
  }, markingList).map(({ id }) => id);
};
