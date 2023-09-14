import * as R from 'ramda';
import { getEntitiesMapFromCache } from '../database/cache';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { SYSTEM_USER } from './access';

export const cleanMarkings = async (context, values) => {
  const markingsMap = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const defaultMarkingValues = values?.map((d) => markingsMap.get(d) ?? d) ?? [];
  const defaultGroupedMarkings = R.groupBy((m) => m.definition_type, defaultMarkingValues);
  return Object.entries(defaultGroupedMarkings).map(([_, key]) => {
    const max = Math.max(...key.map((m) => m.x_opencti_order));
    const results = key.filter((m) => m.x_opencti_order === max);
    return R.uniqWith((a, b) => a.id === b.id, results);
  }).flat();
};

export const markingsToReplaceFiltered = async (currentMarkings, context, refs) => {
  const markingsMap = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const markingAdded = markingsMap.get(R.head(refs));

  const markingsHasSameType = currentMarkings.filter((currentMarking) => currentMarking.definition_type === markingAdded.definition_type);
  const markingsToReplace = markingsHasSameType.filter((currentMarking) => currentMarking.x_opencti_order !== markingAdded.x_opencti_order);
  if (markingsToReplace.length !== 0) {
    // filter every value that has not the same type
    const existingMarkings = currentMarkings.filter((marking) => !marking.definition_type.includes(markingAdded.definition_type)).map((m) => m.id);
    return existingMarkings.concat(markingAdded.id);
  }
  return null;
};
