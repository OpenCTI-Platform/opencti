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

export const markingsToReplaceFiltered = async (context, currentMarkings, refs) => {
  const markingsMap = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  // Get object entries from markings Map, convert into array without duplicate values
  const markingsAdded = [...new Set(Object.values(Object.fromEntries(markingsMap)))].filter((m) => refs.includes(m.id));
  // If multiple markings is added, filter and keep the highest rank
  const markingsAddedCleaned = await cleanMarkings(context, markingsAdded);

  const needToBeReplaced = true;
  const markingsToBeChanged = [];
  // todo improve the loop
  currentMarkings.forEach((element) => {
    markingsAddedCleaned.forEach((item) => {
      if (item.definition_type === element.definition_type) {
        if (item.x_opencti_order !== element.x_opencti_order || item.x_opencti_order >= element.x_opencti_order) {
          markingsToBeChanged.push(item);
          // todo if data is coming from a connector, keep the highest order between currentMarkings and markings added
        }
      } else markingsToBeChanged.push(item);
    });
  });
  const existingMarkings = currentMarkings
    .filter((currentMarking) => !markingsAddedCleaned
      .some((markingAdded) => markingAdded.definition_type === currentMarking.definition_type));

  const finalMarkingsList = markingsToBeChanged.concat(existingMarkings);

  if (finalMarkingsList !== currentMarkings) {
    return finalMarkingsList.map((m) => m.id);
  }
  return !needToBeReplaced;
};
