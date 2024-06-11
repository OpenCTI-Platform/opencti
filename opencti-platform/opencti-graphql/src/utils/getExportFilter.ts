import type { StoreMarkingDefinition } from '../types/store';
import { getExportContentMarkings } from './getExportContentMarkings';
import { isNotEmptyField } from '../database/utils';
import type { AuthUser } from '../types/user';

type GetExportFilterType = {
  markingList: StoreMarkingDefinition[];
  contentMaxMarkings: string[];
  objectIdsList: string[];
};

export const getExportFilter = async (user: AuthUser, { markingList, contentMaxMarkings, objectIdsList }: GetExportFilterType) => {
  const { max_shareable_marking } = user;

  const contentMaxMarkingsList = markingList.filter(({ id }) => contentMaxMarkings.includes(id));
  const maxShareableMarkings = markingList.filter(({ id }) => max_shareable_marking.some((m) => m.id === id));
  const notShareableMarkings = markingList.filter(({ definition_type }) => !max_shareable_marking.some((m) => m.definition_type === definition_type)).map(({ id }) => id);

  const effectiveContentMaxMarkings: StoreMarkingDefinition[] = [];
  maxShareableMarkings.forEach((m) => {
    const { definition_type, x_opencti_order } = m;
    const contentMaxMarking = contentMaxMarkingsList.find((c) => c.definition_type === definition_type);
    if (contentMaxMarking) {
      const { x_opencti_order: contentMaxMarkingOrder } = contentMaxMarking;
      effectiveContentMaxMarkings.push(contentMaxMarkingOrder <= x_opencti_order ? contentMaxMarking : m);
    } else {
      effectiveContentMaxMarkings.push(m);
    }
  });

  const contentMarkings = effectiveContentMaxMarkings.length ? await getExportContentMarkings(markingList, effectiveContentMaxMarkings) : [];

  const access_filters = contentMarkings.length ? [
    { key: 'objectMarking', mode: 'and', operator: 'not_eq', values: [...contentMarkings, ...notShareableMarkings] },
  ] : [];

  const markingFilter = {
    mode: 'and',
    filters: access_filters,
    filterGroups: [],
  };

  const mainFilter = {
    mode: 'and',
    filters: [...access_filters],
    filterGroups: []
  };
  if (isNotEmptyField(objectIdsList)) {
    mainFilter.filters.push({
      key: 'ids',
      values: objectIdsList,
      mode: 'or',
      operator: 'eq'
    });
  }

  return { markingFilter, mainFilter };
};
