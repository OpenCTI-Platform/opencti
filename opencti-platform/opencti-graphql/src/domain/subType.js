import * as R from 'ramda';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_DOMAIN_OBJECT, schemaTypes } from '../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { buildPagination } from '../database/utils';

export const findById = (subTypeId) => querySubType(subTypeId);

export const findAll = (args) => querySubTypes(args);

export const querySubType = async (subTypeId) => {
  const attributes = schemaTypes.getAttributes(subTypeId);
  if (attributes.length > 0) {
    return { id: subTypeId, label: subTypeId };
  }
  return null;
};
export const querySubTypes = async ({ type = null, search = null }) => {
  if (type === null) {
    return queryDefaultSubTypes(search);
  }
  const sortByLabel = R.sortBy(R.toLower);
  const types = schemaTypes.get(type).filter((n) => n.includes(search ?? ''));
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, label: n } })),
    R.uniqBy(R.path(['node', 'id'])),
  )(types);
  return buildPagination(0, null, finalResult, finalResult.length);
};
export const queryDefaultSubTypes = async (search = null) => {
  const sortByLabel = R.sortBy(R.toLower);
  const types = schemaTypes.get(ABSTRACT_STIX_DOMAIN_OBJECT).filter((n) => n.includes(search ?? ''));
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, label: n } })),
    R.append({ node: { id: ABSTRACT_STIX_CORE_RELATIONSHIP, label: ABSTRACT_STIX_CORE_RELATIONSHIP } }),
    R.append({ node: { id: STIX_SIGHTING_RELATIONSHIP, label: STIX_SIGHTING_RELATIONSHIP } }),
    R.uniqBy(R.path(['node', 'id'])),
  )(types);
  return buildPagination(0, null, finalResult, finalResult.length);
};
