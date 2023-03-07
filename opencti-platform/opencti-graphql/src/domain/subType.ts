import * as R from 'ramda';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { buildPagination } from '../database/utils';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { schemaTypesDefinition } from '../schema/schema-types';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { ABSTRACT_STIX_NESTED_REF_RELATIONSHIP } from '../schema/stixRefRelationship';

// -- ENTITY TYPES --

export const queryDefaultSubTypes = async (search : string | null = null) => {
  const sortByLabel = R.sortBy(R.toLower);
  const types = schemaTypesDefinition.get(ABSTRACT_STIX_DOMAIN_OBJECT).filter((n) => n.includes(search ?? ''));
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, label: n } })),
    R.append({ node: { id: ABSTRACT_STIX_CORE_RELATIONSHIP, label: ABSTRACT_STIX_CORE_RELATIONSHIP } }),
    R.append({ node: { id: STIX_SIGHTING_RELATIONSHIP, label: STIX_SIGHTING_RELATIONSHIP } }),
    R.uniqBy(R.path(['node', 'id'])),
  )(types);
  return buildPagination(0, null, finalResult, finalResult.length);
};

const querySubType = async (subTypeId: string) => {
  const attributes = schemaAttributesDefinition.getAttributeNames(subTypeId);
  if (attributes.length > 0) {
    return { id: subTypeId, label: subTypeId };
  }
  return null;
};
const querySubTypes = async ({ type = null, search = null } : { type: string | null, search?: string | null }) => {
  if (type === null) {
    return queryDefaultSubTypes(search);
  }
  const sortByLabel = R.sortBy(R.toLower);

  let types;
  if (type === ABSTRACT_STIX_NESTED_REF_RELATIONSHIP) {
    types = schemaRelationsRefDefinition.getDatables();
  } else {
    types = schemaTypesDefinition.get(type).filter((n) => n.includes(search ?? ''));
  }
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, label: n } })),
    R.uniqBy(R.path(['node', 'id'])),
  )(types);
  return buildPagination(0, null, finalResult, finalResult.length);
};

export const findById = (subTypeId: string) => querySubType(subTypeId);

export const findAll = (args : { type: string | null, search?: string | null }) => querySubTypes(args);
