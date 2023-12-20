import * as R from 'ramda';
import { SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION } from '@opentelemetry/semantic-conventions';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { buildPagination } from '../database/utils';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { schemaTypesDefinition } from '../schema/schema-types';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { ABSTRACT_STIX_NESTED_REF_RELATIONSHIP } from '../schema/stixRefRelationship';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT } from '../schema/stixCyberObservable';
import { telemetry } from '../config/tracing';
import type { AuthContext, AuthUser } from '../types/user';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';

// -- ENTITY TYPES --

export const queryDefaultSubTypes = async (context: AuthContext, user: AuthUser, search : string | null = null) => {
  const queryDefaultSubTypesFn = async () => {
    const sortByLabel = R.sortBy(R.toLower);
    const types = schemaTypesDefinition.get(ABSTRACT_STIX_DOMAIN_OBJECT).filter((n) => n.includes(search ?? ''));
    const finalResult = R.pipe(
      sortByLabel,
      R.map((n) => ({ node: { id: n, label: n, overridable: true } })),
      R.append({ node: { id: ABSTRACT_STIX_CORE_RELATIONSHIP, label: ABSTRACT_STIX_CORE_RELATIONSHIP, overridable: false } }),
      R.append({ node: { id: STIX_SIGHTING_RELATIONSHIP, label: STIX_SIGHTING_RELATIONSHIP, overridable: false } }),
      R.append({ node: { id: ABSTRACT_STIX_CYBER_OBSERVABLE, label: ABSTRACT_STIX_CYBER_OBSERVABLE, overridable: false } }),
      R.append({ node: { id: ENTITY_TYPE_EXTERNAL_REFERENCE, label: ENTITY_TYPE_EXTERNAL_REFERENCE, overridable: false } }),
      R.append({ node: { id: ENTITY_HASHED_OBSERVABLE_ARTIFACT, label: ENTITY_HASHED_OBSERVABLE_ARTIFACT, overridable: false } }),
      R.uniqBy(R.path(['node', 'id'])),
    )(types);
    return buildPagination(0, null, finalResult, finalResult.length);
  };

  return telemetry(context, user, 'QUERY default subtypes', {
    [SEMATTRS_DB_NAME]: 'subtypes_domain',
    [SEMATTRS_DB_OPERATION]: 'read',
  }, queryDefaultSubTypesFn);
};

const querySubType = async (subTypeId: string) => {
  const attributes = schemaAttributesDefinition.getAttributeNames(subTypeId);
  if (attributes.length > 0) {
    return { id: subTypeId, label: subTypeId, overridable: true };
  }
  return null;
};
const querySubTypes = async (context: AuthContext, user: AuthUser, { type = null, search = null } : { type: string | null, search?: string | null }) => {
  if (type === null) {
    return queryDefaultSubTypes(context, user, search);
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
    R.map((n) => ({ node: { id: n, label: n, overridable: true } })),
    R.uniqBy(R.path(['node', 'id'])),
  )(types);
  return buildPagination(0, null, finalResult, finalResult.length);
};

export const findById = (subTypeId: string) => querySubType(subTypeId);

export const findAll = (context: AuthContext, user: AuthUser, args : { type: string | null, search?: string | null }) => {
  return querySubTypes(context, user, args);
};
