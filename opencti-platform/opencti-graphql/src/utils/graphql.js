import * as R from 'ramda';
import { isInternalRelationship } from '../schema/internalRelationship';
import { isInternalObject } from '../schema/internalObject';
import { isStixMetaRelationship } from '../schema/stixMetaRelationship';
import typeDefs from '../../config/schema/opencti.graphql';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { isStixCyberObservableRelationship } from '../schema/stixCyberObservableRelationship';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { pascalize } from '../database/utils';
import { UnsupportedError } from '../config/errors';

export const extractFieldInputDefinition = (entityType) => {
  // Internal doesnt have any contract
  if (isInternalRelationship(entityType)) {
    return [];
  }
  if (isInternalObject(entityType)) {
    return [];
  }
  // Relations
  if (isStixMetaRelationship(entityType)) {
    const def = R.find((e) => e.name.value === 'StixMetaRelationshipsAddInput', typeDefs.definitions);
    return def.fields.map((f) => f.name.value);
  }
  if (isStixCoreRelationship(entityType)) {
    const def = R.find((e) => e.name.value === 'StixCoreRelationshipAddInput', typeDefs.definitions);
    return def.fields.map((f) => f.name.value);
  }
  if (isStixSightingRelationship(entityType)) {
    const def = R.find((e) => e.name.value === 'StixSightingRelationshipAddInput', typeDefs.definitions);
    return def.fields.map((f) => f.name.value);
  }
  if (isStixCyberObservableRelationship(entityType)) {
    const def = R.find((e) => e.name.value === 'StixCyberObservableRelationshipAddInput', typeDefs.definitions);
    return def.fields.map((f) => f.name.value);
  }
  // Entities
  if (isStixCyberObservable(entityType)) {
    const baseFields = [
      'stix_id',
      'x_opencti_score',
      'x_opencti_description',
      'createIndicator',
      'createdBy',
      'objectMarking',
      'objectLabel',
      'externalReferences',
      'clientMutationId',
      'update',
    ];
    const formattedType = `${entityType.split('-').join('')}AddInput`;
    const def = R.find((e) => e.name.value === formattedType, typeDefs.definitions);
    const schemaFields = def.fields.map((f) => f.name.value);
    return [...baseFields, ...schemaFields];
  }
  const formattedType = `${entityType.split('-').map((e) => pascalize(e)).join('')}AddInput`;
  const def = R.find((e) => e.name.value === formattedType, typeDefs.definitions);
  if (def) {
    return def.fields.map((f) => f.name.value);
  }
  throw UnsupportedError(`Cant extract fields definition ${entityType}`);
};
