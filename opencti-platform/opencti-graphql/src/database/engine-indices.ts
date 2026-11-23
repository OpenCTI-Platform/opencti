import * as R from 'ramda';
import {
  inferIndexFromConceptType,
  isEmptyField,
  READ_DATA_INDICES,
  READ_DATA_INDICES_WITHOUT_INFERRED,
  READ_ENTITIES_INDICES,
  READ_ENTITIES_INDICES_WITHOUT_INFERRED,
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_INTERNAL_RELATIONSHIPS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_META_RELATIONSHIPS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  READ_RELATIONSHIPS_INDICES,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
} from './utils';
import { UnsupportedError } from '../config/errors';
import { isStixRefRelationship, STIX_REF_RELATIONSHIP_TYPES } from '../schema/stixRefRelationship';
import { isAbstract } from '../schema/general';
import { isStixDomainObject } from '../schema/stixDomainObject';
import { isBasicObject, isStixCoreObject, isStixObject } from '../schema/stixCoreObject';
import { isBasicRelationship, isStixRelationship } from '../schema/stixRelationship';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixMetaObject } from '../schema/stixMetaObject';
import { isInternalObject } from '../schema/internalObject';
import { isInternalRelationship } from '../schema/internalRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';

const withInferencesEntities = (indices: string[], withInferences: boolean) => {
  return withInferences ? [READ_INDEX_INFERRED_ENTITIES, ...indices] : indices;
};
const withInferencesRels = (indices: string[], withInferences: boolean) => {
  return withInferences ? [READ_INDEX_INFERRED_RELATIONSHIPS, ...indices] : indices;
};
export const computeQueryIndices = (
  indices: string[] | string | undefined | null,
  typeOrTypes: string[] | string | undefined | null,
  withInferences = true,
): string[] | string | undefined | null => {
  const types = (Array.isArray(typeOrTypes) || isEmptyField(typeOrTypes)) ? typeOrTypes : [typeOrTypes] as string[];
  // If indices are explicitly defined, just rely on the definition
  if (isEmptyField(indices)) {
    // If not and have no clue about the expected types, ask for all indices.
    // Worst case scenario that need to be avoided.
    if (isEmptyField(types)) {
      return withInferences ? READ_DATA_INDICES : READ_DATA_INDICES_WITHOUT_INFERRED;
    }
    // If types are defined we need to infer from them the correct indices
    const definedTypes = types as string[];
    return R.uniq(definedTypes.map((findType) => {
      // If defined types are abstract, try to restrict the indices as much as possible
      if (isAbstract(findType)) {
        // For objects
        if (isBasicObject(findType)) {
          if (isInternalObject(findType)) {
            return withInferencesEntities([READ_INDEX_INTERNAL_OBJECTS], withInferences);
          }
          if (isStixMetaObject(findType)) {
            return withInferencesEntities([READ_INDEX_STIX_META_OBJECTS], withInferences);
          }
          if (isStixDomainObject(findType)) {
            return withInferencesEntities([READ_INDEX_STIX_DOMAIN_OBJECTS], withInferences);
          }
          if (isStixCoreObject(findType)) {
            return withInferencesEntities([READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES], withInferences);
          }
          if (isStixObject(findType)) {
            return withInferencesEntities([READ_INDEX_STIX_META_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES], withInferences);
          }
          return withInferences ? READ_ENTITIES_INDICES : READ_ENTITIES_INDICES_WITHOUT_INFERRED;
        }
        // For relationships
        if (isBasicRelationship(findType) || STIX_REF_RELATIONSHIP_TYPES.includes(findType)) {
          if (isInternalRelationship(findType)) {
            return withInferencesRels([READ_INDEX_INTERNAL_RELATIONSHIPS], withInferences);
          }
          if (isStixSightingRelationship(findType)) {
            return withInferencesRels([READ_INDEX_STIX_SIGHTING_RELATIONSHIPS], withInferences);
          }
          if (isStixCoreRelationship(findType)) {
            return withInferencesRels([READ_INDEX_STIX_CORE_RELATIONSHIPS], withInferences);
          }
          if (isStixRefRelationship(findType) || STIX_REF_RELATIONSHIP_TYPES.includes(findType)) {
            return withInferencesRels([READ_INDEX_STIX_META_RELATIONSHIPS, READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS], withInferences);
          }
          if (isStixRelationship(findType)) {
            return withInferencesRels([READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS, READ_INDEX_STIX_META_RELATIONSHIPS,
              READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS], withInferences);
          }
          return withInferences ? READ_RELATIONSHIPS_INDICES : READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED;
        }
        // Fallback
        throw UnsupportedError('Fail to compute indices for unknown type', { type: findType });
      }
      // If concrete type, infer the index from the type
      if (isBasicObject(findType)) {
        return withInferencesEntities([`${inferIndexFromConceptType(findType)}*`], withInferences);
      }
      return withInferencesRels([`${inferIndexFromConceptType(findType)}*`], withInferences);
    }).flat());
  }
  return indices;
};
