import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { STIX_CORE_RELATIONSHIPS } from '../schema/stixCoreRelationship';
import type { RefAttribute } from '../schema/attribute-definition';

export const schemaRelationsRefTypesMapping = () => {
  const relationshipsRefs = new Map<string, RefAttribute[]>();
  STIX_CORE_RELATIONSHIPS.forEach((relation) => {
    relationshipsRefs.set(relation, schemaRelationsRefDefinition.getRelationsRef(relation));
  });
  return [
    ...Array.from(relationshipsRefs.entries()),
    ...Array.from(schemaRelationsRefDefinition.relationsRefCacheArray.entries())
  ].map(([key, refs]) => {
    return {
      key,
      values: refs.map((ref) => ({
        name: ref.name,
        toTypes: ref.toTypes
      }))
    };
  });
};
