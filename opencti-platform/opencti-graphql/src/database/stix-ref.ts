import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';

export const schemaRelationsRefTypesMapping = () => {
  return Array.from(schemaRelationsRefDefinition.relationsRefCacheArray.entries()).map(([key, refs]) => {
    return {
      key,
      values: refs.map((ref) => ({
        name: ref.name,
        toTypes: ref.toTypes
      }))
    };
  });
};
