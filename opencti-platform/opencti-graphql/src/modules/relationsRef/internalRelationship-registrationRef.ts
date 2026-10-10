import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_INTERNAL_RELATIONSHIP } from '../../schema/general';

export const registerInternalRelationshipRelationsRefs = () => {
  schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_INTERNAL_RELATIONSHIP, []);
};
