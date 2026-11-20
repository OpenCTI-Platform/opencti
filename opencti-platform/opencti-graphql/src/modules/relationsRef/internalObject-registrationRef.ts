import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { objectMarking } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_WORK } from '../../schema/internalObject';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';

export const registerInternalObjectRelationsRefs = () => {
  schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_INTERNAL_OBJECT, []);
  schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_WORK, [objectMarking]);
};
