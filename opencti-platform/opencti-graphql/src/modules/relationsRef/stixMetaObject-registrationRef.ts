import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_STIX_META_OBJECT } from '../../schema/general';

export const registerStixMetaObjectRelationsRefs = () => {
  schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_META_OBJECT, []);
};
