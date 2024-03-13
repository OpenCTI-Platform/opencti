import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_INTERNAL_RELATIONSHIP } from '../../schema/general';
import { objectMarking } from '../../schema/stixRefRelationship';

schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_INTERNAL_RELATIONSHIP, [objectMarking]);
