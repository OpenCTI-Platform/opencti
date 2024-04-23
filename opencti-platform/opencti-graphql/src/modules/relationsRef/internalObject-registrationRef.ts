import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { objectMarking, objectOrganization } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_INTERNAL_FILE, ENTITY_TYPE_USER, ENTITY_TYPE_WORK } from '../../schema/internalObject';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';

schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_INTERNAL_OBJECT, []);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INTERNAL_FILE, [objectMarking]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_WORK, [objectMarking]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_USER, [objectOrganization]);
