import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { objectMarking, objectOrganization } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_USER, ENTITY_TYPE_WORK } from '../../schema/internalObject';

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_WORK, [objectMarking]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_USER, [objectOrganization]);
