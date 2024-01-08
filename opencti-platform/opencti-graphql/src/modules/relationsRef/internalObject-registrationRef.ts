import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { objectOrganization } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';

schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_INTERNAL_OBJECT, []);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_USER, [objectOrganization]);
