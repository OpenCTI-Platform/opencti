import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { createdBy, externalReferences, inPir, objectLabel, objectMarking } from '../../schema/stixRefRelationship';

schemaRelationsRefDefinition.registerRelationsRef(
  ABSTRACT_STIX_CORE_OBJECT,
  [createdBy, objectMarking, objectLabel, externalReferences, inPir]
);
