import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { createdBy, externalReferences, objectLabel, objectMarking } from '../../schema/stixRefRelationship';

const stixCoreObjectsMetaRel = [createdBy, objectMarking, objectLabel, externalReferences];

schemaRelationsRefDefinition.registerRelationsRef(
  ABSTRACT_STIX_CORE_OBJECT,
  stixCoreObjectsMetaRel,
);
