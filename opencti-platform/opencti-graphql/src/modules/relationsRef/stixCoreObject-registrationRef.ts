import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { createdBy, externalReferences, inPir, objectLabel, objectMarking } from '../../schema/stixRefRelationship';
import { isFeatureEnabled } from '../../config/conf';

const stixCoreObjectsMetaRel = [createdBy, objectMarking, objectLabel, externalReferences];
if (isFeatureEnabled('Pir')) {
  stixCoreObjectsMetaRel.push(inPir);
}

schemaRelationsRefDefinition.registerRelationsRef(
  ABSTRACT_STIX_CORE_OBJECT,
  stixCoreObjectsMetaRel,
);
