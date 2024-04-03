import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import {
  createdBy,
  externalReferences,
  internalFiles,
  objectLabel,
  objectMarking,
  work,
  xOpenctiLinkedTo
} from '../../schema/stixRefRelationship';

schemaRelationsRefDefinition.registerRelationsRef(
  ABSTRACT_STIX_CORE_OBJECT,
  [createdBy, objectMarking, objectLabel, externalReferences, internalFiles, work, xOpenctiLinkedTo]
);
