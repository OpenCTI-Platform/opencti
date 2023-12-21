import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_CONTAINER } from '../../schema/general';
import {
  createdBy,
  externalReferences,
  killChainPhases,
  objectAssignee,
  objectLabel,
  objectMarking,
  objectOrganization,
  objectParticipant,
  objects,
  operatingSystems,
  samples,
  xOpenctiLinkedTo
} from '../../schema/stixRefRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_SOFTWARE } from '../../schema/stixCyberObservable';

schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_DOMAIN_OBJECT, [createdBy, objectMarking, objectLabel, externalReferences, xOpenctiLinkedTo]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER, [objects]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_ATTACK_PATTERN, [killChainPhases, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INFRASTRUCTURE, [killChainPhases, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_MALWARE, [{
  ...samples,
  checker: (_, toType) => [ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE].includes(toType)
},
{
  ...operatingSystems,
  checker: (_, toType) => ENTITY_SOFTWARE === toType
}, killChainPhases, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_TOOL, [killChainPhases, objectOrganization]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CAMPAIGN, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_REPORT, [objectAssignee, objectOrganization, objectParticipant]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INTRUSION_SET, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_THREAT_ACTOR_GROUP, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INCIDENT, [objectAssignee, objectOrganization, objectParticipant]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_NOTE, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, [{ ...objects, mandatoryType: 'external' }, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_OPINION, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_COURSE_OF_ACTION, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_GROUPING, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_VULNERABILITY, [objectOrganization]);
