import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_CONTAINER, ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION } from '../../schema/general';
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
  samples
} from '../../schema/stixRefRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY
} from '../../schema/stixDomainObject';

import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';

schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_DOMAIN_OBJECT, [createdBy, objectMarking, objectLabel, externalReferences]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER, [objects]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_IDENTITY, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_LOCATION, []);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_ATTACK_PATTERN, [killChainPhases, { ...objectOrganization, isFilterable: false }]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INFRASTRUCTURE, [killChainPhases, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_MALWARE, [
  samples, operatingSystems,
  killChainPhases,
  objectOrganization
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_TOOL, [killChainPhases, objectOrganization]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CAMPAIGN, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_REPORT, [objectAssignee, objectOrganization, objectParticipant]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INTRUSION_SET, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_THREAT_ACTOR_GROUP, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INCIDENT, [objectAssignee, objectOrganization, objectParticipant]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_NOTE, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, [{ ...objects, mandatoryType: 'external' }, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_OPINION, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_COURSE_OF_ACTION, [{ ...objectOrganization, isFilterable: false }]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_GROUPING, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_VULNERABILITY, [objectOrganization]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_IDENTITY_SYSTEM, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_IDENTITY_SECTOR, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_IDENTITY_INDIVIDUAL, [objectOrganization]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_LOCATION_REGION, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_LOCATION_CITY, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_LOCATION_COUNTRY, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_LOCATION_POSITION, []);
