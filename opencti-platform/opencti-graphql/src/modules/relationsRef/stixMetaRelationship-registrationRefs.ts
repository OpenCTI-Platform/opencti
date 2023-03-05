import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  ENTITY_TYPE_CONTAINER
} from '../../schema/general';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../administrativeArea/administrativeArea-types';
import { ENTITY_TYPE_CHANNEL } from '../channel/channel-types';
import { ENTITY_TYPE_EVENT } from '../event/event-types';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { ENTITY_TYPE_NARRATIVE } from '../narrative/narrative-types';
import {
  createdBy,
  externalReferences,
  killChainPhases,
  objectAssignee,
  objectLabel,
  objectMarking,
  objectOrganization,
  objects
} from '../../schema/stixMetaRelationship';
import { operatingSystems, samples } from '../../schema/stixCyberObservableRelationship';

schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_DOMAIN_OBJECT, [createdBy, objectMarking, objectLabel, externalReferences]);
schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_CYBER_OBSERVABLE, [createdBy, objectMarking, objectLabel, externalReferences]);
schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_RELATIONSHIP, [createdBy, objectMarking, objectLabel, externalReferences, { ...killChainPhases, mandatoryType: 'no' }]);
schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_CORE_RELATIONSHIP, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(STIX_SIGHTING_RELATIONSHIP, [objectOrganization]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER, [objects]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_ATTACK_PATTERN, [killChainPhases, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INDICATOR, [killChainPhases]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INFRASTRUCTURE, [killChainPhases, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_MALWARE, [samples, operatingSystems, killChainPhases, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_TOOL, [killChainPhases]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CAMPAIGN, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_REPORT, [objectAssignee, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INTRUSION_SET, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_THREAT_ACTOR, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INCIDENT, [objectAssignee, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_CASE, [ // Case cant use standard mandatory attributes, waiting a split from feedbacks
  { ...createdBy, mandatoryType: 'no' }, { ...objectMarking, mandatoryType: 'no' }, { ...objectAssignee, mandatoryType: 'no' }, objectOrganization]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_NOTE, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, [{ ...objects, mandatoryType: 'external' }, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_OPINION, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_COURSE_OF_ACTION, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CHANNEL, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_DATA_SOURCE, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_DATA_COMPONENT, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_EVENT, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_GROUPING, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_NARRATIVE, [objectOrganization]);
