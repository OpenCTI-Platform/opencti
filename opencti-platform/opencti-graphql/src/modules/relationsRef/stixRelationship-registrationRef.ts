import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP } from '../../schema/general';
import { createdBy, externalReferences, killChainPhases, objectLabel, objectMarking, objectOrganization } from '../../schema/stixRefRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';

schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_RELATIONSHIP, [createdBy, objectMarking, objectLabel, externalReferences, { ...killChainPhases, mandatoryType: 'no' }]);

schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_CORE_RELATIONSHIP, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(STIX_SIGHTING_RELATIONSHIP, [objectOrganization]);
