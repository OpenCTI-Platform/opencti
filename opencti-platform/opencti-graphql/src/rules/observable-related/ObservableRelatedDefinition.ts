import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import {
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
} from '../../schema/stixDomainObject';
import type { RuleDefinition } from '../../types/rules';

const id = 'observable_related';
const name = 'Relation propagation via an observable';
const description = 'Propagate relation between 2 objects via a common observable.';
const category = 'Correlation';
const display = {
  if: [
    {
      source: 'Observable A',
      source_color: '#ff9800',
      relation: 'relationship_related-to',
      target: 'Entity B',
      target_color: '#4caf50',
    },
    {
      source: 'Observable A',
      source_color: '#ff9800',
      relation: 'relationship_related-to',
      target: 'Entity C',
      target_color: '#00bcd4',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_related-to',
      source: 'Entity B',
      source_color: '#4caf50',
      target: 'Entity C',
      target_color: '#00bcd4',
    },
  ],
};

// For rescan
const scan = {
  types: [RELATION_RELATED_TO],
  fromTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE],
  toTypes: [
    ENTITY_TYPE_THREAT_ACTOR,
    ENTITY_TYPE_INTRUSION_SET,
    ENTITY_TYPE_CAMPAIGN,
    ENTITY_TYPE_INCIDENT,
    ENTITY_TYPE_MALWARE,
  ],
};

// For live
const filters = {
  types: [RELATION_RELATED_TO],
  fromTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE],
  toTypes: [
    ENTITY_TYPE_THREAT_ACTOR,
    ENTITY_TYPE_INTRUSION_SET,
    ENTITY_TYPE_CAMPAIGN,
    ENTITY_TYPE_INCIDENT,
    ENTITY_TYPE_MALWARE,
  ],
};
const attributes = [
  { name: 'start_time' },
  { name: 'stop_time' },
  { name: 'confidence' },
  { name: 'object_marking_refs' },
];
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
