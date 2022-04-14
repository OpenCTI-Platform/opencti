import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import {
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
} from '../../schema/stixDomainObject';
import type { RuleDefinition, RuleBehavior } from '../../types/rules';

const id = 'observable_related';
const name = 'Related via observable';
const description = 'If **observable A** is `related-to` **entity B** and **observable A** '
  + 'is `related-to` **entity C**, then **entity B** is `related-to` **entity C**.';

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
const behaviors: Array<RuleBehavior> = [];
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, behaviors };
export default definition;
