import conf, { booleanConf } from '../../config/conf';
import { ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../schema/stixDomainObject';
import { RELATION_ATTRIBUTED_TO, RELATION_TARGETS, RELATION_USES } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../threatActorIndividual/threatActorIndividual-types';

// Kill switch: when disabled, provenance must cost nothing. Every write path, background manager,
// telemetry query and STIX extension of the provenance module is gated on this flag.
export const PROVENANCE_ENABLED = booleanConf('provenance:enabled', true);

// A source re-asserting an element it already asserted within this window costs no write.
// Freshness is measured in days, so the last assertion date only needs this precision.
export const PROVENANCE_REASSERTION_WINDOW_MS = Number(conf.get('provenance:reassertion_window_hours') ?? 24) * 60 * 60 * 1000;

// Relationship types tracked out of the box: seeded on the relationships setting of a new platform, enabled on an
// existing one by migration, and restored by the "Recommended" action. 'indicates' is left out: indicator feeds
// re-assert it with every indicator, doubling their writes for a corroboration the indicator already carries.
export const PROVENANCE_RECOMMENDED_RELATIONSHIP_TYPES: string[] = [RELATION_USES, RELATION_TARGETS, RELATION_ATTRIBUTED_TO];

// Types tracked while their entity setting does not say otherwise ('*' tracks every type).
export const PROVENANCE_DEFAULT_TRACKED_TYPES: string[] = conf.get('provenance:default_tracked_types') ?? [
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
  ENTITY_TYPE_MALWARE,
  ...PROVENANCE_RECOMMENDED_RELATIONSHIP_TYPES,
];
