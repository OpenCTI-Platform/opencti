import { RELATION_LOCATED_AT, RELATION_TARGETS } from '../../schema/stixCoreRelationship';

const id = 'location_targets';
const name = 'Targets via location';
const description =
  'If **entity A** `targets` **entity B** and **entity B** is ' +
  '`located-at` **entity C**, then **entity A** `targets` **entity C**.';

// For rescan
const scan = { types: [RELATION_TARGETS] };

// For live
const filters = { types: [RELATION_TARGETS, RELATION_LOCATED_AT] };
const attributes = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];
const scopes = [{ filters, attributes }];

const definition = { id, name, description, scan, scopes };
export default definition;
