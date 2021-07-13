import { RELATION_PART_OF, RELATION_TARGETS } from '../../schema/stixCoreRelationship';

const id = 'part-of_targets';
const name = 'Targets via Part-Of';
const description =
  'If `entity A` **targets** `entity B` and `entity B` is ' +
  '**part-of** `entity C`, then `entity A` **targets** `entity C`.';

// For rescan
const scanFilters = { types: [RELATION_TARGETS] };

// For live
const scopeFilters = { types: [RELATION_TARGETS, RELATION_PART_OF] };
const scopePatch = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];

const definition = { id, name, description, scanFilters, scopeFilters, scopePatch };
export default definition;
