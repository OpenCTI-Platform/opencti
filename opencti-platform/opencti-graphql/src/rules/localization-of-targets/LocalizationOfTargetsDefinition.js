import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';

const id = 'localization_of_targets';
const name = 'Location of targets';
const description =
  'If `entity A` **targets** `entity B` through `relation X`, and `relation X` is **located-at** `entity C`,' +
  ' then `entity A` **targets**  `entity C`';

// For rescan
const scanFilters = { types: [RELATION_LOCATED_AT] };

// For live
const scopeFilters = { types: [RELATION_LOCATED_AT] };
const scopePatch = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];

const definition = { id, name, description, scanFilters, scopeFilters, scopePatch };
export default definition;
