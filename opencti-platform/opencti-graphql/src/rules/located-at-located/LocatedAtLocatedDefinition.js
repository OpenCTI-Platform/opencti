import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';

const id = 'location_location';
const name = 'Location via location';
const description =
  'If `entity A` is **located-at** `entity B` and `entity B` ' +
  'is **located-at** `entity C`, then `entity A` is **located-at** `entity C`.';

// For rescan
const scanFilters = { types: [RELATION_LOCATED_AT] };

// For live
const scopeFilters = { types: [RELATION_LOCATED_AT] };
const scopePatch = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];

const definition = { id, name, description, scanFilters, scopeFilters, scopePatch };
export default definition;
