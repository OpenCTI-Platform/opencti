import { RELATION_ATTRIBUTED_TO, RELATION_USES } from '../../schema/stixCoreRelationship';

const id = 'attribution_use';
const name = 'Usage via attribution';
const description =
  'If `entity A` **uses** `entity B` and `entity A` is ' +
  '**attributed-to** `entity C`, then `entity C` **uses** `entity B`.';

// For rescan
const scanFilters = { types: [RELATION_ATTRIBUTED_TO] };

// For live
const scopeFilters = { types: [RELATION_USES, RELATION_ATTRIBUTED_TO] };
const scopePatch = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];

const definition = { id, name, description, scanFilters, scopeFilters, scopePatch };
export default definition;
