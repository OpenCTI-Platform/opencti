import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';

const id = 'observable_related';
const name = 'Related via observable';
const description =
  'If **observable A** is `related-to` **entity B** and **observable A** ' +
  'is `related-to` **entity C**, then **entity B** is `related-to` **entity C**.';

// For rescan
const scanFilters = { types: [RELATION_RELATED_TO], fromTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE] };

// For live
const scopeFilters = { types: [RELATION_RELATED_TO], fromTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE] };
const scopePatch = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];

const definition = { id, name, description, scanFilters, scopeFilters, scopePatch };
export default definition;
