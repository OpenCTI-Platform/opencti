import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';

const id = 'observable_related';
const name = 'Related via observable';
const description =
  'If **observable A** is `related-to` **entity B** and **observable A** ' +
  'is `related-to` **entity C**, then **entity B** is `related-to` **entity C**.';

// For rescan
const scan = { types: [RELATION_RELATED_TO], fromTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE] };

// For live
const filters = { types: [RELATION_RELATED_TO], fromTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE] };
const attributes = [
  { name: 'start_time' },
  { name: 'stop_time' },
  { name: 'confidence' },
  { name: 'object_marking_refs' },
];
const scopes = [{ filters, attributes }];

const definition = { id, name, description, scan, scopes };
export default definition;
