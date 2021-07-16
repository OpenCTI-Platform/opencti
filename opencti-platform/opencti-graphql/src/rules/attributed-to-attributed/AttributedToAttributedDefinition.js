import { RELATION_ATTRIBUTED_TO } from '../../schema/stixCoreRelationship';

const id = 'attribution_attribution';
const name = 'Attribution via attribution';
const description =
  'If **entity A** is `attributed-to` **entity B** and **entity B** ' +
  'is `attributed-to` **entity C**, then **entity A** is `attributed-to` **entity C**.';

// For rescan
const scan = { types: [RELATION_ATTRIBUTED_TO] };

// For live
const filters = { types: [RELATION_ATTRIBUTED_TO] };
const attributes = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];
const scopes = [{ filters, attributes }];

const definition = { id, name, description, scan, scopes };
export default definition;
