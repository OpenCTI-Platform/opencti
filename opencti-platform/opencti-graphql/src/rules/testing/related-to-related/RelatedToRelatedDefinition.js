import { RELATION_RELATED_TO } from '../../../schema/stixCoreRelationship';

const id = 'related_related';
const name = 'Related testing';
const description = 'Test related rule';

// For rescan
const scan = { types: [RELATION_RELATED_TO] };

// For live
const filters = { types: [RELATION_RELATED_TO] };
const attributes = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];
const scopes = [{ filters, attributes }];

const definition = { id, name, description, scan, scopes };
export default definition;
