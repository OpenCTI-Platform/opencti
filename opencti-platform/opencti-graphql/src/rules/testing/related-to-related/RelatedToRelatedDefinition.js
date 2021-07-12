import { RELATION_RELATED_TO } from '../../../schema/stixCoreRelationship';

const id = 'related_related';
const name = 'Related testing';
const description = 'Test related rule';

// For rescan
const scanFilters = { types: [RELATION_RELATED_TO] };

// For live
const scopeFilters = { types: [RELATION_RELATED_TO] };
const scopePatch = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];

const definition = { id, name, description, scanFilters, scopeFilters, scopePatch };
export default definition;
