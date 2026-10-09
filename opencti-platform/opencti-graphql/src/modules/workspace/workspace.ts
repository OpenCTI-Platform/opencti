import { v4 as uuidv4 } from 'uuid';
import { normalizeName } from '../../schema/identifier';
import { ENTITY_TYPE_WORKSPACE } from './workspace-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { InternalObjectModuleDefinition } from '../../schema/module';
import { registerInternalObjectDefinition } from '../../schema/module';
import { authorizedMembers, draftChange } from '../../schema/attribute-definition';

export const WORKSPACE_DEFINITION: InternalObjectModuleDefinition = {
  type: {
    id: 'workspaces',
    name: ENTITY_TYPE_WORKSPACE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_WORKSPACE]: () => uuidv4(),
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'openCTI_version', label: 'OpenCTI version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'manifest', label: 'Manifest', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'type', label: 'Type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'tags', label: 'Tags', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'graph_data', label: 'Workspace graph data', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'investigated_entities_ids', label: 'Investigated entities', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'refresh_interval', label: 'Refresh interval', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { ...draftChange, isFilterable: false },
    authorizedMembers,
  ],
  relations: [],
};

registerInternalObjectDefinition(WORKSPACE_DEFINITION);
