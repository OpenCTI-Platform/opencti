import { v4 as uuidv4 } from 'uuid';
import workspaceTypeDefs from './workspace.graphql';
import { normalizeName } from '../../schema/identifier';
import workspaceResolvers from './workspace-resolver';
import { ENTITY_TYPE_WORKSPACE, type StixWorkspace, type StoreEntityWorkspace } from './workspace-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import convertWorkspaceToStix from './workspace-converter';
import { authorizedMembers } from '../../schema/attribute-definition';

const WORKSPACE_DEFINITION: ModuleDefinition<StoreEntityWorkspace, StixWorkspace> = {
  type: {
    id: 'workspaces',
    name: ENTITY_TYPE_WORKSPACE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  graphql: {
    schema: workspaceTypeDefs,
    resolver: workspaceResolvers,
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
    { name: 'description', label: 'Description', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'openCTI_version', label: 'Platform version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'manifest', label: 'Manifest', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'type', label: 'Type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'tags', label: 'Tags', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'graph_data', label: 'Graph data', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'investigated_entities_ids', label: 'Investigated entities', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    authorizedMembers
  ],
  relations: [],
  representative: (stix: StixWorkspace) => {
    return stix.name;
  },
  converter: convertWorkspaceToStix
};

registerDefinition(WORKSPACE_DEFINITION);
