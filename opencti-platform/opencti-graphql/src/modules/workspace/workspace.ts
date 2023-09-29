import { v4 as uuidv4 } from 'uuid';
import workspaceTypeDefs from './workspace.graphql';
import { normalizeName } from '../../schema/identifier';
import workspaceResolvers from './workspace-resolver';
import { ENTITY_TYPE_WORKSPACE, type StixWorkspace, type StoreEntityWorkspace } from './workspace-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import convertWorkspaceToStix from './workspace-converter';

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
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'manifest', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'type', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'tags', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
    { name: 'graph_data', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'investigated_entities_ids', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
    { name: 'authorized_members', type: 'json', mandatoryType: 'no', multiple: true, upsert: false },
  ],
  relations: [],
  representative: (stix: StixWorkspace) => {
    return stix.name;
  },
  converter: convertWorkspaceToStix
};

registerDefinition(WORKSPACE_DEFINITION);
