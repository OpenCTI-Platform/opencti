import { v4 as uuidv4 } from 'uuid';
import { ENTITY_TYPE_WORKSPACE_USER_STATE, type StixWorkspaceUserState, type StoreEntityWorkspaceUserState } from './workspaceUserState-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import convertWorkspaceUserStateToStix from './workspaceUserState-converter';
import { creators, createdAt } from '../../schema/attribute-definition';

const WORKSPACE_USER_STATE_DEFINITION: ModuleDefinition<StoreEntityWorkspaceUserState, StixWorkspaceUserState> = {
  type: {
    id: 'workspace-user-states',
    name: ENTITY_TYPE_WORKSPACE_USER_STATE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_WORKSPACE_USER_STATE]: () => uuidv4(),
    },
  },
  attributes: [
    creators,
    createdAt,
    {
      name: 'workspace_id',
      label: 'Workspace ID',
      type: 'string',
      format: 'short',
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
    {
      name: 'variable_values',
      label: 'Variable values',
      type: 'string',
      format: 'text',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
  ],
  relations: [],
  representative: (instance: StixWorkspaceUserState) => {
    return instance.workspace_id;
  },
  converter_2_1: convertWorkspaceUserStateToStix,
};

registerDefinition(WORKSPACE_USER_STATE_DEFINITION);
