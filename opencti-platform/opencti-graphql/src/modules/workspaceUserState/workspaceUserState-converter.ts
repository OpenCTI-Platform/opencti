import type { StixWorkspaceUserState, StoreEntityWorkspaceUserState } from './workspaceUserState-types';
import { buildStixObject } from '../../database/stix-2-1-converter';

const convertWorkspaceUserStateToStix = (instance: StoreEntityWorkspaceUserState): StixWorkspaceUserState => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    workspace_id: instance.workspace_id,
    variable_values: instance.variable_values,
  };
};

export default convertWorkspaceUserStateToStix;
