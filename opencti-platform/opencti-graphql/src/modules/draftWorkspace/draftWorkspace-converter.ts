import { buildStixObject, } from '../../database/stix-converter';
import type { StixDraftWorkspace, StoreEntityDraftWorkspace } from './draftWorkspace-types';

const convertDraftWorkspaceToStix = (instance: StoreEntityDraftWorkspace): StixDraftWorkspace => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
  };
};

export default convertDraftWorkspaceToStix;
