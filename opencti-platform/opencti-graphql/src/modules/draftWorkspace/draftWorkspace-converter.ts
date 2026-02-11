import { buildStixObject } from '../../database/stix-2-1-converter';
import type { StixDraftWorkspace, StoreEntityDraftWorkspace } from './draftWorkspace-types';
import { INPUT_OBJECTS } from '../../schema/general';

const convertDraftWorkspaceToStix = (instance: StoreEntityDraftWorkspace): StixDraftWorkspace => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    draft_status: instance.draft_status,
    description: instance.description,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
  };
};

export default convertDraftWorkspaceToStix;
