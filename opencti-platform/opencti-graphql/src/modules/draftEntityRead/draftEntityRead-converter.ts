import type { StixDraftEntityRead, StoreEntityDraftEntityRead } from './draftEntityRead-types';
import { buildStixObject } from '../../database/stix-2-1-converter';

const convertDraftEntityReadToStix = (instance: StoreEntityDraftEntityRead): StixDraftEntityRead => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    user_id: instance.user_id,
    draft_id: instance.draft_id,
    entity_id: instance.entity_id,
    is_read: instance.is_read,
  };
};

export default convertDraftEntityReadToStix;
