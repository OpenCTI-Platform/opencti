import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';
import type { StixKnowledgeSnapshot, StixUserVisit, StoreEntityKnowledgeSnapshot, StoreEntityUserVisit } from './timeMachine-types';

export const convertKnowledgeSnapshotToStix = (instance: StoreEntityKnowledgeSnapshot): StixKnowledgeSnapshot => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    entity_id: instance.entity_id,
    target_entity_type: instance.target_entity_type,
    snapshot_date: instance.snapshot_date,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export const convertUserVisitToStix = (instance: StoreEntityUserVisit): StixUserVisit => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    user_id: instance.user_id,
    entity_id: instance.entity_id,
    last_seen_at: instance.last_seen_at,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};
