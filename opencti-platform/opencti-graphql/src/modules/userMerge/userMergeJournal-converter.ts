import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';
import type { StixUserMergeJournal, StoreEntityUserMergeJournal } from './userMergeJournal-types';

const convertUserMergeJournalToStix = (instance: StoreEntityUserMergeJournal): StixUserMergeJournal => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    merge_id: instance.merge_id,
    source_user_id: instance.source_user_id,
    target_user_id: instance.target_user_id,
    handler: instance.handler,
    dry_run: instance.dry_run,
    status: instance.status,
    started_at: instance.started_at,
    completed_at: instance.completed_at,
    message: instance.message,
    output: instance.output,
    updated_count: instance.updated_count,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertUserMergeJournalToStix;
