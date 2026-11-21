import * as R from 'ramda';
import { logMigration } from '../config/conf';
import { patchAttribute } from '../database/middleware';
import { internalLoadById } from '../database/middleware-loader';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { MARKING_TLP_OASIS_V2_ALIASES } from '../schema/identifier';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Add the OASIS TLP 2.0 ids to the static TLP markings';

// The static TLP markings keep their ids; the OASIS TLP 2.0 ids become other STIX ids of them
// so a reference to marking-definition--94868c89-... (TLP:CLEAR) and the four others resolves.
export const up = async (next: () => void) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  let count = 0;
  const entries = Object.entries(MARKING_TLP_OASIS_V2_ALIASES);
  for (let index = 0; index < entries.length; index += 1) {
    const [standardId, aliasIds] = entries[index];
    const marking = await internalLoadById(context, SYSTEM_USER, standardId) as any;
    // A static marking can be deleted on some platforms
    if (marking && marking.entity_type === ENTITY_TYPE_MARKING_DEFINITION) {
      const currentStixIds: string[] = marking.x_opencti_stix_ids ?? [];
      const idsToAdd: string[] = [];
      for (let aliasIndex = 0; aliasIndex < aliasIds.length; aliasIndex += 1) {
        const aliasId = aliasIds[aliasIndex];
        if (!currentStixIds.includes(aliasId)) {
          // Never take an id another element already answers to
          const holder = await internalLoadById(context, SYSTEM_USER, aliasId) as any;
          if (!holder || holder.internal_id === marking.internal_id) {
            idsToAdd.push(aliasId);
          } else {
            logMigration.warn(`${message} > ${aliasId} already held by ${holder.internal_id}, skipped`);
          }
        }
      }
      if (idsToAdd.length > 0) {
        await patchAttribute(context, SYSTEM_USER, marking.internal_id, ENTITY_TYPE_MARKING_DEFINITION, {
          x_opencti_stix_ids: R.uniq([...currentStixIds, ...idsToAdd]),
        });
        count += idsToAdd.length;
      }
    }
  }
  logMigration.info(`${message} > done. ${count} ids added.`);
  next();
};

export const down = async (next: () => void) => {
  next();
};
