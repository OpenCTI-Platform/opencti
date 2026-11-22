import { logMigration } from '../config/conf';
import { fullEntitiesList } from '../database/middleware-loader';
import { type BasicStoreEntityPir, ENTITY_TYPE_PIR } from '../modules/pir/pir-types';
import { linkPirToRequirement } from '../modules/intelligenceRequirement/intelligenceRequirement-pirLink';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Linking every Pir to its intelligence requirement';

// Every existing Pir gets the intelligence requirement built from its criteria, filters, weights, rescan window and members
// (pir_requirement_id on the Pir, ir_pir_id on the requirement). The engine of the Pir is not changed: the legacy manager
// keeps flagging it and the requirement stays paused, so an instance behaves exactly as before after this migration.
// Idempotent and resumable: a Pir already linked to an existing requirement is skipped, a broken link is rebuilt,
// and a Pir that fails is logged and left for the next run without stopping the others.
export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const pirs = await fullEntitiesList<BasicStoreEntityPir>(context, SYSTEM_USER, [ENTITY_TYPE_PIR]);
  let linked = 0;
  let failed = 0;
  for (let i = 0; i < pirs.length; i += 1) {
    const pir = pirs[i];
    try {
      const before = pir.pir_requirement_id;
      const requirementId = await linkPirToRequirement(context, pir);
      if (requirementId !== before) linked += 1;
    } catch (err) {
      failed += 1;
      logMigration.error(`${message} > Pir not linked`, { cause: err, pir: pir.id });
    }
  }
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms (${pirs.length} Pir, ${linked} linked, ${failed} failed)`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
