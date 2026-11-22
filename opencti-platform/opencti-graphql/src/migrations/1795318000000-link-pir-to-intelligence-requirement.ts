import { logMigration } from '../config/conf';
import { migratePirsToRequirements } from '../modules/intelligenceRequirement/intelligenceRequirement-pirMigration';
import { executionContext } from '../utils/access';

const message = '[MIGRATION] Converting every Pir into an intelligence requirement';

// Full replacement of the PIR engine (opencti #20278). Every Pir becomes an intelligence requirement with the same criteria,
// filters, weights, rescan window, authorized members, flags and scores; then the Pir is deleted. Every playbook that starts on
// "Listen PIR events" is rewritten to "Listen intelligence requirement events" on the requirements the Pirs became.
// Idempotent and resumable: a converted Pir is gone, a half-converted one is finished (its requirement and entities kept).
// A Pir that fails (its flags would change, or an error) is logged, kept and reported; its playbooks are kept unchanged.
export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const report = await migratePirsToRequirements(context);
  report.failed.forEach((failure) => {
    if (!failure.converted) {
      logMigration.error(`${message} > Pir ${failure.pir_id} (${failure.name}) kept: ${failure.reason}`, { mismatches: failure.mismatches });
    }
  });
  report.playbooks_kept.forEach((kept) => {
    logMigration.error(`${message} > playbook ${kept.playbook_id} kept on "Listen PIR events": ${kept.reason}`);
  });
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms (${report.pirs} Pir, ${report.converted} converted, ${report.failed.length} kept; `
    + `${report.playbooks_rewritten} playbook(s) rewritten, ${report.playbooks_kept.length} kept)`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
