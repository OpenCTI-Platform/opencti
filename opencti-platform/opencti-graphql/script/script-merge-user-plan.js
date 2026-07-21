// PoC merge-users #3 - schema-driven, dry-run merge plan.
// Usage:
//   node build/script-merge-user-plan.js --sourceId=<id> --targetId=<id>
//   node build/script-merge-user-plan.js --csv=<path-to-csv>   (columns: source_id,target_id)
// This script NEVER writes to Elasticsearch: it only prints the plan of operations that a
// future merge engine would need to execute.
import '../src/modules/index';
import { logApp } from '../src/config/conf';
import { buildMergeUserPlan, parseMergeUserCsv } from '../src/utils/merge-user-plan';

const getArg = (name) => {
  const arg = process.argv.find((a) => a.startsWith(`--${name}=`));
  return arg ? arg.split('=').slice(1).join('=') : undefined;
};

const sourceId = getArg('sourceId');
const targetId = getArg('targetId');
const csvPath = getArg('csv');

const pairs = csvPath
  ? parseMergeUserCsv(csvPath)
  : (sourceId && targetId ? [{ sourceId, targetId }] : []);

if (pairs.length === 0) {
  logApp.error('[SCRIPT] Missing arguments. Usage: --sourceId=<id> --targetId=<id> or --csv=<path>');
  process.exit(1);
}

const plans = pairs.map((pair) => buildMergeUserPlan(pair));
// eslint-disable-next-line no-console
console.log(JSON.stringify(csvPath ? plans : plans[0], null, 2));
