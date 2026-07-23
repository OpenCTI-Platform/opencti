// PoC (merge-users #1, iteration 2): read-only footprint scan for a user internal_id.
// Counts unique documents per persistent Elasticsearch scope and classifies known
// references according to the proposed merge disposition matrix.
//
// Usage:
//   yarn build:dev
//   yarn poc:user-footprint --userId=<internal_id>
import '../src/modules/index';
import fs from 'node:fs';
import { executionContext, SYSTEM_USER } from '../src/utils/access';
import { logApp } from '../src/config/conf';
import { elRawSearch, searchEngineInit } from '../src/database/engine';
import { READ_DATA_INDICES, READ_INDEX_DELETED_OBJECTS, READ_INDEX_DRAFT_OBJECTS, READ_INDEX_FILES, READ_INDEX_HISTORY } from '../src/database/utils';
import { schemaAttributesDefinition } from '../src/schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../src/schema/schema-relationsRef';
import { ENTITY_TYPE_USER } from '../src/schema/internalObject';
import { INPUT_ASSIGNEE, INPUT_PARTICIPANT } from '../src/schema/general';
import { buildUserFootprintScopes, buildUserFootprintSearch, parseUserFootprintSearch, summarizeUserFootprint, USER_FOOTPRINT_COVERAGE } from '../src/utils/user-footprint';

const REPORT_FILE = './poc-user-footprint-report.json';

const userIdArg = process.argv.find((arg) => arg.startsWith('--userId='));
const userId = userIdArg?.split('=')[1] || null;

if (!userId) {
  logApp.error('[POC] Missing required --userId=<internal_id> argument');
  process.exit(1);
}

const run = async () => {
  await searchEngineInit();
  const context = executionContext('poc-user-footprint');

  const userIdAttributeNames = [...new Set(
    schemaAttributesDefinition.getIdAttributes()
      .filter((attr) => (attr.entityTypes ?? []).includes(ENTITY_TYPE_USER))
      .map((attr) => attr.name),
  )];
  logApp.info(`[POC] Discovered ${userIdAttributeNames.length} schema id-attribute(s) referencing User`, { attributes: userIdAttributeNames });

  const assigneeDatabaseName = schemaRelationsRefDefinition.getDatabaseName(INPUT_ASSIGNEE);
  const participantDatabaseName = schemaRelationsRefDefinition.getDatabaseName(INPUT_PARTICIPANT);
  if (!assigneeDatabaseName || !participantDatabaseName) {
    throw new Error('Unable to resolve physical assignee/participant relationship fields');
  }

  const scopes = buildUserFootprintScopes({
    userId,
    schemaFieldNames: userIdAttributeNames,
    indices: {
      active: READ_DATA_INDICES,
      draft: READ_INDEX_DRAFT_OBJECTS,
      history: READ_INDEX_HISTORY,
      files: READ_INDEX_FILES,
      deleted: READ_INDEX_DELETED_OBJECTS,
    },
    relationDatabaseNames: {
      assignee: assigneeDatabaseName,
      participant: participantDatabaseName,
    },
  });
  const scopeResults = {};
  for (const scope of scopes) {
    const response = await elRawSearch(context, SYSTEM_USER, `User footprint (${scope.id})`, buildUserFootprintSearch(scope));
    scopeResults[scope.id] = parseUserFootprintSearch(scope, response);
  }

  const report = {
    version: 2,
    userId,
    generatedAt: new Date().toISOString(),
    schemaDiscovery: {
      rootUserIdAttributes: userIdAttributeNames,
      limitation: 'Root schema attributes are completed by an explicit registry for nested, serialized, physical, and dedicated-index references.',
    },
    scopes: scopeResults,
    total: summarizeUserFootprint(scopeResults),
    coverage: USER_FOOTPRINT_COVERAGE,
  };

  console.log('\n=== User footprint report v2 (read-only PoC) ===');
  console.log(`User id: ${userId}\n`);
  console.log('-- Unique persistent Elasticsearch documents by scope --');
  Object.entries(report.scopes).forEach(([scopeId, scope]) => {
    console.log(`  ${scopeId.padEnd(12)} ${scope.uniqueDocuments}`);
  });
  console.log(`  ${'TOTAL'.padEnd(12)} ${report.total.uniquePersistentDocuments}`);
  console.log(`  ${'EXACT'.padEnd(12)} ${report.total.exactUniquePersistentDocuments}`);
  console.log(`  ${'CANDIDATE'.padEnd(12)} ${report.total.candidateUniquePersistentDocuments}`);
  console.log('\n-- Unique documents by proposed disposition --');
  Object.entries(report.total.dispositions).forEach(([disposition, count]) => {
    console.log(`  ${disposition.padEnd(12)} ${count}`);
  });
  console.log(`\nUnsupported storage categories: ${report.coverage.unsupported.map(({ storage }) => storage).join(', ')}`);
  console.log(`\nReport written to ${REPORT_FILE}`);

  fs.writeFileSync(REPORT_FILE, JSON.stringify(report, null, 2));
  logApp.info(`[POC] User footprint report written to ${REPORT_FILE}`, { report });
};

run()
  .then(() => process.exit(0))
  .catch((error) => {
    logApp.error('[POC] User footprint script failed', { error });
    process.exit(1);
  });
