// PoC (merge-users #1): read-only footprint scan for a given user internal_id.
// For a given --userId, counts how many Elastic documents reference that user, broken
// down by field, so that a future "merge users" implementation (either approach) can be
// sized before doing anything. STRICTLY READ ONLY: only elCount/elRawSearch are used,
// no elUpdate*/delete call is ever made.
//
// Usage:
//   yarn build:dev
//   yarn poc:user-footprint --userId=<internal_id>
import '../src/modules/index';
import fs from 'node:fs';
import { executionContext, SYSTEM_USER } from '../src/utils/access';
import { logApp } from '../src/config/conf';
import { elCount, searchEngineInit } from '../src/database/engine';
import { READ_DATA_INDICES, READ_RELATIONSHIPS_INDICES } from '../src/database/utils';
import { schemaAttributesDefinition } from '../src/schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../src/schema/schema-relationsRef';
import { ENTITY_TYPE_USER } from '../src/schema/internalObject';
import { INPUT_ASSIGNEE, INPUT_PARTICIPANT } from '../src/schema/general';
import { RELATION_MEMBER_OF, RELATION_PARTICIPATE_TO, RELATION_HAS_ROLE, RELATION_HAS_CAPABILITY } from '../src/schema/internalRelationship';

const REPORT_FILE = './poc-user-footprint-report.json';

const userIdArg = process.argv.find((arg) => arg.startsWith('--userId='));
const userId = userIdArg?.split('=')[1] || null;

if (!userId) {
  logApp.error('[POC] Missing required --userId=<internal_id> argument');
  process.exit(1);
}

// Build a simple "field = userId" equality filter, reused by all the term-based counts.
const buildEqFilter = (key) => ({
  mode: 'and',
  filters: [{ key: [key], values: [userId], operator: 'eq' }],
  filterGroups: [],
});

// Count documents in READ_DATA_INDICES having <field> = userId.
// noFiltersChecking bypasses the "isFilterable" schema check: some User-referencing
// attributes (e.g. i_attributes.user_id) are not flagged filterable but are still
// perfectly queryable as plain ES term filters.
const countByField = async (context, field) => elCount(context, SYSTEM_USER, READ_DATA_INDICES, {
  filters: buildEqFilter(field),
  noFiltersChecking: true,
});

// Count relationship documents (rights: member-of, has-role, has-capability, participate-to)
// where the user is on the "fromId" or "toId" side of the graph edge.
const countRelationshipSide = async (context, relationshipType, side) => elCount(context, SYSTEM_USER, READ_RELATIONSHIPS_INDICES, {
  types: [relationshipType],
  filters: buildEqFilter(side),
  noFiltersChecking: true,
});

// Upper-bound heuristic: full-text search for the userId string across all data indices.
// This will also match legitimate references embedded in JSON fields (saved filters,
// stream/trigger/feed filter definitions, etc.) that are not modeled as "id" attributes,
// but it can also produce false positives (e.g. partial/incidental matches), hence "upper bound".
const countFullTextHeuristic = async (context) => elCount(context, SYSTEM_USER, READ_DATA_INDICES, {
  search: `"${userId}"`,
  noFiltersChecking: true,
});

const run = async () => {
  // Minimal dependency check needed for the lightweight bootstrap: connects/selects the
  // search engine client (read-only, no index/mapping creation happens here).
  await searchEngineInit();
  const context = executionContext('poc-user-footprint');
  const report = {
    userId,
    generatedAt: new Date().toISOString(),
    fields: {},
    relationships: {},
    heuristics: {},
  };

  // 1. Schema-driven discovery: every "id" attribute whose entityTypes includes User.
  // Nothing here is hardcoded, it is entirely derived from schemaAttributesDefinition.
  const userIdAttributeNames = [...new Set(
    schemaAttributesDefinition.getIdAttributes()
      .filter((attr) => (attr.entityTypes ?? []).includes(ENTITY_TYPE_USER))
      .map((attr) => attr.name),
  )];
  logApp.info(`[POC] Discovered ${userIdAttributeNames.length} schema id-attribute(s) referencing User`, { attributes: userIdAttributeNames });

  for (const field of userIdAttributeNames) {
    const count = await countByField(context, field);
    report.fields[field] = { count, method: 'elCount term filter (schema-driven id attribute)' };
  }

  // 2. STIX ref relationships known to reference users but not exposed as simple id attributes.
  // Their real ES field name (databaseName, e.g. "object-assignee" -> rel_object-assignee.internal_id)
  // is looked up dynamically from the schema, not hardcoded.
  const refsToCheck = [INPUT_ASSIGNEE, INPUT_PARTICIPANT];
  for (const refName of refsToCheck) {
    const databaseName = schemaRelationsRefDefinition.getDatabaseName(refName);
    const count = await countByField(context, refName);
    report.fields[databaseName ?? refName] = { count, method: `elCount term filter (ref relation "${refName}", resolved databaseName=${databaseName ?? 'unknown'})` };
  }

  // 3. Graph relationships representing rights: counted separately since transferring
  // them blindly during a merge would be a rights escalation/loss, not a plain data rewrite.
  const rightsRelationshipTypes = [RELATION_MEMBER_OF, RELATION_PARTICIPATE_TO, RELATION_HAS_ROLE, RELATION_HAS_CAPABILITY];
  for (const relationshipType of rightsRelationshipTypes) {
    const asSource = await countRelationshipSide(context, relationshipType, 'fromId');
    const asTarget = await countRelationshipSide(context, relationshipType, 'toId');
    report.relationships[relationshipType] = {
      asSource,
      asTarget,
      method: 'elCount on READ_RELATIONSHIPS_INDICES (fromId/toId)',
    };
  }

  // 4. Full-text heuristic (upper bound, may include false positives).
  const fullTextCount = await countFullTextHeuristic(context);
  report.heuristics.fullTextSearch = {
    count: fullTextCount,
    method: 'elCount full-text search on the userId string (upper bound, may include false positives)',
  };

  // Totals
  const fieldsTotal = Object.values(report.fields).reduce((acc, v) => acc + v.count, 0);
  const relationshipsTotal = Object.values(report.relationships)
    .reduce((acc, v) => acc + v.asSource + v.asTarget, 0);
  report.total = { fieldsTotal, relationshipsTotal, fullTextHeuristic: fullTextCount };

  // Human-readable console report.
  console.log('\n=== User footprint report (read-only PoC) ===');
  console.log(`User id: ${userId}\n`);
  console.log('-- Fields (schema-driven id attributes + ref relations) --');
  Object.entries(report.fields).forEach(([field, { count }]) => console.log(`  ${field.padEnd(30)} ${count}`));
  console.log(`  ${'TOTAL'.padEnd(30)} ${fieldsTotal}`);
  console.log('\n-- Rights relationships (graph edges) --');
  Object.entries(report.relationships).forEach(([relationshipType, { asSource, asTarget }]) => {
    console.log(`  ${relationshipType.padEnd(30)} asSource=${asSource} asTarget=${asTarget}`);
  });
  console.log(`  ${'TOTAL'.padEnd(30)} ${relationshipsTotal}`);
  console.log('\n-- Full text heuristic (upper bound) --');
  console.log(`  ${'match on userId string'.padEnd(30)} ${fullTextCount}`);
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
