import * as R from 'ramda';
import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../modules/securityCoverage/securityCoverage-types';
import { elBulk, elList } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { getSettings } from '../domain/settings';
import { storeLoadById } from '../database/middleware-loader';

const message = '[MIGRATION] Migrate coverage_information to org-scoped v2 format';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  // 1. Get the platform organization
  const settings = await getSettings(context);
  const platformOrgId = settings.platform_organization;
  let platformOrgName = 'Platform';
  if (platformOrgId) {
    const platformOrg = await storeLoadById(context, SYSTEM_USER, platformOrgId, 'Identity');
    if (platformOrg) {
      platformOrgName = platformOrg.name ?? 'Platform';
    }
  }
  logMigration.info(`${message} > Platform org: ${platformOrgId ?? 'none'} (${platformOrgName})`);
  // 2. Process all SecurityCoverage entities
  const bulkOperations = [];
  let processedCount = 0;
  let migratedCount = 0;
  const processCoverages = async (coverages) => {
    for (let i = 0; i < coverages.length; i += 1) {
      const coverage = coverages[i];
      processedCount += 1;
      const coverageInfo = coverage.coverage_information;
      // Skip if no coverage_information or already migrated (has organization_id)
      if (!coverageInfo || coverageInfo.length === 0) {
        continue;
      }
      // Check if already in v2 format (first entry has organization_id)
      if (coverageInfo[0].organization_id) {
        continue;
      }
      // Wrap flat results into org-scoped format
      const orgScopedInfo = [{
        organization_id: platformOrgId ?? 'unknown',
        organization_name: platformOrgName,
        last_result: coverage.coverage_last_result ?? null,
        auto_enrichment: !(coverage.auto_enrichment_disable ?? false),
        results: coverageInfo.map((entry) => ({
          coverage_name: entry.coverage_name,
          coverage_score: entry.coverage_score,
        })),
      }];
      bulkOperations.push(
        { update: { _index: coverage._index, _id: coverage._id, retry_on_conflict: 5 } },
        {
          script: {
            source: 'ctx._source.coverage_information = params.info; ctx._source.remove("rel_coverage-organization.internal_id");',
            lang: 'painless',
            params: { info: orgScopedInfo },
          },
        }
      );
      migratedCount += 1;
    }
    logMigration.info(`${message} > Processed ${processedCount} coverages, migrated ${migratedCount}`);
  };
  const opts = {
    types: [ENTITY_TYPE_SECURITY_COVERAGE],
    logForMigration: true,
    callback: processCoverages,
  };
  await elList(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, opts);
  // Apply bulk updates
  if (bulkOperations.length > 0) {
    const groupsOfOperations = R.splitEvery(1000, bulkOperations);
    for (let i = 0; i < groupsOfOperations.length; i += 1) {
      await elBulk({ refresh: true, timeout: '30m', body: groupsOfOperations[i] });
    }
    logMigration.info(`${message} > Updated ${migratedCount} coverages to v2 format`);
  }
  logMigration.info(`${message} > done. ${processedCount} processed, ${migratedCount} migrated.`);
  next();
};

export const down = async (next) => {
  next();
};
