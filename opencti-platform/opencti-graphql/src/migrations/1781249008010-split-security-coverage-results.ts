import { logMigration } from '../config/conf';
import { fullEntitiesList } from '../database/middleware-loader';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../modules/securityCoverage/securityCoverage-types';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Separate results data of Security Coverage into dedicated objects';

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  const context = executionContext('migration');
  logMigration.info(`${message} > started`);

  // Step 1 -> Retrieve SecurityCoverages containing results data
  // TODO probably need improvements, ask Souad
  const allSecurityCoverages = await fullEntitiesList(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_SECURITY_COVERAGE],
    {
      indices: [READ_INDEX_STIX_DOMAIN_OBJECTS],
      filters: {
        filterGroups: [],
        mode: FilterMode.And,
        filters: [{ key: ['external_uri'], operator: FilterOperator.NotNil, values: [] }],
      },
    },
  );
  logMigration.info(`${message} > ${allSecurityCoverages.length} SecurityCoverages found`);

  // Step 2 -> Create a SecurityCoverageResult for each SecurityCoverage found
  // + Step 3 -> Remove attributes in SecurityCoverage objects
  for (const sc of allSecurityCoverages) {
    // TODO create SCR
    logMigration.info(`${message} > SecurityCoverageResult created for ${sc.standard_id}`);
    // TODO remove attributes
    logMigration.info(`${message} > SecurityCoverage ${sc.standard_id} cleaned`);
  }

  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
