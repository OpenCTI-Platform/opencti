import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { createEntity } from '../database/middleware';
import { fullEntitiesList } from '../database/middleware-loader';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_SECURITY_COVERAGE, type BasicStoreEntitySecurityCoverage } from '../modules/securityCoverage/securityCoverage-types';
import {
  ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  INPUT_RESULT_OF,
  type BasicStoreEntitySecurityCoverageResult,
} from '../modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Separate results data of Security Coverage into dedicated objects';

interface OldSecurityCoverage extends BasicStoreEntitySecurityCoverage {
  external_uri?: string;
  coverage_last_result?: string;
  coverage_valid_from?: string;
  coverage_valid_to?: string;
  coverage_information?: {
    coverage_name: string;
    coverage_score: number;
  }[];
}

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  const context = executionContext('migration');
  logMigration.info(`${message} > started`);

  // Step 1 -> Retrieve all SecurityCoverages
  const allSecurityCoverages = await fullEntitiesList<OldSecurityCoverage>(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_SECURITY_COVERAGE],
  );
  logMigration.info(`${message} > ${allSecurityCoverages.length} SecurityCoverages found`);

  // Step 2 -> Create a SecurityCoverageResult for each SecurityCoverage with data
  for (const sc of allSecurityCoverages) {
    let result: BasicStoreEntitySecurityCoverageResult | undefined = undefined;
    let source = "ctx._source.remove('coverage_information');"
      + "ctx._source.remove('coverage_last_result');"
      + "ctx._source.remove('coverage_valid_from');"
      + "ctx._source.remove('coverage_valid_to');"
      + "ctx._source.remove('external_uri');";

    const {
      coverage_information,
      coverage_last_result,
      coverage_valid_from,
      coverage_valid_to,
      external_uri,
      confidence,
      created,
      modified,
      x_opencti_modified_at,
      ...otherAttributes
    } = sc;

    const shouldCreateResult = external_uri || (coverage_information ?? []).length > 0;
    if (shouldCreateResult) {
      const securityCoverageResultInput = {
        name: `Result of ${sc.name}`,
        [INPUT_RESULT_OF]: sc.id,
        coverage_information,
        coverage_last_result,
        coverage_valid_from,
        coverage_valid_to,
        external_uri,
        confidence,
        created,
        modified,
        x_opencti_modified_at,
        createdBy: otherAttributes['created-by'],
        objectLabel: otherAttributes['object-label'],
        objectMarking: otherAttributes['object-marking'],
      };
      result = await createEntity(
        context,
        SYSTEM_USER,
        securityCoverageResultInput,
        ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
      );
      source += 'ctx._source.rel_result-of.internal_id = [params.security_coverage_result_id];';
      logMigration.info(`${message} > SCR ${result?.standard_id} created for ${sc.standard_id}`);
    }

    await elUpdateByQueryForMigration(
      `${message} > SecurityCoverage ${sc.internal_id}: add result id + clean old attributes`,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      {
        script: {
          params: result ? { security_coverage_result_id: result.internal_id } : {},
          source,
        },
        query: {
          ids: {
            values: [sc.internal_id],
          },
        },
      },
    );
  }

  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
