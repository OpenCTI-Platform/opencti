import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { createEntity } from '../database/middleware';
import { fullEntitiesList } from '../database/middleware-loader';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_SECURITY_COVERAGE, type BasicStoreEntitySecurityCoverage } from '../modules/securityCoverage/securityCoverage-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT, INPUT_RESULT_OF } from '../modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Separate results data of Security Coverage into dedicated objects';

// To match what we have in Elastic at the time the migration is ran.
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
  // TODO : add a callback system to avoid getting too many SC
  const allSecurityCoverages = await fullEntitiesList<OldSecurityCoverage>(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_SECURITY_COVERAGE],
  );
  logMigration.info(`${message} > ${allSecurityCoverages.length} SecurityCoverages found`);

  // TODO : get all has-covered relationships

  // Step 2 -> Create a SecurityCoverageResult for each SecurityCoverage containing results data.
  for (const sc of allSecurityCoverages) {
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

    // Want to create a result if there is results data,
    // Or an external_uri is set because we can have a result instantiate by OpenAEV but without data yet.
    // TODO : add condition if there is has-covered relationship => create a SCR
    if (external_uri || (coverage_information ?? []).length > 0) {
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
      const result = await createEntity(
        context,
        SYSTEM_USER,
        securityCoverageResultInput,
        ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
      );

      // TODO : a bulk update + split in groups (see line 124 of clean-deprecated-rels)

      // Find the has-covered relationships with the SC id

      // 1rst op : relation => filter on  "role": "has-covered_from"
      // In relationship : replace "connections" :
      // "internal_id" : replace SC id with SCR id
      // "name" : replace SC name with SCR name
      // "types" : replace "Security-Coverage" with "Security-Coverage-Result" ENTITY_TYPE_SECURITY_COVERAGE_RESULT

      // 2nd op : In SCR : "rel_has-covered.internal_id" : list of has-covered entities TO BE ADDED (to)
      // get SCR id
      // add list of has-covered entities to "rel_has-covered.internal_id"

      // 3rd op : In entity : "rel_has-covered.internal_id" : list of SC to be replaced with corresponding SCR

      // 4rth op : In SC : remove attributes
      // "rel_has-covered.internal_id" : list of has-covered entities TO BE REMOVED (to)
      // + all other attributes :
      // 'coverage_information'
      // 'coverage_last_result'
      // 'coverage_valid_from'
      // 'coverage_valid_to'
      // 'external_uri'

      logMigration.info(`${message} > SCR ${result?.standard_id} created for SC ${sc.standard_id}`);
    }
  }

  // Step 3 -> Remove old attributes.
  // TODO : create a bulk update to call query only once (see clean-deprecated-rels)
  await elUpdateByQueryForMigration(
    `${message} > Clean old attributes`,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    {
      script: {
        source: "ctx._source.remove('coverage_information');"
          + "ctx._source.remove('coverage_last_result');"
          + "ctx._source.remove('coverage_valid_from');"
          + "ctx._source.remove('coverage_valid_to');"
          + "ctx._source.remove('external_uri');",
      },
      query: {
        term: {
          'entity_type.keyword': {
            value: ENTITY_TYPE_SECURITY_COVERAGE,
          },
        },
      },
    },
  );

  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
