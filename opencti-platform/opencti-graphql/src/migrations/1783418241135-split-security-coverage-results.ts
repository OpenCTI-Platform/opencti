import * as R from 'ramda';
import { logMigration } from '../config/conf';
import { BULK_TIMEOUT, elBulk, ES_MAX_CONCURRENCY, ES_RETRY_ON_CONFLICT, MAX_BULK_OPERATIONS } from '../database/engine';
import { createEntity } from '../database/middleware';
import { fullEntitiesList, fullRelationsList, internalFindByIds } from '../database/middleware-loader';
import { Promise } from 'bluebird';
import { ENTITY_TYPE_SECURITY_COVERAGE, type BasicStoreEntitySecurityCoverage } from '../modules/securityCoverage/securityCoverage-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT, INPUT_RESULT_OF } from '../modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { RELATION_HAS_COVERED } from '../schema/stixCoreRelationship';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { pushAll } from '../utils/arrayUtil';
import type { BasicStoreObject, BasicStoreRelation } from '../types/store';
import { ABSTRACT_BASIC_OBJECT, ABSTRACT_STIX_OBJECT, ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

const message = '[MIGRATION] Separate results data of Security Coverage into dedicated objects';

// To match what we have in Elastic at the time the migration is ran.
interface OldSecurityCoverage extends BasicStoreEntitySecurityCoverage {
  external_uri?: string;
  coverage_last_result?: string;
  coverage_valid_from?: string;
  coverage_valid_to?: string;
  coverage_information: {
    coverage_name: string;
    coverage_score: number;
  }[];
}

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  const context = executionContext('migration');
  logMigration.info(`${message} > started`);

  // Step 1 -> Retrieve all SecurityCoverages & has-covered relationships
  // TODO : add a callback system to avoid getting too many SC
  const allSecurityCoverages = await fullEntitiesList<OldSecurityCoverage>(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_SECURITY_COVERAGE],
  );
  logMigration.info(`${message} > ${allSecurityCoverages.length} SecurityCoverages found`);

  if (allSecurityCoverages.length > 0) {
    const allHasCoveredRelationships = await fullRelationsList<BasicStoreRelation>(
      context,
      SYSTEM_USER,
      [RELATION_HAS_COVERED],
    );
    logMigration.info(`${message} > ${allHasCoveredRelationships.length} Has-Covered relationships found`);

    const hasCoveredRelationshipsByFromId = new Map<string, BasicStoreRelation[]>();
    for (const relation of allHasCoveredRelationships) {
      const existing = hasCoveredRelationshipsByFromId.get(relation.fromId) ?? [];
      existing.push(relation);
      hasCoveredRelationshipsByFromId.set(relation.fromId, existing);
    }

    const allCoveredEntityIds = [...new Set(allHasCoveredRelationships.map((relationship) => relationship.toId))];
    const allCoveredEntitiesResult = await internalFindByIds<BasicStoreObject>(
      context,
      SYSTEM_USER,
      allCoveredEntityIds,
      { baseData: true },
    );

    const allCoveredEntities: BasicStoreObject[] = Array.isArray(allCoveredEntitiesResult)
      ? allCoveredEntitiesResult
      : [];

    const coveredEntitiesIndexById = new Map<string, string>(
      allCoveredEntities.map((entity) => [entity.internal_id, entity._index]),
    );

    // Starting the bulk operations
    const bulkOperations: any[] = [];

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
      // Or an external_uri is set because we can have a result instantiate by OpenAEV but without data yet,
      // Or if there is has-covered relationship
      const securityCoverageHasCoveredRelationships = hasCoveredRelationshipsByFromId.get(sc.internal_id) || [];
      if (external_uri || (coverage_information ?? []).length > 0 || securityCoverageHasCoveredRelationships.length > 0) {
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

        // First operation : update has-covered relationships
        securityCoverageHasCoveredRelationships.forEach((relation) => {
          const query = [
            { update: { _index: relation._index, _id: relation.internal_id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
            { script: {
              params: {
                old_id: sc.internal_id,
                new_id: result.internal_id,
                new_name: result.name,
                new_types: [
                  ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
                  ABSTRACT_BASIC_OBJECT,
                  ABSTRACT_STIX_OBJECT,
                  ABSTRACT_STIX_CORE_OBJECT,
                  ABSTRACT_STIX_DOMAIN_OBJECT,
                ],
              },
              source: "def connection = ctx._source.connections.find(conn -> conn.role == 'has-covered_from');"
                + 'if (connection != null) {'
                + 'connection.internal_id = params.new_id;'
                + 'connection.name = params.new_name;'
                + 'connection.types = params.new_types;'
                + '}',
            },
            },
          ];
          pushAll(bulkOperations, query);
        });

        // Second operation : add list of has-covered entities to SCR
        const coveredEntitiesIds = [...new Set(securityCoverageHasCoveredRelationships.map((relation) => relation.toId))];
        const updateSCRQuery = [
          { update: { _index: result._index, _id: result.internal_id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
          { script: { params: { covered_entities_ids: coveredEntitiesIds }, source: 'ctx._source["rel_has-covered.internal_id"] = params.covered_entities_ids;' } },
        ];
        pushAll(bulkOperations, updateSCRQuery);

        // Third operation : In covered entities : each SC is replaced with corresponding SCR
        const coveredEntitiesIdsAndIndexes = coveredEntitiesIds.map((id) => ({
          internalId: id,
          index: coveredEntitiesIndexById.get(id),
        }));
        coveredEntitiesIdsAndIndexes.forEach((coveredEntity) => {
          if (!coveredEntity.index) return;
          const query = [
            { update: { _index: coveredEntity.index, _id: coveredEntity.internalId, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
            { script: {
              params: {
                old_id: sc.internal_id,
                new_id: result.internal_id,
              },
              source: `if (ctx._source.containsKey('rel_has-covered.internal_id')) {
                def coveredIds = ctx._source['rel_has-covered.internal_id'];
                for (int i = 0; i < coveredIds.length; i++) {
                  if (coveredIds[i] == params.old_id) { coveredIds[i] = params.new_id; }
                }
              }
            `,
            } },
          ];
          pushAll(bulkOperations, query);
        });

        // Forth operation : In SC : remove old SC attributes
        const removeSCAttributesQuery = [
          { update: { _index: sc._index, _id: sc.internal_id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
          { script: {
            source: "ctx._source.remove('coverage_information');"
              + "ctx._source.remove('coverage_last_result');"
              + "ctx._source.remove('coverage_valid_from');"
              + "ctx._source.remove('coverage_valid_to');"
              + "ctx._source.remove('external_uri');"
              + "ctx._source.remove('rel_has-covered.internal_id');",
          },
          },
        ];
        pushAll(bulkOperations, removeSCAttributesQuery);

        logMigration.info(`${message} > SCR ${result?.standard_id} created for SC ${sc.standard_id}`);
      }
    }

    // Step 3 -> Apply operations.
    const groupsOfOperations = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperations);
    let currentProcessing = 0;
    const concurrentUpdate = async (bulk: any[][]) => {
      await elBulk(context, { refresh: true, timeout: BULK_TIMEOUT, body: bulk });
      currentProcessing += bulk.length;
      logMigration.info(`${message} bulk operations on SC / SCR / Entities  ${currentProcessing} / ${bulkOperations.length}`);
    };
    await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  } else {
    logMigration.info(`${message} > No SecurityCoverage found, skipping migration`);
  }

  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
