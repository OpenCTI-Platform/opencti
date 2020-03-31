import { Promise } from 'bluebird';
import { last, map, pathOr, head, includes } from 'ramda';
import { stixObservablesNumber, findAll } from '../domain/stixObservable';
import {
  markingDefinitions,
  createdByRef,
  reports,
  stixEntityAddRelation,
  stixEntityDeleteRelation,
} from '../domain/stixEntity';
import { findAll as findAllStixRelations, addStixRelation, stixRelationDelete } from '../domain/stixRelation';
import { executeWrite, loadByGraknId, updateAttribute } from '../database/grakn';
import { logger } from '../config/conf';
import { addIndicator, findAll as findAllIndicators } from '../domain/indicator';
import { objectRefs, observableRefs } from '../domain/report';
import { createStixPattern } from '../python/pythonBridge';

export const up = async (next) => {
  logger.info(`[MIGRATION] split_observables_indicators > Starting the migration of all observables...`);
  const nbOfObservables = stixObservablesNumber();
  const count = await nbOfObservables.total;
  if (count === 0) {
    next();
    return;
  }
  logger.info(`[MIGRATION] split_observables_indicators > Migrating ${count} Stix-Observable in batchs of 200`);
  let hasMore = true;
  let currentCursor = null;
  while (hasMore) {
    logger.info(
      `[MIGRATION] split_observables_indicators > Migrating ${count} Stix-Observable batch at cursor ${currentCursor}`
    );
    const stixObservables = await findAll({
      first: 200,
      after: currentCursor,
      orderAsc: true,
      orderBy: 'observable_value',
    });
    await Promise.all(
      stixObservables.edges.map(async (stixObservableEdge) => {
        const stixObservable = stixObservableEdge.node;
        const stixObservableMarkingDefinitions = await markingDefinitions(stixObservable.id);
        const markingDefinitionsIds = map((n) => n.node.id, stixObservableMarkingDefinitions.edges);
        const stixObservableCreatedByRef = await createdByRef(stixObservable.id);
        const createdByRefId = pathOr(null, ['node', 'id'], stixObservableCreatedByRef);
        const stixObservableReports = await reports(stixObservable.id);
        const stixRelations = await findAllStixRelations({
          first: 200,
          relationType: 'indicates',
          fromId: stixObservable.id,
        });
        // Update the stix_id_key
        if (stixObservable.stix_id_key.includes('indicator')) {
          await executeWrite((wTx) => {
            return updateAttribute(
              stixObservable.id,
              'Stix-Observable',
              {
                key: 'stix_id_key',
                value: [stixObservable.stix_id_key.replace('indicator', 'observable')],
              },
              wTx
            );
          });
        }
        // Create the corresponding indicator
        const pattern = await createStixPattern(stixObservable.entity_type, stixObservable.observable_value);
        if (pattern) {
          try {
            const indicatorToCreate = {
              name: stixObservable.observable_value,
              description: stixObservable.description
                ? stixObservable.description
                : `Simple indicator of observable {${stixObservable.observable_value}}`,
              main_observable_type: stixObservable.entity_type,
              indicator_pattern: pattern,
              pattern_type: 'stix',
              valid_from: stixObservable.created_at,
              created: stixObservable.created_at,
              modified: stixObservable.updated_at,
              observableRefs: [stixObservable.id],
              markingDefinitions: markingDefinitionsIds,
              createdByRef: createdByRefId,
            };
            let indicator = await findAllIndicators({ filters: [{ key: 'indicator_pattern', values: [pattern] }] });
            if (indicator.edges.length > 0) {
              indicator = head(indicator.edges).node;
            } else {
              indicator = await addIndicator(null, indicatorToCreate, false);
            }
            if (indicator === null) {
              return Promise.resolve(true);
            }
            // Add indicator to reports
            for (let index = 0; index < stixObservableReports.edges.length; index += 1) {
              const stixObservableReportEdge = stixObservableReports.edges[index];
              const stixObservableReportObjectRefs = await objectRefs(stixObservableReportEdge.node.id, {});
              const stixObservableReportObjectRefsIds = map((n) => n.node.id, stixObservableReportObjectRefs.edges);
              const stixObservableReportObservableRefs = await observableRefs(stixObservableReportEdge.node.id, {});
              const stixObservableReportObservableRefsIds = map(
                (n) => n.node.id,
                stixObservableReportObservableRefs.edges
              );
              // Add indicator to report
              if (!includes(indicator.id, stixObservableReportObjectRefsIds)) {
                await stixEntityAddRelation(null, stixObservableReportEdge.node.id, {
                  fromRole: 'knowledge_aggregation',
                  toId: indicator.id,
                  toRole: 'so',
                  through: 'object_refs',
                });
              }
              // Add observable to report
              if (!includes(stixObservable.id, stixObservableReportObservableRefsIds)) {
                await stixEntityAddRelation(null, stixObservableReportEdge.node.id, {
                  fromRole: 'observables_aggregation',
                  toId: stixObservable.id,
                  toRole: 'soo',
                  through: 'observable_refs',
                });
              }
              // Delete observable from report
              await stixEntityDeleteRelation(
                null,
                stixObservableReportEdge.node.id,
                stixObservableReportEdge.relation.id
              );
            }
            // Create relation indicates
            for (let index = 0; index < stixRelations.edges.length; index += 1) {
              const stixrelationEdge = stixRelations.edges[index];
              const stixRelation = stixrelationEdge.node;
              const to = await loadByGraknId(stixRelation.toId);
              const stixRelationReports = await reports(stixRelation.id);
              const createdStixRelation = await addStixRelation(null, {
                relationship_type: to.entity_type === 'incident' ? 'related-to' : 'indicates',
                fromId: to.entity_type === 'incident' ? stixObservable.id : indicator.id,
                fromRole: to.entity_type === 'incident' ? 'relate_from' : 'indicator',
                toId: to.id,
                toRole: to.entity_type === 'incident' ? 'relate_to' : 'characterize',
                name: stixRelation.name,
                description: stixRelation.description,
                role_played: stixRelation.role_played,
                weight: stixRelation.weight,
                first_seen: new Date(stixRelation.first_seen),
                last_seen: new Date(stixRelation.last_seen),
                created: new Date(stixRelation.created),
                modified: new Date(stixRelation.modified),
              });
              // Add the relation to reports
              for (let index2 = 0; index2 < stixRelationReports.edges.length; index2 += 1) {
                const stixRelationReportEdge = stixRelationReports.edges[index2];
                await stixEntityAddRelation(null, stixRelationReportEdge.node.id, {
                  fromRole: 'knowledge_aggregation',
                  toId: createdStixRelation.id,
                  toRole: 'so',
                  through: 'object_refs',
                });
              }
              // Delete the relation after creation
              await stixRelationDelete(stixRelation.id);
            }
          } catch (err) {
            logger.info(`[MIGRATION] split_observables_indicators > Error ${err}`);
          }
        }
        return Promise.resolve(true);
      })
    );
    if (last(stixObservables.edges)) {
      currentCursor = last(stixObservables.edges).cursor;
      hasMore = stixObservables.pageInfo.hasNextPage;
    } else {
      hasMore = false;
    }
  }
  logger.info(`[MIGRATION] split_observables_indicators > Migration complete`);
  next();
};

export const down = async (next) => {
  next();
};
