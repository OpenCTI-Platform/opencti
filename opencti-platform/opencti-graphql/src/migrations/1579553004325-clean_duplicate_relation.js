import { Promise } from 'bluebird';
import { last, groupBy, dropLast, map } from 'ramda';
import { findAll as findAllReports } from '../domain/report';
import { findAll as findallStixDomainEntities } from '../domain/stixDomainEntity';
import { deleteRelationById, findWithConnectedRelations, listRelations } from '../database/grakn';
import { logger } from '../config/conf';

const purgeDuplicates = async (query, relation = false, reportId = null) => {
  try {
    let relations;
    if (relation) {
      const relationFilter = { relation: 'object_refs', fromRole: 'so', toRole: 'knowledge_aggregation', id: reportId };
      relations = await listRelations('stix_relation', { noCache: true, first: 500000, relationFilter });
      relations = relations.edges;
    } else {
      relations = await findWithConnectedRelations(query, 'to', { extraRelKey: 'rel' });
    }
    const groupedRelations = groupBy((n) => n.node.internal_id_key, relations);
    // eslint-disable-next-line no-restricted-syntax,guard-for-in
    for (const groupedRelationKey in groupedRelations) {
      // noinspection JSUnfilteredForInLoop
      const groupedRelation = groupedRelations[groupedRelationKey];
      if (groupedRelation.length > 1) {
        const relationsToDelete = map((n) => n.relation.internal_id_key, dropLast(1, groupedRelation));
        // eslint-disable-next-line no-restricted-syntax
        for (const relationToDelete of relationsToDelete) {
          await deleteRelationById(null, relationToDelete, 'relation');
        }
      }
    }
  } catch (err) {
    logger.info(`[MIGRATION] clean_duplicate_embedded_relations`, { error: err });
  }
};

export const up = async (next) => {
  logger.info(`[MIGRATION] clean_duplicate_embedded_relations > Starting cleaning...`);
  logger.info(`[MIGRATION] clean_duplicate_embedded_relations > Cleaning reports in batchs of 100`);
  let hasMore = true;
  let currentCursor = null;
  while (hasMore) {
    logger.info(`[MIGRATION] clean_duplicate_embedded_relations > Cleaning reports at cursor ${currentCursor}`);
    const reports = await findAllReports({
      first: 100,
      after: currentCursor,
      orderAsc: true,
      orderBy: 'name',
    });
    await Promise.all(
      reports.edges.map((reportEdge) => {
        const report = reportEdge.node;
        return purgeDuplicates(
          `match $from isa Report, has internal_id_key "${report.id}"; $rel(observables_aggregation:$from, soo:$to) isa observable_refs; $to isa Stix-Observable; get;`
        );
      })
    );
    await Promise.all(
      reports.edges.map((reportEdge) => {
        const report = reportEdge.node;
        return purgeDuplicates(
          `match $from isa Report, has internal_id_key "${report.id}"; $rel(knowledge_aggregation:$from, so:$to) isa object_refs; $to isa Stix-Domain-Entity; get;`
        );
      })
    );
    await Promise.all(
      reports.edges.map((reportEdge) => {
        const report = reportEdge.node;
        return purgeDuplicates(null, true, report.id);
      })
    );
    if (last(reports.edges)) {
      currentCursor = last(reports.edges).cursor;
      hasMore = reports.pageInfo.hasNextPage;
    } else {
      hasMore = false;
    }
  }

  hasMore = true;
  logger.info(`[MIGRATION] clean_duplicate_embedded_relations > Cleaning stix domain entities in batchs of 100`);
  while (hasMore) {
    logger.info(
      `[MIGRATION] clean_duplicate_embedded_relations > Cleaning stix domain entities at cursor ${currentCursor}`
    );
    const stixDomainEntities = await findallStixDomainEntities({
      first: 100,
      after: currentCursor,
      orderAsc: true,
      orderBy: 'name',
    });
    await Promise.all(
      stixDomainEntities.edges.map((stixDomainEntityEdge) => {
        const stixDomainEntity = stixDomainEntityEdge.node;
        return purgeDuplicates(
          `match $from isa Stix-Domain-Entity, has internal_id_key "${stixDomainEntity.id}"; $rel(so:$from, external_reference:$to) isa external_references; $to isa External-Reference; get;`
        );
      })
    );
    await Promise.all(
      stixDomainEntities.edges.map((stixDomainEntityEdge) => {
        const stixDomainEntity = stixDomainEntityEdge.node;
        return purgeDuplicates(
          `match $from isa Stix-Domain-Entity, has internal_id_key "${stixDomainEntity.id}"; $rel(so:$from, marking:$to) isa object_marking_refs; $to isa Marking-Definition; get;`
        );
      })
    );
    await Promise.all(
      stixDomainEntities.edges.map((stixDomainEntityEdge) => {
        const stixDomainEntity = stixDomainEntityEdge.node;
        return purgeDuplicates(
          `match $from isa Stix-Domain-Entity, has internal_id_key "${stixDomainEntity.id}"; $rel(so:$from, creator:$to) isa created_by_ref; $to isa Identity; get;`
        );
      })
    );
    if (last(stixDomainEntities.edges)) {
      currentCursor = last(stixDomainEntities.edges).cursor;
      hasMore = stixDomainEntities.pageInfo.hasNextPage;
    } else {
      hasMore = false;
    }
  }
  logger.info(`[MIGRATION] clean_duplicate_embedded_relations > Migration complete`);
  next();
};

export const down = async (next) => {
  next();
};
