import { Promise } from 'bluebird';
import { last, groupBy, dropLast, map } from 'ramda';
import { findAll as findAllReports } from '../domain/report';
import { findAll as findallStixDomainEntities } from '../domain/stixDomainEntity';
import { deleteRelationById, findWithConnectedRelations, listRelations } from '../database/grakn';
import { logger } from '../config/conf';

const purgeDuplicates = async (query, relation = false, reportId = null) => {
  try {
    let relations = null;
    if (relation) {
      const pointingFilter = { relation: 'object_refs', fromRole: 'so', toRole: 'knowledge_aggregation', id: reportId };
      relations = await listRelations('stix_relation', pointingFilter, { withCache: false, first: 500000 });
      relations = relations.edges;
    } else {
      relations = await findWithConnectedRelations(query, 'to', 'rel');
    }
    const groupedRelations = groupBy(n => n.node.internal_id_key, relations);
    for (const groupedRelationKey in groupedRelations) {
      const groupedRelation = groupedRelations[groupedRelationKey];
      if (groupedRelation.length > 1) {
        const relationsToDelete = map(n => n.relation.internal_id_key, dropLast(1, groupedRelation));
        for (const relationToDelete of relationsToDelete) {
          await deleteRelationById(relationToDelete);
        }
      }
    }
  } catch (err) {
    logger.info(`[MIGRATION] clean_duplicate_embedded_relations > Error ${err}`);
  }
};

export const up = async next => {

  next();
};

export const down = async next => {
  next();
};
