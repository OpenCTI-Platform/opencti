import { executionContext, SYSTEM_USER } from '../utils/access';
import { elCount, elRawUpdateByQuery } from '../database/engine';
import {
  READ_ENTITIES_INDICES, READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
} from '../database/utils';
import { DatabaseError } from '../config/errors';
import { elList } from '../database/middleware-loader';
import { ENTITY_TYPE_THREAT_ACTOR } from '../schema/general';
import { logApp } from '../config/conf';

const message = '[MIGRATION] Threat-actors to group and individual (inferred)';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  // Iterator over all threat actors
  const threatCount = await elCount(context, SYSTEM_USER, READ_ENTITIES_INDICES, { types: [ENTITY_TYPE_THREAT_ACTOR] });
  logApp.info(`${message} > Migrating threat actors 0/${threatCount}`);
  let processNumber = 0;
  const callback = async (threatActors) => {
    processNumber += threatActors.length;
    for (let index = 0; index < threatActors.length; index += 1) {
      const threatActor = threatActors[index];
      const toType = threatActor.entity_type;
      // update the relations
      const updateRelationsQuery = {
        script: {
          params: { toType, toId: threatActor.internal_id },
          source: 'for(def connection : ctx._source.connections) {'
              + ' if (connection.internal_id == params.toId && !connection.types.contains(params.toType)) { connection.types.add(params.toType); }'
              + ' if (connection.internal_id == params.toId && connection.role.endsWith("_from")) { ctx._source.fromType = params.toType; }'
              + ' if (connection.internal_id == params.toId && connection.role.endsWith("_to")) { ctx._source.toType = params.toType; }'
              + '}'
        },
        query: {
          nested: {
            path: 'connections',
            query: {
              bool: {
                should: [
                  { term: { 'connections.internal_id.keyword': { value: threatActor.internal_id } } },
                  { term: { 'connections.internal_id.keyword': { value: threatActor.internal_id } } }
                ],
                minimum_should_match: 1
              }
            }
          }
        },
      };
      const relationsPromise = elRawUpdateByQuery({
        index: READ_INDEX_INFERRED_RELATIONSHIPS,
        refresh: true,
        wait_for_completion: true,
        body: updateRelationsQuery
      }).catch((err) => {
        throw DatabaseError('Error updating elastic', { error: err });
      });
      await Promise.all([relationsPromise]);
    }
    logApp.info(`${message} > Migrating threat actors ${processNumber}/${threatCount}`);
  };
  await elList(context, SYSTEM_USER, [READ_INDEX_STIX_DOMAIN_OBJECTS], { types: [ENTITY_TYPE_THREAT_ACTOR], callback });
  // Done with the migration
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
