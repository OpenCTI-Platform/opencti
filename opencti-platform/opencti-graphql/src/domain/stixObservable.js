import { assoc, dissoc, map, pipe } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteEntityById,
  deleteRelationById,
  deleteRelationsByFromAndTo,
  escape,
  escapeString,
  executeWrite,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  loadRelationById,
  now,
  timeSeriesEntities,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import { elCount } from '../database/elasticSearch';
import { buildPagination, TYPE_STIX_OBSERVABLE } from '../database/utils';
import { createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { addIndicator } from './indicator';
import { askEnrich } from './enrichment';
import { ForbiddenAccess, FunctionalError } from '../config/errors';
import { createStixPattern } from '../python/pythonBridge';
import { OBSERVABLE_TYPES } from '../database/stix';
import { checkObservableSyntax } from '../utils/syntax';

export const findById = (stixObservableId) => {
  return loadEntityById(stixObservableId, 'Stix-Observable');
};
export const findAll = async (args) => {
  const noTypes = !args.types || args.types.length === 0;
  const entityTypes = noTypes ? ['Stix-Observable'] : args.types;
  const finalArgs = assoc('parentType', 'Stix-Observable', args);
  return listEntities(entityTypes, ['name', 'description', 'observable_value'], finalArgs);
};

// region by elastic
export const stixObservablesNumber = (args) => ({
  count: elCount('stix_observables', args),
  total: elCount('stix_observables', dissoc('endDate', args)),
});
// endregion

// region time series
export const reportsTimeSeries = (stixObservableId, args) => {
  const filters = [
    { isRelation: true, from: 'knowledge_aggregation', to: 'so', type: 'object_refs', value: stixObservableId },
  ];
  return timeSeriesEntities('Report', filters, args);
};
export const stixObservablesTimeSeries = (args) => {
  return timeSeriesEntities(args.type ? escape(args.type) : 'Stix-Observable', [], args);
};
// endregion

// region mutations
export const stixObservableAskEnrichment = async (id, connectorId) => {
  const connector = await loadEntityById(connectorId, 'Connector');
  const { job, work } = await createWork(connector, 'Stix-Observable', id);
  const message = {
    work_id: work.internal_id_key,
    job_id: job.internal_id_key,
    entity_id: id,
  };
  await pushToConnector(connector, message);
  return work;
};
export const indicators = (stixObservableId) => {
  return findWithConnectedRelations(
    `match $from isa Stix-Observable; $rel(soo:$from, observables_aggregation:$to) isa observable_refs;
    $to isa Indicator;
    $from has internal_id_key "${escapeString(stixObservableId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const addStixObservable = async (user, stixObservable) => {
  const innerType = stixObservable.type;
  if (!OBSERVABLE_TYPES.includes(innerType.toLowerCase())) {
    throw new Error(`[SCHEMA] Observable type ${innerType} is not supported.`);
  }
  const observableSyntaxResult = checkObservableSyntax(innerType.toLowerCase(), stixObservable.observable_value);
  if (observableSyntaxResult !== true) {
    throw new FunctionalError({
      data: {
        details: `[SCHEMA] Observable ${stixObservable.observable_value} of type ${innerType} is not correctly formatted (${observableSyntaxResult}).`,
      },
    });
  }
  const observableToCreate = pipe(dissoc('type'), dissoc('createIndicator'))(stixObservable);
  const created = await createEntity(user, observableToCreate, innerType, {
    modelType: TYPE_STIX_OBSERVABLE,
    stixIdType: 'observable',
  });
  await askEnrich(created.id, innerType);
  // create the linked indicator
  if (stixObservable.createIndicator) {
    try {
      const pattern = await createStixPattern(created.entity_type, created.observable_value);
      if (pattern) {
        const indicatorToCreate = pipe(
          dissoc('internal_id_key'),
          dissoc('stix_id_key'),
          dissoc('observable_value'),
          assoc('name', stixObservable.observable_value),
          assoc(
            'description',
            stixObservable.description
              ? stixObservable.description
              : `Simple indicator of observable {${stixObservable.observable_value}}`
          ),
          assoc('indicator_pattern', pattern),
          assoc('pattern_type', 'stix'),
          assoc('main_observable_type', innerType),
          assoc('valid_from', stixObservable.observable_date ? stixObservable.observable_date : now()),
          assoc('observableRefs', [created.id])
        )(observableToCreate);
        await addIndicator(user, indicatorToCreate, false);
      }
    } catch (err) {
      logger.info(`Cannot create indicator`, { error: err });
    }
  }
  return notify(BUS_TOPICS.StixObservable.ADDED_TOPIC, created, user);
};
export const stixObservableDelete = async (user, stixObservableId) => {
  return deleteEntityById(user, stixObservableId, 'Stix-Observable');
};
export const stixObservableAddRelation = (user, stixObservableId, input) => {
  if (!input.through) {
    throw new ForbiddenAccess();
  }
  const finalInput = assoc('fromType', 'Stix-Observable', input);
  return createRelation(user, stixObservableId, finalInput).then((relationData) => {
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixObservableAddRelations = async (user, stixObservableId, input) => {
  const finalInput = map(
    (n) => ({
      fromType: 'Stix-Observable',
      fromRole: input.fromRole,
      toId: n,
      toRole: input.toRole,
      through: input.through,
    }),
    input.toIds
  );
  await createRelations(user, stixObservableId, finalInput);
  return loadEntityById(stixObservableId, 'Stix-Observable').then((entity) =>
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, entity, user)
  );
};
export const stixObservableEditField = (user, stixObservableId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, stixObservableId, 'Stix-Observable', input, wTx);
  }).then(async () => {
    const stixObservable = await loadEntityById(stixObservableId, 'Stix-Observable');
    return notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user);
  });
};
export const stixObservableDeleteRelation = async (
  user,
  stixObservableId,
  relationId = null,
  toId = null,
  relationType = 'stix_relation_embedded'
) => {
  const stixObservable = await loadEntityById(stixObservableId, 'Stix-Observable');
  if (!stixObservable) {
    throw new Error('Cannot delete the relation, Stix-Observable cannot be found.');
  }
  if (relationId) {
    const data = await loadRelationById(relationId, 'relation');
    if (data.fromId !== stixObservable.grakn_id) {
      throw new ForbiddenAccess();
    }
    await deleteRelationById(user, relationId, 'relation');
  } else if (toId) {
    await deleteRelationsByFromAndTo(user, stixObservableId, toId, relationType, 'relation');
  } else {
    throw new Error('Cannot delete the relation, missing relationId or toId');
  }
  const data = await loadEntityById(stixObservableId, 'Stix-Observable');
  return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const stixObservableCleanContext = (user, stixObservableId) => {
  delEditContext(user, stixObservableId);
  return loadEntityById(stixObservableId, 'Stix-Observable').then((stixObservable) =>
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user)
  );
};
export const stixObservableEditContext = (user, stixObservableId, input) => {
  setEditContext(user, stixObservableId, input);
  return loadEntityById(stixObservableId, 'Stix-Observable').then((stixObservable) =>
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user)
  );
};
// endregion
