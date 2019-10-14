import {
  assoc,
  isNil,
  map,
  filter,
  propOr,
  dissoc,
  tail,
  join,
  head
} from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  escape,
  escapeString,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  updateAttribute,
  getById,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  takeWriteTx,
  timeSeries,
  getObject,
  prepareDate,
  load,
  getId,
  commitWriteTx
} from '../database/grakn';
import {
  deleteEntity,
  paginate as elPaginate,
  countEntities
} from '../database/elasticSearch';

import {
  BUS_TOPICS,
  RABBITMQ_EXPORT_ROUTING_KEY,
  RABBITMQ_EXCHANGE_NAME,
  logger
} from '../config/conf';
import {
  findAll as relationFindAll,
  search as relationSearch
} from './stixRelation';
import { send } from '../database/rabbitmq';

export const findAll = args => elPaginate('stix_domain_entities', args);

export const stixDomainEntitiesTimeSeries = args =>
  timeSeries(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'}`,
    args
  );

export const stixDomainEntitiesNumber = args => ({
  count: countEntities('stix_domain_entities', args),
  total: countEntities('stix_domain_entities', dissoc('endDate', args))
});

export const findById = stixDomainEntityId => getById(stixDomainEntityId);

export const findByStixId = args =>
  paginate(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'};
    $x has stix_id "${escapeString(args.stix_id)}"`,
    args,
    false
  );

export const findByName = args =>
  paginate(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'};
   $x has name $name;
   $x has alias $alias;
   { $name "${escapeString(args.name)}"; } or
   { $alias "${escapeString(args.name)}"; }`,
    args,
    false
  );

export const findByExternalReference = args =>
  paginate(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'};
     $rel(external_reference:$externalReference, so:$x) isa external_references;
     $externalReference has internal_id "${escapeString(
       args.externalReferenceId
     )}"`,
    args,
    false
  );

export const createdByRef = stixDomainEntityId =>
  getObject(
    `match $i isa Identity; 
    $rel(creator:$i, so:$x) isa created_by_ref; 
    $x has internal_id "${escapeString(
      stixDomainEntityId
    )}"; get $i, $rel; offset 0; limit 1;`,
    'i',
    'rel'
  );

export const killChainPhases = (stixDomainEntityId, args) =>
  paginate(
    `match $k isa Kill-Chain-Phase; 
    $rel(kill_chain_phase:$k, phase_belonging:$x) isa kill_chain_phases; 
    $x has internal_id "${escapeString(stixDomainEntityId)}"`,
    args,
    false,
    false
  );

export const markingDefinitions = (stixDomainEntityId, args) =>
  paginate(
    `match $m isa Marking-Definition; 
    $rel(marking:$m, so:$x) isa object_marking_refs; 
    $x has internal_id "${escapeString(stixDomainEntityId)}"`,
    args,
    false,
    null,
    false,
    false
  );

export const reports = (stixDomainEntityId, args) =>
  paginate(
    `match $r isa Report; 
    $rel(knowledge_aggregation:$r, so:$x) isa object_refs; 
    $x has internal_id "${escapeString(stixDomainEntityId)}"`,
    args
  );

export const reportsTimeSeries = (stixDomainEntityId, args) =>
  timeSeries(
    `match $x isa Report; 
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs; 
    $so has internal_id "${escapeString(stixDomainEntityId)}"`,
    args
  );

export const externalReferences = (stixDomainEntityId, args) =>
  paginate(
    `match $e isa External-Reference; 
    $rel(external_reference:$e, so:$x) isa external_references; 
    $x has internal_id "${escapeString(stixDomainEntityId)}"`,
    args,
    false
  );

export const stixRelations = (stixDomainEntityId, args) => {
  const finalArgs = assoc('fromId', stixDomainEntityId, args);
  if (finalArgs.search && finalArgs.search.length > 0) {
    return relationSearch(finalArgs);
  }
  return relationFindAll(finalArgs);
};

export const exports = (stixDomainEntityId, args) => {
  const { types } = args;
  const result = Promise.all(
    types.map(type => {
      const query = `match $e isa Export; $e has export_type "${escapeString(
        type
      )}"; $e has created_at $c; (export: $e, exported: $x) isa exports; $x has internal_id "${escapeString(
        stixDomainEntityId
      )}"; get $e, $c; sort $c desc;`;
      return load(query, ['e']).then(data => {
        return propOr(null, 'e', data);
      });
    })
  );
  return result.then(data => {
    return filter(n => !isNil(n), data);
  });
};

export const stixDomainEntityRefreshExport = async (
  stixDomainEntityId,
  stixDomainEntityType,
  type
) => {
  const wTx = await takeWriteTx();
  const internalId = uuid();
  const query = `insert $export isa Export, 
  has internal_id "${internalId}",
  has export_type "${escapeString(type)}",
  has object_status 0,
  has raw_data "",
  has created_at ${now()},
  has created_at_day "${dayFormat(now())}",
  has created_at_month "${monthFormat(now())}",
  has created_at_year "${yearFormat(now())}",
  has updated_at ${now()};`;
  const exportIterator = await wTx.tx.query(query);
  const createdExport = await exportIterator.next();
  const createdExportId = await createdExport.map().get('export').id;
  await wTx.tx.query(
    `match $from id ${createdExportId}; $to has internal_id "${escapeString(
      stixDomainEntityId
    )}"; insert (export: $from, exported: $to) isa exports, has internal_id "${uuid()}";`
  );
  await commitWriteTx(wTx);
  send(
    RABBITMQ_EXCHANGE_NAME,
    RABBITMQ_EXPORT_ROUTING_KEY,
    JSON.stringify({
      type,
      entity_type: stixDomainEntityType,
      entity_id: stixDomainEntityId,
      export_id: internalId
    })
  );
  return getById(stixDomainEntityId);
};

export const stixDomainEntityExportPush = async (
  user,
  stixDomainEntityId,
  exportId,
  rawData
) => {
  await updateAttribute(exportId, { key: 'raw_data', value: [rawData] });
  await updateAttribute(exportId, { key: 'object_status', value: [1] });
  return getById(stixDomainEntityId).then(stixDomainEntity => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user);
    return true;
  });
};

export const addStixDomainEntity = async (user, stixDomainEntity) => {
  const wTx = await takeWriteTx();
  const internalId = stixDomainEntity.internal_id
    ? escapeString(stixDomainEntity.internal_id)
    : uuid();
  const query = `insert $stixDomainEntity isa ${escape(stixDomainEntity.type)},
    has internal_id "${internalId}",
    has entity_type "${escapeString(stixDomainEntity.type.toLowerCase())}",
    has stix_id "${
      stixDomainEntity.stix_id
        ? escapeString(stixDomainEntity.stix_id)
        : `${escapeString(stixDomainEntity.type.toLowerCase())}--${uuid()}`
    }",
    has stix_label "",
    ${
      stixDomainEntity.alias
        ? `${join(
            ' ',
            map(
              val => `has alias "${escapeString(val)}",`,
              tail(stixDomainEntity.alias)
            )
          )} has alias "${escapeString(head(stixDomainEntity.alias))}",`
        : ''
    }
    has name "${escapeString(stixDomainEntity.name)}",
    has description "${escapeString(stixDomainEntity.description)}",
    has created ${
      stixDomainEntity.created ? prepareDate(stixDomainEntity.created) : now()
    },
    has modified ${
      stixDomainEntity.modified ? prepareDate(stixDomainEntity.modified) : now()
    },
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",      
    has updated_at ${now()};
  `;
  logger.debug(`[GRAKN - infer: false] addStixDomainEntity > ${query}`);
  const stixDomainEntityIterator = await wTx.tx.query(query);
  const createStixDomainEntity = await stixDomainEntityIterator.next();
  const createdStixDomainEntityId = await createStixDomainEntity
    .map()
    .get('stixDomainEntity').id;

  if (stixDomainEntity.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdStixDomainEntityId};
      $to has internal_id "${escapeString(stixDomainEntity.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (stixDomainEntity.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdStixDomainEntityId}; 
        $to has internal_id "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      stixDomainEntity.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};

export const stixDomainEntityDelete = async stixDomainEntityId => {
  const graknId = await getId(stixDomainEntityId);
  await deleteEntity('stix_domain_entities', graknId);
  return deleteEntityById(stixDomainEntityId);
};

export const stixDomainEntityAddRelation = (user, stixDomainEntityId, input) =>
  createRelation(stixDomainEntityId, input).then(relationData => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixDomainEntityDeleteRelation = (
  user,
  stixDomainEntityId,
  relationId
) =>
  deleteRelationById(stixDomainEntityId, relationId).then(relationData => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixDomainEntityCleanContext = (user, stixDomainEntityId) => {
  delEditContext(user, stixDomainEntityId);
  return getById(stixDomainEntityId).then(stixDomainEntity =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};

export const stixDomainEntityEditContext = (
  user,
  stixDomainEntityId,
  input
) => {
  setEditContext(user, stixDomainEntityId, input);
  return getById(stixDomainEntityId).then(stixDomainEntity =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};

export const stixDomainEntityEditField = (user, stixDomainEntityId, input) =>
  updateAttribute(stixDomainEntityId, input).then(stixDomainEntity => {
    return notify(
      BUS_TOPICS.StixDomainEntity.EDIT_TOPIC,
      stixDomainEntity,
      user
    );
  });
