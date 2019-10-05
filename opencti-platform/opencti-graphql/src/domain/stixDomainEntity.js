import { assoc, dissoc, map } from 'ramda';
import uuid from 'uuid/v4';
import mime from 'mime-types';
import { delEditContext, setEditContext } from '../database/redis';
import {
  commitWriteTx,
  createRelation,
  dayFormat,
  deleteEntityById,
  deleteRelationById,
  escape,
  escapeString,
  getById,
  getId,
  getObject,
  monthFormat,
  notify,
  now,
  paginate,
  prepareDate,
  takeWriteTx,
  timeSeries,
  updateAttribute,
  yearFormat
} from '../database/grakn';
import {
  countEntities,
  deleteEntity,
  paginate as elPaginate
} from '../database/elasticSearch';

import { BUS_TOPICS } from '../config/conf';
import {
  findAll as relationFindAll,
  search as relationSearch
} from './stixRelation';
import { upload } from '../database/minio';
import {
  CONNECTOR_INTERNAL_EXPORT_FILE,
  connectorsForExport
} from './connector';
import { createWork, workToExportFile } from './work';
import { CONNECTOR_EXCHANGE, listenRouting, send } from '../database/rabbitmq';

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

/**
 * Create export element waiting for completion
 * @param domainEntityId
 * @param format
 * @param exportType > stix2-bundle-full | stix2-bundle-simple
 * @returns {*}
 */
export const stixDomainEntityAskExport = async (
  domainEntityId,
  format,
  exportType
) => {
  const creation = now();
  const entity = await getById(domainEntityId);
  const connectors = await connectorsForExport(format);
  // Create job and send ask to broker
  const workList = await Promise.all(
    map(connector => {
      return createWork(
        connector.internal_id,
        CONNECTOR_INTERNAL_EXPORT_FILE,
        domainEntityId
      );
    }, connectors)
  );
  // Send message to all correct connectors queues
  await Promise.all(
    map(data => {
      const { connector, work } = data;
      const fileExt = mime.extension(format);
      const fileName = `${creation}Z_(${connector.name})_${entity.entity_type}_${entity.name}_${exportType}.${fileExt}`;
      const message = {
        job_id: work.internal_id, // job(id)
        export_type: exportType, // simple or full
        entity_type: entity.entity_type, // report, threat, ...
        entity_id: domainEntityId, // report(id), thread(id), ...
        file_name: fileName // Base path for the upload
      };
      return send(
        CONNECTOR_EXCHANGE,
        listenRouting(connector.internal_id),
        JSON.stringify(message)
      );
    }, workList)
  );
  // Return the work list to do
  return map(w => workToExportFile(w.work, w.connector), workList);
};

export const stixDomainEntityExportPush = async (
  user,
  entityId,
  jobId,
  file
) => {
  // Upload the document in minio
  await upload(user, 'export', file, entityId);
  // Delete the export placeholder
  await deleteEntityById(jobId);
  return getById(entityId).then(stixDomainEntity => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user);
    return true;
  });
};

export const addStixDomainEntity = async (user, stixDomainEntity) => {
  const wTx = await takeWriteTx();
  const internalId = stixDomainEntity.internal_id
    ? escapeString(stixDomainEntity.internal_id)
    : uuid();
  const stixDomainEntityIterator = await wTx.tx
    .query(`insert $stixDomainEntity isa ${escape(stixDomainEntity.type)},
    has internal_id "${internalId}",
    has entity_type "${escapeString(stixDomainEntity.type.toLowerCase())}",
    has stix_id "${
      stixDomainEntity.stix_id
        ? escapeString(stixDomainEntity.stix_id)
        : `${escapeString(stixDomainEntity.type.toLowerCase())}--${uuid()}`
    }",
    has stix_label "",
    has alias "",
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
  `);
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
        `match $from has id ${createdStixDomainEntityId}; 
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
